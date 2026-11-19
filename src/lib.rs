//! Non-hardened HD key derivation for ZcashFoundation `frost-ed25519` 2.2.
//!
//! Implements the FROST-HD-v1 Ed25519 profile proposed in
//! <https://github.com/ZcashFoundation/frost/pull/1083> (pinned at
//! `6f55efc80e316980591e51ec66792780d0aea2f5`, MIT OR Apache-2.0).
//! Not affiliated with the Zcash Foundation. Experimental and unaudited:
//! do not use with funds.
//!
//! Every participant applies the same additive tweak to its signing share,
//! its verifying share and the group key, so a child key is signable with the
//! same FROST threshold without a new DKG.
//!
//! Security notes:
//! - A participant's child share minus the cumulative tweak reveals its root
//!   share. Keep the [`DerivationKey`] secret: anyone holding it and the root
//!   public key can enumerate every child public key.
//! - Child verifying shares correlate children of one root. Publish only child
//!   group keys (addresses), never child public key packages.
//! - Authenticate the root packages, derivation key and context before use.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod path;

use alloc::vec::Vec;
use core::fmt;

use frost_core::{Ciphersuite, Field, Group, Scalar};
use frost_ed25519::{
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    Ed25519Group, Ed25519ScalarField, Ed25519Sha512, VerifyingKey,
};
use hmac::{Hmac, Mac};
pub use path::{DerivationPath, MAX_PATH_DEPTH};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEY_FAMILY_VERSION: u16 = 1;
const PROFILE_ID: &str = "FROST-HD-ED25519-SHA512-H1-v1";
const NORMAL_SEGMENT_KIND: u8 = 0;
const DERIVATION_KEY_BYTES: usize = 32;
const CONTEXT_DIGEST_BYTES: usize = 32;
const SHA512_OUTPUT_BYTES: usize = 64;
const DST_CONTEXT: &[u8] = b"FROST-HD-v1/context";
const DST_EDGE: &[u8] = b"FROST-HD-v1/edge";
const DST_TWEAK_PRF: &[u8] = b"FROST-HD-v1/tweak-prf";
const DST_CHILD_KEY: &[u8] = b"FROST-HD-v1/child-derivation-key";
const DST_HASH_TO_SCALAR: &[u8] = b"FROST-HD-v1/hash-to-scalar";

type Tweak = Scalar<Ed25519Sha512>;
type Element = <Ed25519Group as Group>::Element;

/// A secret 32-byte derivation key supplied by the application.
#[derive(ZeroizeOnDrop)]
pub struct DerivationKey([u8; DERIVATION_KEY_BYTES]);

impl DerivationKey {
    /// Takes secret application-provided key bytes. The caller owns any other copies.
    pub const fn new(bytes: [u8; DERIVATION_KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DerivationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivationKey(<redacted>)")
    }
}

/// An Ed25519 profile-bound digest of a key family's application context.
#[derive(Clone, Copy)]
pub struct DerivationContext([u8; CONTEXT_DIGEST_BYTES]);

impl DerivationContext {
    /// Binds the application, network and purpose labels to the FROST-HD-v1 profile.
    pub fn new(application: &[u8], network: &[u8], purpose: &[u8]) -> Result<Self, Error> {
        let mut hasher = Sha256::new();
        hasher.update(DST_CONTEXT);
        hasher.update(KEY_FAMILY_VERSION.to_be_bytes());
        for label in [
            Ed25519Sha512::ID.as_bytes(),
            PROFILE_ID.as_bytes(),
            application,
            network,
            purpose,
        ] {
            hasher.update(length_prefix(label)?);
            hasher.update(label);
        }
        Ok(Self(hasher.finalize().into()))
    }
}

/// Derives one participant's signable child package from an authenticated root package.
pub fn derive_key_package(
    root: &KeyPackage,
    key: &DerivationKey,
    context: DerivationContext,
    path: &DerivationPath,
) -> Result<KeyPackage, Error> {
    let mut signing_scalar = Zeroizing::new(root.signing_share().to_scalar());
    let mut verifying_share = *root.verifying_share();
    if VerifyingShare::from(*root.signing_share()) != verifying_share {
        return Err(Error::InconsistentPrivatePackage);
    }
    let verifying_key = derive_path(
        root.verifying_key(),
        key,
        context,
        path.indices().iter().copied(),
        |edge| {
            *signing_scalar += *edge.tweak;
            verifying_share = tweak_verifying_share(verifying_share, edge)?;
            Ok(())
        },
    )?;
    Ok(KeyPackage::new(
        *root.identifier(),
        SigningShare::new(*signing_scalar),
        verifying_share,
        verifying_key,
        *root.min_signers(),
    ))
}

/// Derives the child public package for FROST aggregation from an authenticated root package.
///
/// Keep its participant verifying shares private to the signing workflow. They can
/// correlate related children.
pub fn derive_public_key_package(
    root: &PublicKeyPackage,
    key: &DerivationKey,
    context: DerivationContext,
    path: &DerivationPath,
) -> Result<PublicKeyPackage, Error> {
    let mut verifying_shares = root.verifying_shares().clone();
    let verifying_key = derive_path(
        root.verifying_key(),
        key,
        context,
        path.indices().iter().copied(),
        |edge| {
            for share in verifying_shares.values_mut() {
                *share = tweak_verifying_share(*share, edge)?;
            }
            Ok(())
        },
    )?;
    Ok(PublicKeyPackage::new(verifying_shares, verifying_key))
}

fn tweak_verifying_share(share: VerifyingShare, edge: &Edge) -> Result<VerifyingShare, Error> {
    let element = share.to_element() + edge.tweak_element;
    if element == Ed25519Group::identity() {
        return Err(Error::DerivedVerifyingShareIdentity);
    }
    Ok(VerifyingShare::new(element))
}

struct Edge {
    tweak: Zeroizing<Tweak>,
    tweak_element: Element,
    child_verifying_key: VerifyingKey,
    child_derivation_key: DerivationKey,
}

fn derive_path(
    root: &VerifyingKey,
    root_key: &DerivationKey,
    context: DerivationContext,
    indices: impl IntoIterator<Item = u32>,
    mut apply: impl FnMut(&Edge) -> Result<(), Error>,
) -> Result<VerifyingKey, Error> {
    let mut verifying_key = *root;
    let mut key = None;
    for index in indices {
        let edge = derive_edge(
            &verifying_key,
            key.as_ref().unwrap_or(root_key),
            context,
            index,
        )?;
        apply(&edge)?;
        verifying_key = edge.child_verifying_key;
        key = Some(edge.child_derivation_key);
    }
    Ok(verifying_key)
}

fn derive_edge(
    parent: &VerifyingKey,
    key: &DerivationKey,
    context: DerivationContext,
    index: u32,
) -> Result<Edge, Error> {
    let serialized_parent = parent
        .serialize()
        .map_err(|_| Error::ParentKeySerialization)?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(DST_EDGE);
    transcript.extend_from_slice(&KEY_FAMILY_VERSION.to_be_bytes());
    for label in [Ed25519Sha512::ID.as_bytes(), PROFILE_ID.as_bytes()] {
        transcript.extend_from_slice(&length_prefix(label)?);
        transcript.extend_from_slice(label);
    }
    transcript.extend_from_slice(&context.0);
    transcript.extend_from_slice(&length_prefix(&serialized_parent)?);
    transcript.extend_from_slice(&serialized_parent);
    transcript.push(NORMAL_SEGMENT_KIND);
    transcript.extend_from_slice(&index.to_be_bytes());
    let retry_offset = transcript.len();

    for retry in 0..=u16::MAX {
        transcript.truncate(retry_offset);
        transcript.extend_from_slice(&retry.to_be_bytes());

        let tweak_prf = hmac_sha512(key, DST_TWEAK_PRF, &transcript)?;
        let mut scalar_input = Zeroizing::new(Vec::with_capacity(
            DST_HASH_TO_SCALAR.len() + SHA512_OUTPUT_BYTES,
        ));
        scalar_input.extend_from_slice(DST_HASH_TO_SCALAR);
        scalar_input.extend_from_slice(tweak_prf.as_ref());
        let tweak = Zeroizing::new(Ed25519Sha512::H1(&scalar_input));
        if *tweak == Ed25519ScalarField::zero() {
            continue;
        }
        let tweak_element = Ed25519Group::generator() * *tweak;
        let child_element = parent.to_element() + tweak_element;
        if child_element == Ed25519Group::identity() {
            continue;
        }

        let child_prf = hmac_sha512(key, DST_CHILD_KEY, &transcript)?;
        let mut child_key = DerivationKey::new([0; DERIVATION_KEY_BYTES]);
        child_key
            .0
            .copy_from_slice(&child_prf[..DERIVATION_KEY_BYTES]);
        return Ok(Edge {
            tweak,
            tweak_element,
            child_verifying_key: VerifyingKey::new(child_element),
            child_derivation_key: child_key,
        });
    }
    Err(Error::RetryExhausted)
}

fn hmac_sha512(
    key: &DerivationKey,
    domain: &[u8],
    transcript: &[u8],
) -> Result<Zeroizing<[u8; SHA512_OUTPUT_BYTES]>, Error> {
    let mut mac = Hmac::<Sha512>::new_from_slice(&key.0).map_err(|_| Error::KdfInitialization)?;
    mac.update(domain);
    mac.update(transcript);
    let mut output = mac.finalize().into_bytes();
    let mut bytes = Zeroizing::new([0; SHA512_OUTPUT_BYTES]);
    bytes.copy_from_slice(&output);
    output.as_mut_slice().zeroize();
    Ok(bytes)
}

fn length_prefix(value: &[u8]) -> Result<[u8; size_of::<u16>()], Error> {
    Ok(u16::try_from(value.len())
        .map_err(|_| Error::ContextComponentTooLong)?
        .to_be_bytes())
}

/// A path validation or derivation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A context/transcript component exceeds the canonical u16 length.
    ContextComponentTooLong,
    /// The path has no segment.
    EmptyPath,
    /// The path exceeds [`MAX_PATH_DEPTH`] segments.
    PathTooDeep,
    /// An index is not written as canonical unsigned decimal.
    NonCanonicalPath,
    /// An index exceeds u32.
    PathIndexOverflow,
    /// The path requests hardened derivation.
    HardenedDerivationUnsupported,
    /// The parent joint verifying key failed to serialize.
    ParentKeySerialization,
    /// HMAC initialization failed.
    KdfInitialization,
    /// All deterministic edge retries yielded invalid children.
    RetryExhausted,
    /// A derived participant verifying share is the group identity.
    DerivedVerifyingShareIdentity,
    /// The root participant's signing share and verifying share disagree.
    InconsistentPrivatePackage,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextComponentTooLong => "derivation context component exceeds u16 length",
            Self::EmptyPath => "derivation path must have at least one segment",
            Self::PathTooDeep => "derivation path exceeds the maximum depth",
            Self::NonCanonicalPath => "non-canonical derivation path",
            Self::PathIndexOverflow => "derivation path index exceeds u32",
            Self::HardenedDerivationUnsupported => "hardened derivation is unsupported",
            Self::ParentKeySerialization => "failed to serialize the parent verifying key",
            Self::KdfInitialization => "failed to initialize the derivation KDF",
            Self::RetryExhausted => "deterministic derivation retry space exhausted",
            Self::DerivedVerifyingShareIdentity => {
                "derived participant verifying share is the identity"
            }
            Self::InconsistentPrivatePackage => "root signing share and verifying share disagree",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests;
