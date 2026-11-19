use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ed25519_dalek::{Signature, VerifyingKey as DalekVerifyingKey};
use serde::Deserialize;

use super::*;

const VECTOR_PATH_VERSION: u16 = 1;
const PARTICIPANT_ID: u16 = 1;
const SIGNING_THRESHOLD: u16 = 2;
const TEST_PATH: [u32; 3] = [7, 0, 33];
const TEST_KEY: [u8; DERIVATION_KEY_BYTES] = [0x42; DERIVATION_KEY_BYTES];
// Pinned upstream Python reference for m/7/0/33, using the fixture's root, key and context.
const THREE_LEVEL_PATH_PUBLIC_KEY_HEX: &str =
    "d4ddda777f778cb247f55537ed3a8d82bcc406579392ecdc569b243bb22d0234";

#[derive(Deserialize)]
struct Vectors {
    application: String,
    network: String,
    purpose: String,
    ciphersuite_id: String,
    profile_id: String,
    root_public_key_hex: String,
    root_derivation_key_hex: String,
    context_digest_hex: String,
    message_hex: String,
    paths: Vec<VectorPath>,
}

#[derive(Deserialize)]
struct VectorPath {
    path: String,
    path_encoding_hex: String,
    public_key_hex: String,
    derivation_key_hex: String,
    cumulative_tweak_le_hex: String,
    signature_hex: String,
}

#[test]
fn frost_hd_matches_upstream_vectors() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../vectors/frost-hd-v1-ed25519.json")).unwrap();
    assert_eq!(vectors.ciphersuite_id, Ed25519Sha512::ID);
    assert_eq!(vectors.profile_id, PROFILE_ID);
    let root =
        VerifyingKey::deserialize(&hex::decode(vectors.root_public_key_hex).unwrap()).unwrap();
    let key = DerivationKey::new(
        hex::decode(vectors.root_derivation_key_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let context = DerivationContext::new(
        vectors.application.as_bytes(),
        vectors.network.as_bytes(),
        vectors.purpose.as_bytes(),
    )
    .unwrap();
    assert_eq!(hex::encode(context.0), vectors.context_digest_hex);
    let message = hex::decode(vectors.message_hex).unwrap();

    for vector in vectors.paths {
        let path: DerivationPath = vector.path.parse().unwrap();
        assert_eq!(path.to_string(), vector.path);
        let indices = path.indices();
        let mut path_encoding = VECTOR_PATH_VERSION.to_be_bytes().to_vec();
        path_encoding.extend_from_slice(&u16::try_from(indices.len()).unwrap().to_be_bytes());
        for index in indices {
            path_encoding.push(NORMAL_SEGMENT_KIND);
            path_encoding.extend_from_slice(&index.to_be_bytes());
        }
        let mut cumulative_tweak = Ed25519ScalarField::zero();
        let mut child_key = [0; DERIVATION_KEY_BYTES];
        let child = derive_path(&root, &key, context, indices.iter().copied(), |edge| {
            cumulative_tweak += *edge.tweak;
            child_key.copy_from_slice(&edge.child_derivation_key.0);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            hex::encode(path_encoding),
            vector.path_encoding_hex,
            "{}",
            vector.path
        );
        let child_bytes = child.serialize().unwrap();
        assert_eq!(
            hex::encode(&child_bytes),
            vector.public_key_hex,
            "{}",
            vector.path
        );
        assert_eq!(
            hex::encode(child_key),
            vector.derivation_key_hex,
            "{}",
            vector.path
        );
        assert_eq!(
            hex::encode(Ed25519ScalarField::serialize(&cumulative_tweak)),
            vector.cumulative_tweak_le_hex,
            "{}",
            vector.path
        );
        let dalek =
            DalekVerifyingKey::from_bytes(&child_bytes.clone().try_into().unwrap()).unwrap();
        let signature = Signature::from_slice(&hex::decode(vector.signature_hex).unwrap()).unwrap();
        dalek.verify_strict(&message, &signature).unwrap();

        let root_package = PublicKeyPackage::new(BTreeMap::new(), root);
        let public = derive_public_key_package(&root_package, &key, context, &path).unwrap();
        assert_eq!(public.verifying_key().serialize().unwrap(), child_bytes);
    }

    let three_level_path = "m/7/0/33".parse().unwrap();
    let root_package = PublicKeyPackage::new(BTreeMap::new(), root);
    let child = derive_public_key_package(&root_package, &key, context, &three_level_path).unwrap();
    assert_eq!(
        hex::encode(child.verifying_key().serialize().unwrap()),
        THREE_LEVEL_PATH_PUBLIC_KEY_HEX
    );
}

fn test_context() -> DerivationContext {
    DerivationContext::new(b"example", b"solana-devnet", b"payments").unwrap()
}

#[test]
fn public_child_tweak_recovers_the_parent_participant_share() {
    let root_share = SigningShare::new(Ed25519ScalarField::one());
    let root_verifying_share = VerifyingShare::from(root_share);
    let root = KeyPackage::new(
        PARTICIPANT_ID.try_into().unwrap(),
        root_share,
        root_verifying_share,
        VerifyingKey::new(Ed25519Group::generator()),
        SIGNING_THRESHOLD,
    );
    let path = DerivationPath::new(&TEST_PATH).unwrap();
    let key = DerivationKey::new(TEST_KEY);
    let context = test_context();
    let child = derive_key_package(&root, &key, context, &path).unwrap();
    let mut cumulative_tweak = Ed25519ScalarField::zero();
    derive_path(
        root.verifying_key(),
        &key,
        context,
        path.indices().iter().copied(),
        |edge| {
            cumulative_tweak += *edge.tweak;
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        child.signing_share().to_scalar() - cumulative_tweak,
        root_share.to_scalar()
    );
    assert_eq!(
        child.verifying_share().to_element() - Ed25519Group::generator() * cumulative_tweak,
        root_verifying_share.to_element()
    );
}

#[test]
fn rejects_identity_at_an_intermediate_share_and_inconsistent_private_root() {
    let id = PARTICIPANT_ID.try_into().unwrap();
    let root_key = VerifyingKey::new(Ed25519Group::generator());
    let key = DerivationKey::new(TEST_KEY);
    let path = DerivationPath::new(&TEST_PATH).unwrap();
    let context = test_context();
    let first_edge = derive_edge(&root_key, &key, context, TEST_PATH[0]).unwrap();
    let cancelling_share = SigningShare::new(-*first_edge.tweak);
    let verifying_share = VerifyingShare::from(cancelling_share);
    let private_root = KeyPackage::new(
        id,
        cancelling_share,
        verifying_share,
        root_key,
        SIGNING_THRESHOLD,
    );
    let public_root = PublicKeyPackage::new(BTreeMap::from([(id, verifying_share)]), root_key);
    assert_eq!(
        derive_key_package(&private_root, &key, context, &path),
        Err(Error::DerivedVerifyingShareIdentity)
    );
    assert_eq!(
        derive_public_key_package(&public_root, &key, context, &path),
        Err(Error::DerivedVerifyingShareIdentity)
    );

    let invalid_root = KeyPackage::new(
        id,
        SigningShare::new(Ed25519ScalarField::zero()),
        verifying_share,
        root_key,
        SIGNING_THRESHOLD,
    );
    assert_eq!(
        derive_key_package(&invalid_root, &key, context, &path),
        Err(Error::InconsistentPrivatePackage)
    );
}

#[test]
fn rejects_an_oversized_context_label() {
    let oversized_label = vec![0; usize::from(u16::MAX) + 1];
    assert!(matches!(
        DerivationContext::new(&oversized_label, b"solana-devnet", b"payments"),
        Err(Error::ContextComponentTooLong)
    ));
}
