//! End-to-end checks with a real frost-ed25519 2.2 two-of-two DKG.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use frost_ed25519::{
    self as frost,
    keys::{dkg, KeyPackage, PublicKeyPackage},
};
use invisible_labs_frost_ed25519_hd::{
    derive_key_package, derive_public_key_package, DerivationContext, DerivationKey,
    DerivationPath, Error, MAX_PATH_DEPTH,
};
use rand::rngs::OsRng;

const FIRST_ID: u16 = 1;
const SECOND_ID: u16 = 2;
const SIGNERS: u16 = 2;
const TEST_PATH: [u32; 3] = [7, 0, 33];
const SIBLING_PATH: [u32; 3] = [7, 0, 34];
const TEST_KEY: [u8; 32] = [0x42; 32];
const OTHER_TEST_KEY: [u8; 32] = [0x43; 32];
const MESSAGE: &[u8] = b"frost-ed25519-hd signing test message";

fn two_of_two_dkg() -> ([KeyPackage; SIGNERS as usize], PublicKeyPackage) {
    let first: frost::Identifier = FIRST_ID.try_into().unwrap();
    let second: frost::Identifier = SECOND_ID.try_into().unwrap();
    let (first_secret, first_message) = dkg::part1(first, SIGNERS, SIGNERS, OsRng).unwrap();
    let (second_secret, second_message) = dkg::part1(second, SIGNERS, SIGNERS, OsRng).unwrap();

    let for_first = BTreeMap::from([(second, second_message)]);
    let for_second = BTreeMap::from([(first, first_message)]);
    let (first_secret, mut first_messages) = dkg::part2(first_secret, &for_first).unwrap();
    let (second_secret, mut second_messages) = dkg::part2(second_secret, &for_second).unwrap();
    let (first_root, first_public) = dkg::part3(
        &first_secret,
        &for_first,
        &BTreeMap::from([(second, second_messages.remove(&first).unwrap())]),
    )
    .unwrap();
    let (second_root, second_public) = dkg::part3(
        &second_secret,
        &for_second,
        &BTreeMap::from([(first, first_messages.remove(&second).unwrap())]),
    )
    .unwrap();
    assert_eq!(first_public, second_public);
    ([first_root, second_root], second_public)
}

fn context() -> DerivationContext {
    DerivationContext::new(b"example", b"solana-devnet", b"payments").unwrap()
}

fn dalek_key(public: &PublicKeyPackage) -> VerifyingKey {
    VerifyingKey::from_bytes(
        &public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn derived_child_signs_and_only_verifies_under_its_own_key() {
    let (roots, root_public) = two_of_two_dkg();
    let context = context();
    let key = DerivationKey::new(TEST_KEY);
    let path = DerivationPath::new(&TEST_PATH).unwrap();
    let child_public = derive_public_key_package(&root_public, &key, context, &path).unwrap();
    let sibling = derive_public_key_package(
        &root_public,
        &key,
        context,
        &DerivationPath::new(&SIBLING_PATH).unwrap(),
    )
    .unwrap();

    let mut commitments = BTreeMap::new();
    let participants = roots.map(|root| {
        let child = derive_key_package(&root, &key, context, &path).unwrap();
        assert_eq!(child.identifier(), root.identifier());
        assert_eq!(child.min_signers(), root.min_signers());
        assert_eq!(child.verifying_key(), child_public.verifying_key());
        assert_eq!(
            child_public.verifying_shares().get(child.identifier()),
            Some(child.verifying_share())
        );
        let (nonce, commitment) = frost::round1::commit(child.signing_share(), &mut OsRng);
        commitments.insert(*child.identifier(), commitment);
        (child, nonce)
    });
    let signing_package = frost::SigningPackage::new(commitments, MESSAGE);
    let shares = participants
        .iter()
        .map(|(child, nonce)| {
            let share = frost::round2::sign(&signing_package, nonce, child).unwrap();
            (*child.identifier(), share)
        })
        .collect();
    let signature = frost::aggregate(&signing_package, &shares, &child_public).unwrap();
    let signature = Signature::from_slice(&signature.serialize().unwrap()).unwrap();

    dalek_key(&child_public)
        .verify_strict(MESSAGE, &signature)
        .unwrap();
    assert!(dalek_key(&root_public)
        .verify_strict(MESSAGE, &signature)
        .is_err());
    assert!(dalek_key(&sibling)
        .verify_strict(MESSAGE, &signature)
        .is_err());
}

#[test]
fn derivation_is_deterministic_and_separates_keys_and_indices() {
    let ([root, _], root_public) = two_of_two_dkg();
    let context = context();
    let key = DerivationKey::new(TEST_KEY);
    let other_key = DerivationKey::new(OTHER_TEST_KEY);
    let path = DerivationPath::new(&TEST_PATH).unwrap();
    let sibling_path = DerivationPath::new(&SIBLING_PATH).unwrap();
    let public = derive_public_key_package(&root_public, &key, context, &path).unwrap();
    let private = derive_key_package(&root, &key, context, &path).unwrap();
    assert_eq!(
        public,
        derive_public_key_package(&root_public, &key, context, &path).unwrap()
    );
    assert!(private == derive_key_package(&root, &key, context, &path).unwrap());
    for (candidate_key, candidate_path) in [(&other_key, &path), (&key, &sibling_path)] {
        let candidate =
            derive_public_key_package(&root_public, candidate_key, context, candidate_path)
                .unwrap();
        assert_ne!(public.verifying_key(), candidate.verifying_key());
    }
}

#[test]
fn rejects_hardened_empty_deep_or_non_canonical_paths() {
    for path in ["m/7'/0/33", "m/7/0'/33", "m/7/0/33'"] {
        assert_eq!(
            path.parse::<DerivationPath>(),
            Err(Error::HardenedDerivationUnsupported)
        );
    }
    assert_eq!("m".parse::<DerivationPath>(), Err(Error::EmptyPath));
    assert_eq!(DerivationPath::new(&[]), Err(Error::EmptyPath));
    assert_eq!(
        DerivationPath::new(&[0; MAX_PATH_DEPTH + 1]),
        Err(Error::PathTooDeep)
    );
    assert!(DerivationPath::new(&[0; MAX_PATH_DEPTH]).is_ok());
    for path in [
        "M/7/0/33",
        "m/07/0/33",
        "m/7/00/33",
        "m/7/0/+33",
        "m/7/0/",
        "/7",
    ] {
        assert_eq!(path.parse::<DerivationPath>(), Err(Error::NonCanonicalPath));
    }
    assert_eq!(
        "m/7/0/4294967296".parse::<DerivationPath>(),
        Err(Error::PathIndexOverflow)
    );
    let max_index = DerivationPath::new(&[u32::MAX, u32::MAX]).unwrap();
    assert_eq!(
        max_index.to_string().parse::<DerivationPath>(),
        Ok(max_index.clone())
    );

    let (_, root_public) = two_of_two_dkg();
    derive_public_key_package(
        &root_public,
        &DerivationKey::new(TEST_KEY),
        context(),
        &max_index,
    )
    .unwrap();
}

#[test]
fn derivation_key_debug_output_is_redacted() {
    assert_eq!(
        format!("{:?}", DerivationKey::new(TEST_KEY)),
        "DerivationKey(<redacted>)"
    );
}
