# invisible-labs-frost-ed25519-hd

HD (non-hardened) key derivation for ZcashFoundation [`frost-ed25519`](https://crates.io/crates/frost-ed25519) 2.2.

> **Not affiliated with the Zcash Foundation. Implements [ZcashFoundation/frost#1083](https://github.com/ZcashFoundation/frost/pull/1083). Experimental, unaudited, do not use with funds.**

From one FROST key (for example a 2-of-2 DKG), every participant derives child
key packages for a path `m/<i0>/<i1>/...` without a new DKG. The same additive
tweak is applied to signing shares, verifying shares and the group key, so the
child is signable with the same threshold. Only non-hardened (normal) indices are
supported; hardened segments are rejected.

```rust,ignore
use invisible_labs_frost_ed25519_hd::{
    derive_key_package, derive_public_key_package, DerivationContext, DerivationKey, DerivationPath,
};

let context = DerivationContext::new(b"my-app", b"solana-mainnet", b"deposits")?;
let key = DerivationKey::new(secret_32_bytes); // keep secret
let path: DerivationPath = "m/7/0/33".parse()?;
let child_key_package = derive_key_package(&root_key_package, &key, context, &path)?;
let child_public_package = derive_public_key_package(&root_public_package, &key, context, &path)?;
```

## Security notes

- **Keep the `DerivationKey` secret.** With it and the root public key, anyone can
  enumerate every child public key. Non-hardened derivation also means a child
  signing share minus the cumulative tweak reveals the root share.
- **Publish only child group keys.** Child verifying shares correlate children of
  the same root; keep child public key packages inside the signing workflow.
- Never fund or publish the root key itself.
- Authenticate the root packages, derivation key and context before deriving.

## Compatibility

- `frost-core` and `frost-ed25519` pinned to `=2.2.0`, Ed25519 only.
- KDF transcript, domain separation tags, retry rule and child key derivation are
  identical to the upstream proposal; the upstream test vectors
  (`vectors/frost-hd-v1-ed25519.json`) match byte for byte.
- If ZcashFoundation/frost#1083 is merged, this crate will point to the official
  crate and older versions will be yanked.

## Tests

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The tests check upstream vector parity, a real 2-of-2 DKG whose derived child
FROST-signs a message that verifies under the child key only (not under the root
or a sibling), path validation, determinism and secret redaction.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option. See [ATTRIBUTION.md](ATTRIBUTION.md).
