# Prior art and attribution

This crate adapts the FROST-HD crate proposed in ZcashFoundation/frost#1083 at
`6f55efc80e316980591e51ec66792780d0aea2f5` (MIT OR Apache-2.0, copyright
2019-2021 Zcash Foundation) to `frost-ed25519` 2.2, Ed25519 only. It is not
affiliated with or endorsed by the Zcash Foundation.
[Upstream PR #1083](https://github.com/ZcashFoundation/frost/pull/1083) ·
[MIT](LICENSE-MIT) · [Apache-2.0](LICENSE-APACHE)

The upstream proposal credits the following prior art.

- Zcash Foundation FROST Discussion #636, "BIP32 Derivation of FROST Keys":
  https://github.com/ZcashFoundation/frost/discussions/636
- MatthewLM's observation that signing shares, verification shares, and the
  joint key can receive the same additive tweak;
- Conduition's analysis and historical `taproot-bip32` prototype:
  https://github.com/conduition/frost/tree/taproot-bip32
- Jesse Posner's discussion of fixed/synthetic chain-code profiles and
  MuSig2-related work;
- PR #584 and successor PR #730 for the Taproot ciphersuite context:
  https://github.com/ZcashFoundation/frost/pull/584
  https://github.com/ZcashFoundation/frost/pull/730
- BIP32's non-hardened derivation and parent-key-recovery warning:
  https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP328 synthetic xpub work for aggregate keys:
  https://github.com/bitcoin/bips/blob/master/bip-0328.mediawiki
- threshold-HD research including ePrint 2023/312 and 2023/714:
  https://eprint.iacr.org/2023/312
  https://eprint.iacr.org/2023/714
