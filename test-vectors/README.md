# Official RFC 9420 MLS Test Vectors

This directory contains 11 official JSON test vector files sourced from the IETF MLS Working Group repository:

- Upstream source: <https://github.com/mlswg/mls-implementations>

## Purpose

These files are kept strictly as offline reference baselines for RFC 9420 interoperability alignment. MoonMLS tests embed selected vectors directly in MoonBit test code and perform **zero file I/O** at test runtime so the full test suite runs identically across `wasm-gc`, `js`, and `native` targets.

## Included Files (11)

- `crypto-basics.json`
- `key-schedule.json`
- `message-protection.json`
- `messages.json`
- `psk_secret.json`
- `secret-tree.json`
- `tree-math.json`
- `tree-operations.json`
- `tree-validation.json`
- `treekem.json`
- `welcome.json`
