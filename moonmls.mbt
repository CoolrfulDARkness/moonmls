///|
/// Supported RFC 9420 MLS CipherSuites (`CS1` / `CS3`).
pub type CipherSuite = @cs.CipherSuite

///|
/// Forward-secure deterministic CSPRNG (ChaCha20-based) for Sans-I/O MLS operations.
pub type DeterministicRng = @crypto.DeterministicRng

///|
/// RFC 9420 `KeyPackage`.
pub type KeyPackage = @types.KeyPackage

///|
/// RFC 9420 `Welcome` message.
pub type Welcome = @types.Welcome

///|
/// RFC 9420 `PrivateMessage` wire frame.
pub type PrivateMessage = @types.PrivateMessage

///|
/// RFC 9420 `Proposal`.
pub type Proposal = @types.Proposal

///|
/// RFC 9420 serialized ratchet tree node array.
pub type RatchetTree = @types.RatchetTree

///|
/// Generated `KeyPackage` paired with its private init, encryption, and signature keys.
pub type KeyPackageBundle = @group.KeyPackageBundle

///|
/// Sans-I/O RFC 9420 MLS Group state machine.
pub type MlsGroup = @group.MlsGroup

///|
/// Result of committing proposals and advancing the group epoch.
pub type CommitOutput = @group.CommitOutput

///|
/// Result of processing an incoming `PrivateMessage`.
pub type ProcessedMessage = @group.ProcessedMessage

///|
/// Verified output of `verify_and_decrypt_welcome`.
pub type WelcomeVerification = @group.WelcomeVerification

///|
/// Errors raised by the MLS group engine.
pub type GroupError = @group.GroupError

///|
/// Returns CipherSuite 1 (`0x0001`): `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub fn cs_x25519_aes128gcm() -> CipherSuite {
  @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
}

///|
/// Returns CipherSuite 3 (`0x0003`): `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.
pub fn cs_x25519_chacha20poly1305() -> CipherSuite {
  @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
}

///|
/// Creates a `DeterministicRng` from `seed`.
pub fn rng_from_seed(seed : Bytes) -> DeterministicRng {
  @crypto.DeterministicRng::from_seed(seed)
}

///|
/// Generates a fresh `KeyPackageBundle` for `identity`.
pub fn generate_key_package(
  cs : CipherSuite,
  identity : Bytes,
  rng : DeterministicRng,
) -> KeyPackageBundle raise GroupError {
  @group.KeyPackageBundle::generate(cs, identity, rng)
}

///|
/// Validates a `KeyPackage` per RFC 9420 §10.1.
pub fn verify_key_package(
  cs : CipherSuite,
  kp : KeyPackage,
) -> Unit raise GroupError {
  @group.verify_key_package(cs, kp)
}

///|
/// Verifies and decrypts a `Welcome` message against an explicit `signer_pub`.
pub fn verify_and_decrypt_welcome(
  cs : CipherSuite,
  welcome : Welcome,
  init_priv : Bytes,
  kp : KeyPackage,
  signer_pub : Bytes,
) -> WelcomeVerification raise GroupError {
  @group.verify_and_decrypt_welcome(cs, welcome, init_priv, kp, signer_pub)
}

///|
/// Creates a new MLS group at epoch 0.
pub fn create_group(
  cs : CipherSuite,
  group_id : Bytes,
  identity : Bytes,
  rng : DeterministicRng,
) -> MlsGroup raise GroupError {
  @group.MlsGroup::create(cs, group_id, identity, rng)
}

///|
/// Creates a new MLS group at epoch 0 from an existing `KeyPackageBundle`.
pub fn create_group_from_bundle(
  cs : CipherSuite,
  group_id : Bytes,
  bundle : KeyPackageBundle,
  rng : DeterministicRng,
) -> MlsGroup raise GroupError {
  @group.MlsGroup::create_from_bundle(cs, group_id, bundle, rng)
}

///|
/// Joins an MLS group from a `Welcome` message and optional external ratchet tree.
pub fn join_group_from_welcome(
  cs : CipherSuite,
  welcome : Welcome,
  bundle : KeyPackageBundle,
  external_tree : RatchetTree?,
) -> MlsGroup raise GroupError {
  @group.MlsGroup::from_welcome(cs, welcome, bundle, external_tree)
}
