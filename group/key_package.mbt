///|
/// A generated MLS `KeyPackage` together with its private init, leaf encryption,
/// and signature keys (RFC 9420 §10).
#derive(Eq, Debug)
pub(all) struct KeyPackageBundle {
  key_package : @types.KeyPackage
  init_priv : Bytes
  encryption_priv : Bytes
  signature_priv : Bytes
}

///|
fn default_capabilities() -> @types.Capabilities {
  {
    versions: [@types.PROTOCOL_VERSION_MLS10],
    cipher_suites: [
      @types.CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
      @types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    ],
    extensions: [],
    proposals: [],
    credentials: [@types.CREDENTIAL_TYPE_BASIC],
  }
}

///|
/// Generates a fresh `KeyPackageBundle` with three independent key pairs
/// (Ed25519 signature key, X25519 leaf encryption key, and X25519 init key),
/// signs the `LeafNode` under `"LeafNodeTBS"`, and signs the `KeyPackage`
/// under `"KeyPackageTBS"` (RFC 9420 §7.2 & §10).
pub fn KeyPackageBundle::generate(
  cs : @cs.CipherSuite,
  identity : Bytes,
  rng : @crypto.DeterministicRng,
) -> KeyPackageBundle raise GroupError {
  let sig_seed = rng.next_bytes(32)
  let (signature_priv, sig_pub) = cs.signature_keypair_from_seed(sig_seed) catch {
    e => raise CsError(e)
  }
  let enc_ikm = rng.next_bytes(32)
  let (encryption_priv, enc_pub) = cs.kem_keypair_from_ikm(enc_ikm) catch {
    e => raise CsError(e)
  }
  let init_ikm = rng.next_bytes(32)
  let (init_priv, init_pub) = cs.kem_keypair_from_ikm(init_ikm) catch {
    e => raise CsError(e)
  }
  if init_pub == enc_pub {
    raise InvalidKeyPackage("generated init_key collided with encryption_key")
  }
  let unsigned_leaf : @types.LeafNode = {
    encryption_key: enc_pub,
    signature_key: sig_pub,
    credential: @types.Credential::Basic(identity),
    capabilities: default_capabilities(),
    leaf_node_source: @types.LeafNodeSource::KeyPackage,
    lifetime: Some({ not_before: 0UL, not_after: 0xFFFFFFFFFFFFFFFFUL, }),
    parent_hash: None,
    extensions: [],
    signature: b"",
  }
  let leaf_tbs = unsigned_leaf.encode_tbs(None, None) catch {
    e => raise TlsError(e)
  }
  let leaf_sig = cs.sign_with_label(signature_priv, "LeafNodeTBS", leaf_tbs) catch {
    e => raise CsError(e)
  }
  let leaf_node : @types.LeafNode = {
    encryption_key: unsigned_leaf.encryption_key,
    signature_key: unsigned_leaf.signature_key,
    credential: unsigned_leaf.credential,
    capabilities: unsigned_leaf.capabilities,
    leaf_node_source: unsigned_leaf.leaf_node_source,
    lifetime: unsigned_leaf.lifetime,
    parent_hash: unsigned_leaf.parent_hash,
    extensions: unsigned_leaf.extensions,
    signature: leaf_sig,
  }
  let unsigned_kp : @types.KeyPackage = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    init_key: init_pub,
    leaf_node,
    extensions: [],
    signature: b"",
  }
  let kp_tbs = unsigned_kp.encode_tbs() catch { e => raise TlsError(e) }
  let kp_sig = cs.sign_with_label(signature_priv, "KeyPackageTBS", kp_tbs) catch {
    e => raise CsError(e)
  }
  let key_package : @types.KeyPackage = {
    version: unsigned_kp.version,
    cipher_suite: unsigned_kp.cipher_suite,
    init_key: unsigned_kp.init_key,
    leaf_node: unsigned_kp.leaf_node,
    extensions: unsigned_kp.extensions,
    signature: kp_sig,
  }
  { key_package, init_priv, encryption_priv, signature_priv, }
}

///|
/// Verifies an MLS `KeyPackage` per RFC 9420 §10.1:
/// - `version == 1` (`mls10`)
/// - `cipher_suite` matches `cs`
/// - `init_key != leaf_node.encryption_key`
/// - `leaf_node.leaf_node_source == KeyPackage` (with `lifetime` present and no `parent_hash`)
/// - Valid `LeafNode` signature (`"LeafNodeTBS"`)
/// - Valid `KeyPackage` signature (`"KeyPackageTBS"`)
pub fn verify_key_package(
  cs : @cs.CipherSuite,
  kp : @types.KeyPackage,
) -> Unit raise GroupError {
  if kp.version != @types.PROTOCOL_VERSION_MLS10 {
    raise UnsupportedProtocolVersion(kp.version)
  }
  if kp.cipher_suite != cs.id() {
    raise CipherSuiteMismatch
  }
  if kp.init_key == kp.leaf_node.encryption_key {
    raise InvalidKeyPackage("init_key must differ from leaf encryption_key")
  }
  match kp.leaf_node.leaf_node_source {
    @types.LeafNodeSource::KeyPackage => ()
    _ => raise InvalidKeyPackage("leaf_node_source must be KeyPackage")
  }
  match kp.leaf_node.lifetime {
    Some(lt) =>
      if lt.not_before > lt.not_after {
        raise InvalidKeyPackage("invalid lifetime range")
      }
    None => raise InvalidKeyPackage("KeyPackage leaf_node must have lifetime")
  }
  if kp.leaf_node.parent_hash is Some(_) {
    raise InvalidKeyPackage("KeyPackage leaf_node must not have parent_hash")
  }
  @tree.verify_leaf_signature(cs, kp.leaf_node, b"", 0U) catch {
    @tree.TreeError::InvalidLeafSignature(_) =>
      raise InvalidKeyPackage("invalid LeafNode signature")
    e => raise TreeError(e)
  }
  let kp_tbs = kp.encode_tbs() catch { e => raise TlsError(e) }
  if !cs.verify_with_label(
      kp.leaf_node.signature_key,
      "KeyPackageTBS",
      kp_tbs,
      kp.signature,
    ) {
    raise InvalidKeyPackage("invalid KeyPackage signature")
  }
}
