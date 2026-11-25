///|
let hpke_version_label : Bytes = b"HPKE-v1"

///|
let hpke_kem_id_x25519 : UInt = 0x0020U

///|
let hpke_kdf_id_sha256 : UInt = 0x0001U

///|
let hpke_mode_base : Bytes = b"\x00"

///|
/// RFC 9180 §4.1 KEM suite_id = concat("KEM", I2OSP(kem_id, 2)) for DHKEM(X25519, HKDF-SHA256).
let kem_suite_id : Bytes = b"KEM\x00\x20"

///|
/// RFC 9180 §5.1 HPKE suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2)).
fn hpke_suite_id(cs : CipherSuite) -> Bytes {
  @tls.bytes_concat([
    b"HPKE",
    i2osp2(hpke_kem_id_x25519),
    i2osp2(hpke_kdf_id_sha256),
    i2osp2(cs.aead_id()),
  ])
}

///|
/// RFC 9180 §4 LabeledExtract(salt, label, ikm).
fn labeled_extract(
  suite_id : Bytes,
  salt : Bytes,
  label : Bytes,
  ikm : Bytes,
) -> Bytes {
  let labeled_ikm = @tls.bytes_concat([hpke_version_label, suite_id, label, ikm])
  @crypto.hkdf_extract(salt, labeled_ikm)
}

///|
/// RFC 9180 §4 LabeledExpand(prk, label, info, L).
fn labeled_expand(
  suite_id : Bytes,
  prk : Bytes,
  label : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise CsError {
  if length < 0 || length > 0xFFFF {
    raise InvalidLength("HPKE LabeledExpand length out of uint16 range")
  }
  let labeled_info = @tls.bytes_concat([
    i2osp2(length.reinterpret_as_uint()),
    hpke_version_label,
    suite_id,
    label,
    info,
  ])
  try @crypto.hkdf_expand(prk, labeled_info, length) catch {
    e => raise CryptoError(e)
  }
}

///|
/// RFC 9180 §4.1 ExtractAndExpand(dh, kem_context) for DHKEM(X25519, HKDF-SHA256).
fn extract_and_expand(dh : Bytes, kem_context : Bytes) -> Bytes raise CsError {
  let eae_prk = labeled_extract(kem_suite_id, b"", b"eae_prk", dh)
  labeled_expand(kem_suite_id, eae_prk, b"shared_secret", kem_context, 32)
}

///|
/// RFC 9180 §7.1.3 DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256).
/// Returns `(sk, pk)` where both are 32 bytes.
pub fn kem_derive_key_pair(ikm : Bytes) -> (Bytes, Bytes) raise CsError {
  let dkp_prk = labeled_extract(kem_suite_id, b"", b"dkp_prk", ikm)
  let sk = labeled_expand(kem_suite_id, dkp_prk, b"sk", b"", 32)
  let pk = try @crypto.x25519_public_key(sk) catch {
    e => raise CryptoError(e)
  }
  (sk, pk)
}

///|
/// RFC 9180 §4.1 Encap(pkR) with explicit ephemeral secret key `sk_e`.
/// Returns `(shared_secret, enc)`.
fn dhkem_encap_with_ephemeral(
  pk_r : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise CsError {
  if pk_r.length() != 32 {
    raise InvalidLength("HPKE recipient public key must be 32 bytes")
  }
  if sk_e.length() != 32 {
    raise InvalidLength("HPKE ephemeral secret key must be 32 bytes")
  }
  let enc = try @crypto.x25519_public_key(sk_e) catch {
    e => raise CryptoError(e)
  }
  let dh = try @crypto.x25519_dh(sk_e, pk_r) catch {
    e => raise CryptoError(e)
  }
  let kem_context = @tls.bytes_concat([enc, pk_r])
  let shared_secret = extract_and_expand(dh, kem_context)
  (shared_secret, enc)
}

///|
/// RFC 9180 §4.1 Decap(enc, skR).
/// Returns `shared_secret`.
fn dhkem_decap(enc : Bytes, sk_r : Bytes) -> Bytes raise CsError {
  if enc.length() != 32 {
    raise InvalidLength("HPKE encapsulated key must be 32 bytes")
  }
  if sk_r.length() != 32 {
    raise InvalidLength("HPKE recipient secret key must be 32 bytes")
  }
  let dh = try @crypto.x25519_dh(sk_r, enc) catch {
    e => raise CryptoError(e)
  }
  let pk_r = try @crypto.x25519_public_key(sk_r) catch {
    e => raise CryptoError(e)
  }
  let kem_context = @tls.bytes_concat([enc, pk_r])
  extract_and_expand(dh, kem_context)
}

///|
/// RFC 9180 §5.1 KeyScheduleBase(shared_secret, info).
/// Returns `(key, base_nonce)`.
fn hpke_key_schedule_base(
  cs : CipherSuite,
  shared_secret : Bytes,
  info : Bytes,
) -> (Bytes, Bytes) raise CsError {
  let suite_id = hpke_suite_id(cs)
  let psk_id_hash = labeled_extract(suite_id, b"", b"psk_id_hash", b"")
  let info_hash = labeled_extract(suite_id, b"", b"info_hash", info)
  let ks_context = @tls.bytes_concat([hpke_mode_base, psk_id_hash, info_hash])
  let secret = labeled_extract(suite_id, shared_secret, b"secret", b"")
  let key = labeled_expand(
    suite_id,
    secret,
    b"key",
    ks_context,
    cs.aead_key_len(),
  )
  let base_nonce = labeled_expand(
    suite_id,
    secret,
    b"base_nonce",
    ks_context,
    cs.aead_nonce_len(),
  )
  (key, base_nonce)
}

///|
/// RFC 9180 §6.1 Single-Shot SealBase with caller-supplied ephemeral secret key `sk_e`.
/// Returns `(enc, ciphertext)`.
pub fn hpke_seal_base_with_ephemeral(
  cs : CipherSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  plaintext : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise CsError {
  let (shared_secret, enc) = dhkem_encap_with_ephemeral(pk_r, sk_e)
  let (key, base_nonce) = hpke_key_schedule_base(cs, shared_secret, info)
  let ct = cs.aead_seal(key, base_nonce, aad, plaintext)
  (enc, ct)
}

///|
/// RFC 9180 §6.1 Single-Shot SealBase using a `DeterministicRng` to derive the ephemeral key pair.
/// Returns `(enc, ciphertext)`.
pub fn hpke_seal_base(
  cs : CipherSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  plaintext : Bytes,
  rng : @crypto.DeterministicRng,
) -> (Bytes, Bytes) raise CsError {
  let ikm = rng.next_bytes(32)
  let (sk_e, _pk_e) = kem_derive_key_pair(ikm)
  hpke_seal_base_with_ephemeral(cs, pk_r, info, aad, plaintext, sk_e)
}

///|
/// RFC 9180 §6.1 Single-Shot OpenBase.
/// Returns the decrypted plaintext or raises `DecryptionFailed` on authentication failure.
pub fn hpke_open_base(
  cs : CipherSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CsError {
  let shared_secret = dhkem_decap(enc, sk_r)
  let (key, base_nonce) = hpke_key_schedule_base(cs, shared_secret, info)
  cs.aead_open(key, base_nonce, aad, ciphertext)
}
