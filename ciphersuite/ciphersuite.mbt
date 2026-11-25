///|
/// Computes the cipher suite's hash function (`SHA-256` for CS1 and CS3).
pub fn CipherSuite::hash(self : CipherSuite, data : Bytes) -> Bytes {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      @crypto.sha256(data)
  }
}

///|
/// Computes the cipher suite's MAC (`HMAC-SHA256` for CS1 and CS3).
pub fn CipherSuite::mac(
  self : CipherSuite,
  key : Bytes,
  data : Bytes,
) -> Bytes {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      @crypto.hmac_sha256(key, data)
  }
}

///|
/// Constant-time verification of a MAC tag.
pub fn CipherSuite::verify_mac(
  self : CipherSuite,
  key : Bytes,
  data : Bytes,
  tag : Bytes,
) -> Bool {
  @crypto.ct_equal(self.mac(key, data), tag)
}

///|
/// Computes HKDF-Extract using the cipher suite's KDF (`HKDF-SHA256` for CS1 and CS3).
pub fn CipherSuite::extract(
  self : CipherSuite,
  salt : Bytes,
  ikm : Bytes,
) -> Bytes {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      @crypto.hkdf_extract(salt, ikm)
  }
}

///|
/// RFC 9420 §8 ExpandWithLabel(Secret, Label, Context, Length).
/// `KDFLabel = u16(length) || opaque("MLS 1.0 " + label) || opaque(context)`.
pub fn CipherSuite::expand_with_label(
  self : CipherSuite,
  secret : Bytes,
  label : String,
  context : Bytes,
  length : Int,
) -> Bytes raise CsError {
  if length < 0 || length > 0xFFFF {
    raise InvalidLength("ExpandWithLabel length out of uint16 range")
  }
  let w = @tls.Writer::new()
  w.write_u16(length.reinterpret_as_uint())
  try {
    w.write_opaque(string_to_utf8_bytes("MLS 1.0 " + label))
    w.write_opaque(context)
  } catch {
    e => raise TlsError(e)
  }
  let info = w.to_bytes()
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      try @crypto.hkdf_expand(secret, info, length) catch {
        e => raise CryptoError(e)
      }
  }
}

///|
/// RFC 9420 §8 DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", KDF.Nh).
pub fn CipherSuite::derive_secret(
  self : CipherSuite,
  secret : Bytes,
  label : String,
) -> Bytes raise CsError {
  self.expand_with_label(secret, label, b"", self.secret_len())
}

///|
/// RFC 9420 §9.1 DeriveTreeSecret(Secret, Label, Generation, Length).
/// Context is `uint32(generation)` in big-endian byte order.
pub fn CipherSuite::derive_tree_secret(
  self : CipherSuite,
  secret : Bytes,
  label : String,
  generation : UInt,
  length : Int,
) -> Bytes raise CsError {
  let w = @tls.Writer::new()
  w.write_u32(generation)
  self.expand_with_label(secret, label, w.to_bytes(), length)
}

///|
/// RFC 9420 §5.2 RefHash(label, value) = Hash(opaque(label) || opaque(value)).
pub fn CipherSuite::ref_hash(
  self : CipherSuite,
  label : String,
  value : Bytes,
) -> Bytes raise CsError {
  let w = @tls.Writer::new()
  try {
    w.write_opaque(string_to_utf8_bytes(label))
    w.write_opaque(value)
  } catch {
    e => raise TlsError(e)
  }
  self.hash(w.to_bytes())
}

///|
/// RFC 9420 §5.2 MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value).
pub fn CipherSuite::make_key_package_ref(
  self : CipherSuite,
  key_package_bytes : Bytes,
) -> Bytes raise CsError {
  self.ref_hash("MLS 1.0 KeyPackage Reference", key_package_bytes)
}

///|
/// RFC 9420 §5.2 MakeProposalRef(value) = RefHash("MLS 1.0 Proposal Reference", value).
pub fn CipherSuite::make_proposal_ref(
  self : CipherSuite,
  authenticated_content_bytes : Bytes,
) -> Bytes raise CsError {
  self.ref_hash("MLS 1.0 Proposal Reference", authenticated_content_bytes)
}

///|
/// Encodes `SignContent` (RFC 9420 §5.1.2) or `EncryptContext` (RFC 9420 §5.1.3):
/// `opaque("MLS 1.0 " + label) || opaque(payload)`.
fn encode_labeled_content(
  label : String,
  payload : Bytes,
) -> Bytes raise CsError {
  let w = @tls.Writer::new()
  try {
    w.write_opaque(string_to_utf8_bytes("MLS 1.0 " + label))
    w.write_opaque(payload)
  } catch {
    e => raise TlsError(e)
  }
  w.to_bytes()
}

///|
/// RFC 9420 §5.1.2 SignWithLabel(SignatureKey, Label, Content).
pub fn CipherSuite::sign_with_label(
  self : CipherSuite,
  sign_priv : Bytes,
  label : String,
  content : Bytes,
) -> Bytes raise CsError {
  let sign_content = encode_labeled_content(label, content)
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      try @crypto.ed25519_sign(sign_priv, sign_content) catch {
        e => raise CryptoError(e)
      }
  }
}

///|
/// RFC 9420 §5.1.2 VerifyWithLabel(VerificationKey, Label, Content, SignatureValue).
pub fn CipherSuite::verify_with_label(
  self : CipherSuite,
  sign_pub : Bytes,
  label : String,
  content : Bytes,
  signature : Bytes,
) -> Bool {
  let sign_content = try encode_labeled_content(label, content) catch {
    _ => return false
  }
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      @crypto.ed25519_verify(sign_pub, sign_content, signature)
  }
}

///|
/// RFC 9420 §5.1.3 EncryptWithLabel(PublicKey, Label, Context, Plaintext).
/// Returns `(kem_output, ciphertext)`.
pub fn CipherSuite::encrypt_with_label(
  self : CipherSuite,
  pk_r : Bytes,
  label : String,
  context : Bytes,
  plaintext : Bytes,
  rng : @crypto.DeterministicRng,
) -> (Bytes, Bytes) raise CsError {
  let info = encode_labeled_content(label, context)
  hpke_seal_base(self, pk_r, info, b"", plaintext, rng)
}

///|
/// Deterministic variant of RFC 9420 §5.1.3 EncryptWithLabel using an explicit ephemeral key `sk_e`.
/// Returns `(kem_output, ciphertext)`.
pub fn CipherSuite::encrypt_with_label_deterministic(
  self : CipherSuite,
  pk_r : Bytes,
  label : String,
  context : Bytes,
  plaintext : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise CsError {
  let info = encode_labeled_content(label, context)
  hpke_seal_base_with_ephemeral(self, pk_r, info, b"", plaintext, sk_e)
}

///|
/// RFC 9420 §5.1.3 DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext).
pub fn CipherSuite::decrypt_with_label(
  self : CipherSuite,
  sk_r : Bytes,
  label : String,
  context : Bytes,
  kem_output : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CsError {
  let info = encode_labeled_content(label, context)
  hpke_open_base(self, kem_output, sk_r, info, b"", ciphertext)
}

///|
/// Encrypts and authenticates `plaintext` using the cipher suite's AEAD.
pub fn CipherSuite::aead_seal(
  self : CipherSuite,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CsError {
  match self {
    X25519Aes128GcmSha256Ed25519 =>
      try @crypto.aes128_gcm_seal(key, nonce, aad, plaintext) catch {
        e => raise CryptoError(e)
      }
    X25519ChaCha20Poly1305Sha256Ed25519 =>
      try @crypto.chacha20_poly1305_seal(key, nonce, aad, plaintext) catch {
        e => raise CryptoError(e)
      }
  }
}

///|
/// Decrypts and verifies `ciphertext` (ciphertext || tag) using the cipher suite's AEAD.
/// Raises `DecryptionFailed` on authentication failure.
pub fn CipherSuite::aead_open(
  self : CipherSuite,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CsError {
  match self {
    X25519Aes128GcmSha256Ed25519 =>
      try @crypto.aes128_gcm_open(key, nonce, aad, ciphertext) catch {
        @crypto.AuthFailed => raise DecryptionFailed
        e => raise CryptoError(e)
      }
    X25519ChaCha20Poly1305Sha256Ed25519 =>
      try @crypto.chacha20_poly1305_open(key, nonce, aad, ciphertext) catch {
        @crypto.AuthFailed => raise DecryptionFailed
        e => raise CryptoError(e)
      }
  }
}

///|
/// Derives a signature key pair `(sign_priv, sign_pub)` from a 32-byte seed.
pub fn CipherSuite::signature_keypair_from_seed(
  self : CipherSuite,
  seed : Bytes,
) -> (Bytes, Bytes) raise CsError {
  if seed.length() != 32 {
    raise InvalidLength("signature key seed must be 32 bytes")
  }
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 => {
      let pk = try @crypto.ed25519_public_key(seed) catch {
        e => raise CryptoError(e)
      }
      (seed, pk)
    }
  }
}

///|
/// Derives an HPKE KEM key pair `(sk, pk)` from input keying material `ikm`
/// using RFC 9180 §7.1.3 `DeriveKeyPair`.
pub fn CipherSuite::kem_keypair_from_ikm(
  self : CipherSuite,
  ikm : Bytes,
) -> (Bytes, Bytes) raise CsError {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 =>
      kem_derive_key_pair(ikm)
  }
}

///|
/// Returns an all-zero secret of length `self.secret_len()` (32 bytes).
pub fn CipherSuite::zero_secret(self : CipherSuite) -> Bytes {
  Bytes::make(self.secret_len(), b'\x00')
}
