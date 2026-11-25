///|
/// Errors raised by RFC 9180 HPKE and RFC 9420 MLS CipherSuite operations.
#derive(Eq, Debug)
pub(all) suberror CsError {
  UnsupportedCipherSuite(UInt32)
  CryptoError(@crypto.CryptoError)
  TlsError(@tls.TlsError)
  InvalidLength(String)
  DecryptionFailed
  VerificationFailed
}

///|
pub impl Show for CsError with fn output(self, logger) {
  match self {
    UnsupportedCipherSuite(id) => {
      logger.write_string("UnsupportedCipherSuite(")
      Show::output(id, logger)
      logger.write_string(")")
    }
    CryptoError(err) => {
      logger.write_string("CryptoError(")
      Show::output(err, logger)
      logger.write_string(")")
    }
    TlsError(err) => {
      logger.write_string("TlsError(")
      Show::output(err, logger)
      logger.write_string(")")
    }
    InvalidLength(msg) => {
      logger.write_string("InvalidLength(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    DecryptionFailed => logger.write_string("DecryptionFailed")
    VerificationFailed => logger.write_string("VerificationFailed")
  }
}

///|
/// Supported RFC 9420 §17.1 MLS CipherSuites.
/// - CS1 (`0x0001`): MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
/// - CS3 (`0x0003`): MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
#derive(Eq, Debug)
pub(all) enum CipherSuite {
  X25519Aes128GcmSha256Ed25519
  X25519ChaCha20Poly1305Sha256Ed25519
}

///|
pub impl Show for CipherSuite with fn output(self, logger) {
  match self {
    X25519Aes128GcmSha256Ed25519 =>
      logger.write_string("X25519Aes128GcmSha256Ed25519")
    X25519ChaCha20Poly1305Sha256Ed25519 =>
      logger.write_string("X25519ChaCha20Poly1305Sha256Ed25519")
  }
}

///|
/// Parses an MLS cipher suite identifier (`uint16`).
pub fn CipherSuite::from_id(id : UInt32) -> CipherSuite raise CsError {
  match id {
    1U => X25519Aes128GcmSha256Ed25519
    3U => X25519ChaCha20Poly1305Sha256Ed25519
    _ => raise UnsupportedCipherSuite(id)
  }
}

///|
/// Returns the RFC 9420 §17.1 numeric identifier of this cipher suite.
pub fn CipherSuite::id(self : CipherSuite) -> UInt32 {
  match self {
    X25519Aes128GcmSha256Ed25519 => 1U
    X25519ChaCha20Poly1305Sha256Ed25519 => 3U
  }
}

///|
/// Returns the hash output length (`Nh`) in bytes.
pub fn CipherSuite::hash_len(self : CipherSuite) -> Int32 {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 => 32
  }
}

///|
/// Returns the AEAD key length (`Nk`) in bytes.
pub fn CipherSuite::aead_key_len(self : CipherSuite) -> Int32 {
  match self {
    X25519Aes128GcmSha256Ed25519 => 16
    X25519ChaCha20Poly1305Sha256Ed25519 => 32
  }
}

///|
/// Returns the AEAD nonce length (`Nn`) in bytes.
pub fn CipherSuite::aead_nonce_len(self : CipherSuite) -> Int32 {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 => 12
  }
}

///|
/// Returns the AEAD authentication tag length (`Nt`) in bytes.
pub fn CipherSuite::aead_tag_len(self : CipherSuite) -> Int32 {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 => 16
  }
}

///|
/// Returns the KDF secret length (`Nh`) in bytes.
pub fn CipherSuite::secret_len(self : CipherSuite) -> Int32 {
  match self {
    X25519Aes128GcmSha256Ed25519 | X25519ChaCha20Poly1305Sha256Ed25519 => 32
  }
}

///|
/// Returns the RFC 9180 §7.3 HPKE AEAD identifier.
pub fn CipherSuite::aead_id(self : CipherSuite) -> UInt32 {
  match self {
    X25519Aes128GcmSha256Ed25519 => 1U
    X25519ChaCha20Poly1305Sha256Ed25519 => 3U
  }
}

///|
/// Encodes a MoonBit `String` into standard UTF-8 `Bytes`.
fn string_to_utf8_bytes(s : String) -> Bytes {
  let out : Array[Byte] = Array(capacity=s.length())
  for c in s {
    let cp = c.to_int()
    if cp <= 0x7F {
      out.push(cp.to_byte())
    } else if cp <= 0x7FF {
      out.push((0xC0 | (cp >> 6)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else if cp <= 0xFFFF {
      out.push((0xE0 | (cp >> 12)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else {
      out.push((0xF0 | (cp >> 18)).to_byte())
      out.push((0x80 | ((cp >> 12) & 0x3F)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    }
  }
  Bytes::makei(out.length(), fn(i) { out[i] })
}

///|
/// Encodes an unsigned 16-bit integer as big-endian 2 bytes (`I2OSP(val, 2)`).
fn i2osp2(value : UInt32) -> Bytes {
  Bytes::makei(2, fn(i) {
    if i == 0 {
      ((value >> 8) & 0xFFU).to_byte()
    } else {
      (value & 0xFFU).to_byte()
    }
  })
}
