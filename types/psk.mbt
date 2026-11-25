///|
/// HPKE ciphertext container (`HPKECiphertext`, RFC 9420 §5.1.3).
#derive(Eq, Debug)
pub(all) struct HpkeCiphertext {
  kem_output : Bytes
  ciphertext : Bytes
}

///|
pub fn HpkeCiphertext::encode(
  self : HpkeCiphertext,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.kem_output)
  w.write_opaque(self.ciphertext)
}

///|
pub fn HpkeCiphertext::to_bytes(
  self : HpkeCiphertext,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn HpkeCiphertext::decode(
  r : @tls.Reader,
) -> HpkeCiphertext raise @tls.TlsError {
  let kem_output = r.read_opaque()
  let ciphertext = r.read_opaque()
  { kem_output, ciphertext }
}

///|
pub fn HpkeCiphertext::from_bytes(
  b : Bytes,
) -> HpkeCiphertext raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = HpkeCiphertext::decode(r)
  r.ensure_empty()
  v
}

///|
/// Pre-shared key type (`PSKType`, `uint8`, RFC 9420 §8.4).
#derive(Eq, Debug)
pub(all) enum PskType {
  External
  Resumption
}

///|
pub fn PskType::to_u8(self : PskType) -> Byte {
  match self {
    External => b'\x01'
    Resumption => b'\x02'
  }
}

///|
pub fn PskType::from_u8(value : Byte) -> PskType raise @tls.TlsError {
  match value {
    b'\x01' => External
    b'\x02' => Resumption
    _ => raise @tls.TlsError::InvalidEnum("invalid PskType: \{value}")
  }
}

///|
pub fn PskType::encode(self : PskType, w : @tls.Writer) -> Unit {
  w.write_u8(self.to_u8())
}

///|
pub fn PskType::to_bytes(self : PskType) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PskType::decode(r : @tls.Reader) -> PskType raise @tls.TlsError {
  PskType::from_u8(r.read_u8())
}

///|
pub fn PskType::from_bytes(b : Bytes) -> PskType raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PskType::decode(r)
  r.ensure_empty()
  v
}

///|
/// Resumption PSK usage (`ResumptionPSKUsage`, `uint8`, RFC 9420 §8.4).
#derive(Eq, Debug)
pub(all) enum ResumptionPskUsage {
  Application
  Reinit
  Branch
}

///|
pub fn ResumptionPskUsage::to_u8(self : ResumptionPskUsage) -> Byte {
  match self {
    Application => b'\x01'
    Reinit => b'\x02'
    Branch => b'\x03'
  }
}

///|
pub fn ResumptionPskUsage::from_u8(
  value : Byte,
) -> ResumptionPskUsage raise @tls.TlsError {
  match value {
    b'\x01' => Application
    b'\x02' => Reinit
    b'\x03' => Branch
    _ =>
      raise @tls.TlsError::InvalidEnum("invalid ResumptionPskUsage: \{value}")
  }
}

///|
pub fn ResumptionPskUsage::encode(
  self : ResumptionPskUsage,
  w : @tls.Writer,
) -> Unit {
  w.write_u8(self.to_u8())
}

///|
pub fn ResumptionPskUsage::to_bytes(self : ResumptionPskUsage) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ResumptionPskUsage::decode(
  r : @tls.Reader,
) -> ResumptionPskUsage raise @tls.TlsError {
  ResumptionPskUsage::from_u8(r.read_u8())
}

///|
pub fn ResumptionPskUsage::from_bytes(
  b : Bytes,
) -> ResumptionPskUsage raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ResumptionPskUsage::decode(r)
  r.ensure_empty()
  v
}

///|
/// Pre-shared key identifier (`PreSharedKeyID`, RFC 9420 §8.4).
#derive(Eq, Debug)
pub(all) enum PreSharedKeyId {
  External(psk_id~ : Bytes, psk_nonce~ : Bytes)
  Resumption(
    usage~ : UInt,
    psk_group_id~ : Bytes,
    psk_epoch~ : UInt64,
    psk_nonce~ : Bytes
  )
}

///|
pub fn PreSharedKeyId::encode(
  self : PreSharedKeyId,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  match self {
    External(psk_id~, psk_nonce~) => {
      PskType::External.encode(w)
      w.write_opaque(psk_id)
      w.write_opaque(psk_nonce)
    }
    Resumption(usage~, psk_group_id~, psk_epoch~, psk_nonce~) => {
      if usage < 1U || usage > 3U {
        raise @tls.TlsError::InvalidEnum(
          "invalid ResumptionPskUsage: \{usage}",
        )
      }
      PskType::Resumption.encode(w)
      w.write_u8(usage.to_byte())
      w.write_opaque(psk_group_id)
      w.write_u64(psk_epoch)
      w.write_opaque(psk_nonce)
    }
  }
}

///|
pub fn PreSharedKeyId::to_bytes(
  self : PreSharedKeyId,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PreSharedKeyId::decode(
  r : @tls.Reader,
) -> PreSharedKeyId raise @tls.TlsError {
  let psk_type = PskType::decode(r)
  match psk_type {
    External => {
      let psk_id = r.read_opaque()
      let psk_nonce = r.read_opaque()
      External(psk_id~, psk_nonce~)
    }
    Resumption => {
      let usage = ResumptionPskUsage::decode(r).to_u8().to_uint()
      let psk_group_id = r.read_opaque()
      let psk_epoch = r.read_u64()
      let psk_nonce = r.read_opaque()
      Resumption(usage~, psk_group_id~, psk_epoch~, psk_nonce~)
    }
  }
}

///|
pub fn PreSharedKeyId::from_bytes(
  b : Bytes,
) -> PreSharedKeyId raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PreSharedKeyId::decode(r)
  r.ensure_empty()
  v
}
