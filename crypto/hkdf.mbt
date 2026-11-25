///|
pub fn hmac_sha256(key : Bytes, data : Bytes) -> Bytes {
  let k_pad = FixedArray::make(64, b'\x00')
  let actual_key = if key.length() > 64 { sha256(key) } else { key }
  for i = 0; i < actual_key.length(); i = i + 1 {
    k_pad[i] = actual_key[i]
  }
  let ipad = FixedArray::make(64, b'\x00')
  let opad = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    ipad[i] = (k_pad[i].to_int() ^ 0x36).to_byte()
    opad[i] = (k_pad[i].to_int() ^ 0x5c).to_byte()
  }
  let inner = Sha256State::new()
  inner.update_fixed(ipad)
  inner.update(data)
  let inner_hash = inner.finalize()
  let outer = Sha256State::new()
  outer.update_fixed(opad)
  outer.update(inner_hash)
  outer.finalize()
}

///|
pub fn hkdf_extract(salt : Bytes, ikm : Bytes) -> Bytes {
  let actual_salt = if salt.length() == 0 {
    Bytes::make(32, b'\x00')
  } else {
    salt
  }
  hmac_sha256(actual_salt, ikm)
}

///|
pub fn hkdf_expand(
  prk : Bytes,
  info : Bytes,
  length : Int32,
) -> Bytes raise CryptoError {
  if length < 0 {
    raise InvalidInputLength
  }
  if length > 255 * 32 {
    raise OutputTooLong
  }
  if length == 0 {
    return b""
  }
  let n = (length + 31) / 32
  let out = FixedArray::make(length, b'\x00')
  let mut prev = b""
  let mut written = 0
  for i = 1; i <= n; i = i + 1 {
    let msg_len = prev.length() + info.length() + 1
    let msg = FixedArray::make(msg_len, b'\x00')
    for j = 0; j < prev.length(); j = j + 1 {
      msg[j] = prev[j]
    }
    for j = 0; j < info.length(); j = j + 1 {
      msg[prev.length() + j] = info[j]
    }
    msg[msg_len - 1] = i.to_byte()
    let t = hmac_sha256(prk, bytes_from_fixed(msg))
    prev = t
    let to_copy = if length - written < 32 { length - written } else { 32 }
    for j = 0; j < to_copy; j = j + 1 {
      out[written + j] = t[j]
    }
    written = written + to_copy
  }
  bytes_from_fixed(out)
}
