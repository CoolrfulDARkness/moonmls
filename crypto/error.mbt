///|
#derive(Eq, Debug)
pub(all) suberror CryptoError {
  InvalidKeyLength
  InvalidNonceLength
  InvalidInputLength
  AuthFailed
  InvalidPoint
  LowOrderPoint
  InvalidSignature
  OutputTooLong
}

///|
pub impl Show for CryptoError with fn output(self, logger) {
  let name = match self {
    InvalidKeyLength => "InvalidKeyLength"
    InvalidNonceLength => "InvalidNonceLength"
    InvalidInputLength => "InvalidInputLength"
    AuthFailed => "AuthFailed"
    InvalidPoint => "InvalidPoint"
    LowOrderPoint => "LowOrderPoint"
    InvalidSignature => "InvalidSignature"
    OutputTooLong => "OutputTooLong"
  }
  logger.write_string(name)
}

///|
pub fn ct_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0U
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  diff == 0U
}

///|
pub fn xor_bytes(a : Bytes, b : Bytes) -> Bytes raise CryptoError {
  if a.length() != b.length() {
    raise InvalidInputLength
  }
  Bytes::makei(a.length(), fn(i) { (a[i].to_int() ^ b[i].to_int()).to_byte() })
}

///|
fn load_be32(data : Bytes, offset : Int32) -> UInt32 {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn load_be32_arr(data : FixedArray[Byte], offset : Int32) -> UInt32 {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn store_be32_arr(dst : FixedArray[Byte], offset : Int32, val : UInt32) -> Unit {
  dst[offset] = ((val >> 24) & 0xFFU).to_byte()
  dst[offset + 1] = ((val >> 16) & 0xFFU).to_byte()
  dst[offset + 2] = ((val >> 8) & 0xFFU).to_byte()
  dst[offset + 3] = (val & 0xFFU).to_byte()
}

///|
fn load_be64(data : Bytes, offset : Int32) -> UInt64 {
  (data[offset].to_uint64() << 56) |
  (data[offset + 1].to_uint64() << 48) |
  (data[offset + 2].to_uint64() << 40) |
  (data[offset + 3].to_uint64() << 32) |
  (data[offset + 4].to_uint64() << 24) |
  (data[offset + 5].to_uint64() << 16) |
  (data[offset + 6].to_uint64() << 8) |
  data[offset + 7].to_uint64()
}

///|
fn load_be64_arr(data : FixedArray[Byte], offset : Int32) -> UInt64 {
  (data[offset].to_uint64() << 56) |
  (data[offset + 1].to_uint64() << 48) |
  (data[offset + 2].to_uint64() << 40) |
  (data[offset + 3].to_uint64() << 32) |
  (data[offset + 4].to_uint64() << 24) |
  (data[offset + 5].to_uint64() << 16) |
  (data[offset + 6].to_uint64() << 8) |
  data[offset + 7].to_uint64()
}

///|
fn store_be64_arr(dst : FixedArray[Byte], offset : Int32, val : UInt64) -> Unit {
  dst[offset] = ((val >> 56) & 0xFFUL).to_byte()
  dst[offset + 1] = ((val >> 48) & 0xFFUL).to_byte()
  dst[offset + 2] = ((val >> 40) & 0xFFUL).to_byte()
  dst[offset + 3] = ((val >> 32) & 0xFFUL).to_byte()
  dst[offset + 4] = ((val >> 24) & 0xFFUL).to_byte()
  dst[offset + 5] = ((val >> 16) & 0xFFUL).to_byte()
  dst[offset + 6] = ((val >> 8) & 0xFFUL).to_byte()
  dst[offset + 7] = (val & 0xFFUL).to_byte()
}

///|
fn load_le32(data : Bytes, offset : Int32) -> UInt32 {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn store_le32_arr(dst : FixedArray[Byte], offset : Int32, val : UInt32) -> Unit {
  dst[offset] = (val & 0xFFU).to_byte()
  dst[offset + 1] = ((val >> 8) & 0xFFU).to_byte()
  dst[offset + 2] = ((val >> 16) & 0xFFU).to_byte()
  dst[offset + 3] = ((val >> 24) & 0xFFU).to_byte()
}

///|
fn load_le64(data : Bytes, offset : Int32) -> UInt64 {
  data[offset].to_uint64() |
  (data[offset + 1].to_uint64() << 8) |
  (data[offset + 2].to_uint64() << 16) |
  (data[offset + 3].to_uint64() << 24) |
  (data[offset + 4].to_uint64() << 32) |
  (data[offset + 5].to_uint64() << 40) |
  (data[offset + 6].to_uint64() << 48) |
  (data[offset + 7].to_uint64() << 56)
}

///|
fn store_le64_arr(dst : FixedArray[Byte], offset : Int32, val : UInt64) -> Unit {
  dst[offset] = (val & 0xFFUL).to_byte()
  dst[offset + 1] = ((val >> 8) & 0xFFUL).to_byte()
  dst[offset + 2] = ((val >> 16) & 0xFFUL).to_byte()
  dst[offset + 3] = ((val >> 24) & 0xFFUL).to_byte()
  dst[offset + 4] = ((val >> 32) & 0xFFUL).to_byte()
  dst[offset + 5] = ((val >> 40) & 0xFFUL).to_byte()
  dst[offset + 6] = ((val >> 48) & 0xFFUL).to_byte()
  dst[offset + 7] = ((val >> 56) & 0xFFUL).to_byte()
}

///|
fn bytes_from_fixed(arr : FixedArray[Byte]) -> Bytes {
  Bytes::makei(arr.length(), fn(i) { arr[i] })
}
