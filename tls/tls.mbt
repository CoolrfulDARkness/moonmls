///|
/// Errors raised by strict RFC 9420 §2.1.2 TLS presentation language codec and
/// byte/hex helpers.
#derive(Eq, Debug)
pub(all) suberror TlsError {
  UnexpectedEof
  InvalidVarint
  NonMinimalVarint
  VarintOverflow
  TrailingData
  LengthMismatch
  InvalidEnum(String)
  LimitExceeded
}

///|
pub impl Show for TlsError with fn output(self, logger) {
  match self {
    UnexpectedEof => logger.write_string("UnexpectedEof")
    InvalidVarint => logger.write_string("InvalidVarint")
    NonMinimalVarint => logger.write_string("NonMinimalVarint")
    VarintOverflow => logger.write_string("VarintOverflow")
    TrailingData => logger.write_string("TrailingData")
    LengthMismatch => logger.write_string("LengthMismatch")
    InvalidEnum(msg) => {
      logger.write_string("InvalidEnum(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    LimitExceeded => logger.write_string("LimitExceeded")
  }
}

///|
/// Growable big-endian TLS presentation language writer.
pub struct Writer {
  buf : Array[Byte]
}

///|
/// Creates an empty `Writer`.
pub fn Writer::new() -> Writer {
  { buf: [], }
}

///|
/// Returns the number of bytes written so far.
pub fn Writer::len(self : Writer) -> Int32 {
  self.buf.length()
}

///|
/// Materializes the written bytes.
pub fn Writer::to_bytes(self : Writer) -> Bytes {
  Bytes::makei(self.buf.length(), fn(i) { self.buf[i] })
}

///|
/// Writes an unsigned 8-bit integer (`uint8`).
pub fn Writer::write_u8(self : Writer, value : Byte) -> Unit {
  self.buf.push(value)
}

///|
/// Writes an unsigned 16-bit integer (`uint16`) in big-endian byte order.
pub fn Writer::write_u16(self : Writer, value : UInt32) -> Unit {
  self.buf.push(((value >> 8) & 0xFFU).to_byte())
  self.buf.push((value & 0xFFU).to_byte())
}

///|
/// Writes an unsigned 32-bit integer (`uint32`) in big-endian byte order.
pub fn Writer::write_u32(self : Writer, value : UInt32) -> Unit {
  self.buf.push(((value >> 24) & 0xFFU).to_byte())
  self.buf.push(((value >> 16) & 0xFFU).to_byte())
  self.buf.push(((value >> 8) & 0xFFU).to_byte())
  self.buf.push((value & 0xFFU).to_byte())
}

///|
/// Writes an unsigned 64-bit integer (`uint64`) in big-endian byte order.
pub fn Writer::write_u64(self : Writer, value : UInt64) -> Unit {
  self.buf.push(((value >> 56) & 0xFFUL).to_byte())
  self.buf.push(((value >> 48) & 0xFFUL).to_byte())
  self.buf.push(((value >> 40) & 0xFFUL).to_byte())
  self.buf.push(((value >> 32) & 0xFFUL).to_byte())
  self.buf.push(((value >> 24) & 0xFFUL).to_byte())
  self.buf.push(((value >> 16) & 0xFFUL).to_byte())
  self.buf.push(((value >> 8) & 0xFFUL).to_byte())
  self.buf.push((value & 0xFFUL).to_byte())
}

///|
/// Appends raw bytes without a length prefix.
pub fn Writer::write_raw(self : Writer, data : Bytes) -> Unit {
  for i = 0; i < data.length(); i = i + 1 {
    self.buf.push(data[i])
  }
}

///|
/// Writes an MLS variable-length integer (RFC 9420 §2.1.2).
/// Valid range is `0 <= value <= 0x3FFFFFFF` (1073741823).
pub fn Writer::write_varint(
  self : Writer,
  value : Int32,
) -> Unit raise TlsError {
  if value < 0 || value > 0x3FFFFFFF {
    raise VarintOverflow
  }
  if value <= 0x3F {
    self.buf.push(value.to_byte())
  } else if value <= 0x3FFF {
    self.buf.push((((value >> 8) & 0x3F) | 0x40).to_byte())
    self.buf.push((value & 0xFF).to_byte())
  } else {
    self.buf.push((((value >> 24) & 0x3F) | 0x80).to_byte())
    self.buf.push(((value >> 16) & 0xFF).to_byte())
    self.buf.push(((value >> 8) & 0xFF).to_byte())
    self.buf.push((value & 0xFF).to_byte())
  }
}

///|
/// Writes an MLS variable-length opaque byte vector (`opaque data<V>`).
pub fn Writer::write_opaque(self : Writer, data : Bytes) -> Unit raise TlsError {
  self.write_varint(data.length())
  self.write_raw(data)
}

///|
/// Writes an MLS variable-length vector (`T vec<V>`), prefixing the encoded
/// payload emitted by `encode_elements` with its varint byte length.
pub fn Writer::write_vec(
  self : Writer,
  encode_elements : (Writer) -> Unit raise TlsError,
) -> Unit raise TlsError {
  let sub = Writer::new()
  encode_elements(sub)
  self.write_opaque(sub.to_bytes())
}

///|
/// Writes an MLS `optional<T>` value: `0x00` for `None`, or `0x01` followed by
/// the encoded value for `Some(v)`.
pub fn[T] Writer::write_optional(
  self : Writer,
  value : T?,
  encode_value : (Writer, T) -> Unit raise TlsError,
) -> Unit raise TlsError {
  match value {
    None => self.write_u8(b'\x00')
    Some(v) => {
      self.write_u8(b'\x01')
      encode_value(self, v)
    }
  }
}

///|
/// Strict cursor-based TLS presentation language reader.
pub struct Reader {
  data : Bytes
  mut pos : Int32
}

///|
/// Creates a `Reader` positioned at offset 0 of `data`.
pub fn Reader::new(data : Bytes) -> Reader {
  { data, pos: 0, }
}

///|
/// Returns the number of unread bytes remaining.
pub fn Reader::remaining(self : Reader) -> Int32 {
  self.data.length() - self.pos
}

///|
/// Returns `true` if no unread bytes remain.
pub fn Reader::is_empty(self : Reader) -> Bool {
  self.pos >= self.data.length()
}

///|
/// Returns the current byte offset in the underlying buffer.
pub fn Reader::offset(self : Reader) -> Int32 {
  self.pos
}

///|
/// Fails with `TrailingData` if any unread bytes remain.
pub fn Reader::ensure_empty(self : Reader) -> Unit raise TlsError {
  if self.pos < self.data.length() {
    raise TrailingData
  }
}

///|
/// Reads an unsigned 8-bit integer (`uint8`).
pub fn Reader::read_u8(self : Reader) -> Byte raise TlsError {
  if self.remaining() < 1 {
    raise UnexpectedEof
  }
  let b = self.data[self.pos]
  self.pos += 1
  b
}

///|
/// Reads an unsigned 16-bit integer (`uint16`) in big-endian byte order.
pub fn Reader::read_u16(self : Reader) -> UInt32 raise TlsError {
  if self.remaining() < 2 {
    raise UnexpectedEof
  }
  let b0 = self.data[self.pos].to_uint()
  let b1 = self.data[self.pos + 1].to_uint()
  self.pos += 2
  (b0 << 8) | b1
}

///|
/// Reads an unsigned 32-bit integer (`uint32`) in big-endian byte order.
pub fn Reader::read_u32(self : Reader) -> UInt32 raise TlsError {
  if self.remaining() < 4 {
    raise UnexpectedEof
  }
  let b0 = self.data[self.pos].to_uint()
  let b1 = self.data[self.pos + 1].to_uint()
  let b2 = self.data[self.pos + 2].to_uint()
  let b3 = self.data[self.pos + 3].to_uint()
  self.pos += 4
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
/// Reads an unsigned 64-bit integer (`uint64`) in big-endian byte order.
pub fn Reader::read_u64(self : Reader) -> UInt64 raise TlsError {
  if self.remaining() < 8 {
    raise UnexpectedEof
  }
  let b0 = self.data[self.pos].to_uint64()
  let b1 = self.data[self.pos + 1].to_uint64()
  let b2 = self.data[self.pos + 2].to_uint64()
  let b3 = self.data[self.pos + 3].to_uint64()
  let b4 = self.data[self.pos + 4].to_uint64()
  let b5 = self.data[self.pos + 5].to_uint64()
  let b6 = self.data[self.pos + 6].to_uint64()
  let b7 = self.data[self.pos + 7].to_uint64()
  self.pos += 8
  (b0 << 56) |
  (b1 << 48) |
  (b2 << 40) |
  (b3 << 32) |
  (b4 << 24) |
  (b5 << 16) |
  (b6 << 8) |
  b7
}

///|
/// Reads exactly `len` bytes.
pub fn Reader::read_fixed(self : Reader, len : Int32) -> Bytes raise TlsError {
  if len < 0 {
    raise LengthMismatch
  }
  if len > 0x3FFFFFFF {
    raise LimitExceeded
  }
  if len > self.remaining() {
    raise UnexpectedEof
  }
  let out = bytes_slice(self.data, self.pos, self.pos + len)
  self.pos += len
  out
}

///|
/// Reads an MLS variable-length integer (RFC 9420 §2.1.2).
/// Rejects `11` prefix (`InvalidVarint`), non-minimal encodings
/// (`NonMinimalVarint`), and truncated inputs (`UnexpectedEof`).
pub fn Reader::read_varint(self : Reader) -> Int32 raise TlsError {
  if self.remaining() < 1 {
    raise UnexpectedEof
  }
  let b0 = self.data[self.pos].to_int()
  let prefix = b0 >> 6
  match prefix {
    0 => {
      self.pos += 1
      b0 & 0x3F
    }
    1 => {
      if self.remaining() < 2 {
        raise UnexpectedEof
      }
      let b1 = self.data[self.pos + 1].to_int()
      let value = ((b0 & 0x3F) << 8) | b1
      if value < 64 {
        raise NonMinimalVarint
      }
      self.pos += 2
      value
    }
    2 => {
      if self.remaining() < 4 {
        raise UnexpectedEof
      }
      let b1 = self.data[self.pos + 1].to_int()
      let b2 = self.data[self.pos + 2].to_int()
      let b3 = self.data[self.pos + 3].to_int()
      let value = ((b0 & 0x3F) << 24) | (b1 << 16) | (b2 << 8) | b3
      if value < 16384 {
        raise NonMinimalVarint
      }
      self.pos += 4
      value
    }
    _ => raise InvalidVarint
  }
}

///|
/// Reads an MLS variable-length opaque byte vector (`opaque data<V>`).
pub fn Reader::read_opaque(self : Reader) -> Bytes raise TlsError {
  let len = self.read_varint()
  self.read_fixed(len)
}

///|
/// Reads an MLS variable-length vector (`T vec<V>`), decoding elements from
/// the varint-length-prefixed payload until all payload bytes are consumed.
pub fn[T] Reader::read_vec(
  self : Reader,
  decode_element : (Reader) -> T raise TlsError,
) -> Array[T] raise TlsError {
  let payload = self.read_opaque()
  let sub = Reader::new(payload)
  let items : Array[T] = []
  while !sub.is_empty() {
    let before = sub.offset()
    items.push(decode_element(sub))
    if sub.offset() == before {
      raise LengthMismatch
    }
  }
  items
}

///|
/// Reads an MLS `optional<T>` value: `0x00` yields `None`, `0x01` decodes and
/// returns `Some(v)`, and any other tag raises `InvalidEnum`.
pub fn[T] Reader::read_optional(
  self : Reader,
  decode_value : (Reader) -> T raise TlsError,
) -> T? raise TlsError {
  let present = self.read_u8()
  match present {
    b'\x00' => None
    b'\x01' => Some(decode_value(self))
    _ => raise InvalidEnum("invalid optional presence byte: \{present}")
  }
}

///|
fn hex_nibble(code : UInt16) -> Int32 raise TlsError {
  let c = code.to_int()
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    raise InvalidEnum("invalid hex character")
  }
}

///|
/// Decodes an even-length hexadecimal string (case-insensitive) into `Bytes`.
pub fn bytes_from_hex(hex : String) -> Bytes raise TlsError {
  let len = hex.length()
  if len % 2 != 0 {
    raise LengthMismatch
  }
  let n = len / 2
  let out : Array[Byte] = Array(capacity=n)
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(hex.code_unit_at(i * 2))
    let lo = hex_nibble(hex.code_unit_at(i * 2 + 1))
    out.push(((hi << 4) | lo).to_byte())
  }
  Bytes::makei(n, fn(i) { out[i] })
}

///|
fn nibble_to_hex_char(n : Int32) -> Char {
  if n < 10 {
    (0x30 + n).unsafe_to_char()
  } else {
    (0x61 + n - 10).unsafe_to_char()
  }
}

///|
/// Encodes `Bytes` into a lowercase hexadecimal string.
pub fn bytes_to_hex(data : Bytes) -> String {
  let sb = StringBuilder(capacity=data.length() * 2)
  for i = 0; i < data.length(); i = i + 1 {
    let b = data[i].to_int()
    sb.write_char(nibble_to_hex_char((b >> 4) & 0x0F))
    sb.write_char(nibble_to_hex_char(b & 0x0F))
  }
  sb.to_string()
}

///|
/// Concatenates an array of `Bytes` into a single `Bytes`.
pub fn bytes_concat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total += parts[i].length()
  }
  let out : Array[Byte] = Array(capacity=total)
  for i = 0; i < parts.length(); i = i + 1 {
    let part = parts[i]
    for j = 0; j < part.length(); j = j + 1 {
      out.push(part[j])
    }
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
/// Returns a copy of the half-open slice `data[start..end)`.
pub fn bytes_slice(
  data : Bytes,
  start : Int32,
  end : Int32,
) -> Bytes raise TlsError {
  if start < 0 || end < start {
    raise LengthMismatch
  }
  if end > data.length() {
    raise UnexpectedEof
  }
  Bytes::makei(end - start, fn(i) { data[start + i] })
}

///|
/// Encodes an integer as an MLS varint byte sequence.
pub fn encode_varint_bytes(value : Int32) -> Bytes raise TlsError {
  let w = Writer::new()
  w.write_varint(value)
  w.to_bytes()
}

///|
/// Encodes a byte slice as a varint-length-prefixed MLS opaque vector.
pub fn encode_opaque(data : Bytes) -> Bytes raise TlsError {
  let w = Writer::new()
  w.write_opaque(data)
  w.to_bytes()
}
