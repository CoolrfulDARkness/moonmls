///|
fn[T] assert_tls_err(
  expected : @tls.TlsError,
  f : () -> T raise @tls.TlsError,
) -> Unit raise {
  try f() catch {
    e => assert_eq(e, expected)
  } noraise {
    _ => fail("expected TlsError \{expected}, but succeeded")
  }
}

///|
fn[T] assert_invalid_enum(f : () -> T raise @tls.TlsError) -> Unit raise {
  try f() catch {
    @tls.TlsError::InvalidEnum(_) => ()
    other => fail("expected InvalidEnum, got \{other}")
  } noraise {
    _ => fail("expected InvalidEnum, but succeeded")
  }
}

///|
test "primitives u8 u16 u32 u64 raw roundtrip" {
  let w = @tls.Writer::new()
  assert_eq(w.len(), 0)
  w.write_u8(b'\xAB')
  w.write_u16(0x1234U)
  w.write_u32(0xDEADBEEFU)
  w.write_u64(0x0102030405060708UL)
  w.write_raw(b"\xCA\xFE\xBA\xBE")
  assert_eq(w.len(), 1 + 2 + 4 + 8 + 4)
  let bytes = w.to_bytes()
  assert_eq(@tls.bytes_to_hex(bytes), "ab1234deadbeef0102030405060708cafebabe")
  let r = @tls.Reader::new(bytes)
  assert_eq(r.offset(), 0)
  assert_eq(r.remaining(), 19)
  assert_eq(r.is_empty(), false)
  assert_eq(r.read_u8(), b'\xAB')
  assert_eq(r.read_u16(), 0x1234U)
  assert_eq(r.read_u32(), 0xDEADBEEFU)
  assert_eq(r.read_u64(), 0x0102030405060708UL)
  assert_eq(r.read_fixed(4), b"\xCA\xFE\xBA\xBE")
  assert_eq(r.offset(), 19)
  assert_eq(r.remaining(), 0)
  assert_eq(r.is_empty(), true)
  r.ensure_empty()
}

///|
test "u64 high-bit and max boundary roundtrip" {
  let w = @tls.Writer::new()
  w.write_u16(0xFFFFU)
  w.write_u32(0xFFFFFFFFU)
  w.write_u64(0xFFFFFFFFFFFFFFFFUL)
  w.write_u64(0x8000000000000000UL)
  w.write_u64(0UL)
  let r = @tls.Reader::new(w.to_bytes())
  assert_eq(r.read_u16(), 0xFFFFU)
  assert_eq(r.read_u32(), 0xFFFFFFFFU)
  assert_eq(r.read_u64(), 0xFFFFFFFFFFFFFFFFUL)
  assert_eq(r.read_u64(), 0x8000000000000000UL)
  assert_eq(r.read_u64(), 0UL)
  r.ensure_empty()
}

///|
test "varint boundary values RFC 9420 2.1.2" {
  let cases : Array[(Int32, String)] = [
    (0, "00"),
    (1, "01"),
    (63, "3f"),
    (64, "4040"),
    (65, "4041"),
    (16383, "7fff"),
    (16384, "80004000"),
    (16385, "80004001"),
    (1073741823, "bfffffff"),
  ]
  for i = 0; i < cases.length(); i = i + 1 {
    let (val, expected_hex) = cases[i]
    let encoded = @tls.encode_varint_bytes(val)
    assert_eq(@tls.bytes_to_hex(encoded), expected_hex)
    let r = @tls.Reader::new(encoded)
    let decoded = r.read_varint()
    assert_eq(decoded, val)
    r.ensure_empty()
  }
}

///|
test "varint write overflow rejected" {
  assert_tls_err(@tls.TlsError::VarintOverflow, () => {
    @tls.encode_varint_bytes(-1)
  })
  assert_tls_err(@tls.TlsError::VarintOverflow, () => {
    @tls.encode_varint_bytes(0x40000000)
  })
  let w = @tls.Writer::new()
  assert_tls_err(@tls.TlsError::VarintOverflow, () => w.write_varint(1073741824))
  assert_eq(w.len(), 0)
}

///|
test "varint non-minimal encoding rejected" {
  let non_minimal : Array[String] = [
    "4000", "4001", "403f", "80000000", "8000003f", "80000040", "80003fff",
  ]
  for i = 0; i < non_minimal.length(); i = i + 1 {
    let raw = @tls.bytes_from_hex(non_minimal[i])
    let r = @tls.Reader::new(raw)
    assert_tls_err(@tls.TlsError::NonMinimalVarint, () => r.read_varint())
    assert_eq(r.offset(), 0)
  }
}

///|
test "varint 11 prefix (0xC0..0xFF) rejected as InvalidVarint" {
  let invalid_prefixes : Array[String] = [
    "c0", "c000000000000000", "ff", "ffffffffffffffff", "d51234",
  ]
  for i = 0; i < invalid_prefixes.length(); i = i + 1 {
    let raw = @tls.bytes_from_hex(invalid_prefixes[i])
    let r = @tls.Reader::new(raw)
    assert_tls_err(@tls.TlsError::InvalidVarint, () => r.read_varint())
    assert_eq(r.offset(), 0)
  }
}

///|
test "truncated inputs rejected as UnexpectedEof" {
  let empty = @tls.Reader::new(b"")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_u8())
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_u16())
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_u32())
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_u64())
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_varint())
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => empty.read_opaque())
  let r1 = @tls.Reader::new(b"\x01")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => r1.read_u16())
  let r3 = @tls.Reader::new(b"\x01\x02\x03")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => r3.read_u32())
  let r7 = @tls.Reader::new(b"\x01\x02\x03\x04\x05\x06\x07")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => r7.read_u64())
  let rv2 = @tls.Reader::new(b"\x40")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => rv2.read_varint())
  let rv4 = @tls.Reader::new(b"\x80\x00\x40")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => rv4.read_varint())
  let rop = @tls.Reader::new(b"\x05\x01\x02\x03")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => rop.read_opaque())
  let rneg = @tls.Reader::new(b"\x01\x02")
  assert_tls_err(@tls.TlsError::LengthMismatch, () => rneg.read_fixed(-1))
  assert_tls_err(@tls.TlsError::LimitExceeded, () => rneg.read_fixed(0x40000000))
  assert_eq(Show::to_string(@tls.TlsError::LimitExceeded), "LimitExceeded")
  assert_eq(
    Show::to_string(@tls.TlsError::InvalidEnum("bad")),
    "InvalidEnum(bad)",
  )
}

///|
test "trailing data rejected by ensure_empty" {
  let r = @tls.Reader::new(b"\x01\x02")
  assert_eq(r.read_u8(), b'\x01')
  assert_eq(r.remaining(), 1)
  assert_eq(r.is_empty(), false)
  assert_tls_err(@tls.TlsError::TrailingData, () => r.ensure_empty())
  assert_eq(r.read_u8(), b'\x02')
  r.ensure_empty()
}

///|
test "opaque encode and decode roundtrip" {
  let empty_enc = @tls.encode_opaque(b"")
  assert_eq(empty_enc, b"\x00")
  let r0 = @tls.Reader::new(empty_enc)
  assert_eq(r0.read_opaque(), b"")
  r0.ensure_empty()
  let payload = Bytes::make(70, b'\x5A')
  let enc = @tls.encode_opaque(payload)
  assert_eq(enc.length(), 72)
  assert_eq(enc[0], b'\x40')
  assert_eq(enc[1], b'\x46')
  let r = @tls.Reader::new(enc)
  assert_eq(r.read_opaque(), payload)
  r.ensure_empty()
}

///|
test "write_vec and read_vec roundtrip and error cases" {
  let nums : Array[UInt32] = [0x0001U, 0x0203U, 0xFFFFU]
  let w = @tls.Writer::new()
  w.write_vec(sub => {
    for i = 0; i < nums.length(); i = i + 1 {
      sub.write_u16(nums[i])
    }
  })
  let encoded = w.to_bytes()
  assert_eq(@tls.bytes_to_hex(encoded), "0600010203ffff")
  let r = @tls.Reader::new(encoded)
  let decoded = r.read_vec(sub => sub.read_u16())
  assert_eq(decoded, nums)
  r.ensure_empty()
  let w_empty = @tls.Writer::new()
  w_empty.write_vec(_sub => ())
  assert_eq(w_empty.to_bytes(), b"\x00")
  let r_empty = @tls.Reader::new(w_empty.to_bytes())
  let dec_empty = r_empty.read_vec(sub => sub.read_u8())
  assert_eq(dec_empty, [])
  r_empty.ensure_empty()
  let r_bad = @tls.Reader::new(b"\x05\x00\x01\x00\x02\x99")
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => {
    r_bad.read_vec(sub => sub.read_u16())
  })
  let r_nop = @tls.Reader::new(b"\x01\xAA")
  assert_tls_err(@tls.TlsError::LengthMismatch, () => r_nop.read_vec(_sub => 0))
}

///|
test "write_optional and read_optional roundtrip and invalid tag" {
  let w = @tls.Writer::new()
  let none_val : UInt32? = None
  let some_val : UInt32? = Some(0x12345678U)
  w.write_optional(none_val, (wr, v) => wr.write_u32(v))
  w.write_optional(some_val, (wr, v) => wr.write_u32(v))
  assert_eq(@tls.bytes_to_hex(w.to_bytes()), "000112345678")
  let r = @tls.Reader::new(w.to_bytes())
  assert_eq(r.read_optional(rd => rd.read_u32()), None)
  assert_eq(r.read_optional(rd => rd.read_u32()), Some(0x12345678U))
  r.ensure_empty()
  let r_bad = @tls.Reader::new(b"\x02\x00")
  assert_invalid_enum(() => r_bad.read_optional(rd => rd.read_u8()))
}

///|
test "hex concat slice utilities" {
  assert_eq(@tls.bytes_from_hex(""), b"")
  assert_eq(@tls.bytes_to_hex(b""), "")
  let b = @tls.bytes_from_hex("00aBcDeF99")
  assert_eq(@tls.bytes_to_hex(b), "00abcdef99")
  assert_tls_err(@tls.TlsError::LengthMismatch, () => @tls.bytes_from_hex("abc"))
  assert_invalid_enum(() => @tls.bytes_from_hex("00zz"))
  let joined = @tls.bytes_concat([b"\x01\x02", b"", b"\x03", b"\x04\x05"])
  assert_eq(joined, b"\x01\x02\x03\x04\x05")
  assert_eq(@tls.bytes_concat([]), b"")
  assert_eq(@tls.bytes_slice(joined, 0, 5), joined)
  assert_eq(@tls.bytes_slice(joined, 1, 4), b"\x02\x03\x04")
  assert_eq(@tls.bytes_slice(joined, 3, 3), b"")
  assert_tls_err(@tls.TlsError::LengthMismatch, () => {
    @tls.bytes_slice(joined, -1, 2)
  })
  assert_tls_err(@tls.TlsError::LengthMismatch, () => {
    @tls.bytes_slice(joined, 4, 2)
  })
  assert_tls_err(@tls.TlsError::UnexpectedEof, () => {
    @tls.bytes_slice(joined, 0, 6)
  })
}
