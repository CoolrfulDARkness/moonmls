///|
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn chacha20_quarter_round(
  s : FixedArray[UInt32],
  a : Int32,
  b : Int32,
  c : Int32,
  d : Int32,
) -> Unit {
  s[a] = s[a] + s[b]
  s[d] = rotl32(s[d] ^ s[a], 16)
  s[c] = s[c] + s[d]
  s[b] = rotl32(s[b] ^ s[c], 12)
  s[a] = s[a] + s[b]
  s[d] = rotl32(s[d] ^ s[a], 8)
  s[c] = s[c] + s[d]
  s[b] = rotl32(s[b] ^ s[c], 7)
}

///|
fn chacha20_block(
  key : Bytes,
  counter : UInt32,
  nonce : Bytes,
) -> FixedArray[Byte] {
  let init = FixedArray::make(16, 0U)
  init[0] = 0x61707865U
  init[1] = 0x3320646eU
  init[2] = 0x79622d32U
  init[3] = 0x6b206574U
  for i = 0; i < 8; i = i + 1 {
    init[4 + i] = load_le32(key, i * 4)
  }
  init[12] = counter
  init[13] = load_le32(nonce, 0)
  init[14] = load_le32(nonce, 4)
  init[15] = load_le32(nonce, 8)
  let work = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    work[i] = init[i]
  }
  for _r = 0; _r < 10; _r = _r + 1 {
    chacha20_quarter_round(work, 0, 4, 8, 12)
    chacha20_quarter_round(work, 1, 5, 9, 13)
    chacha20_quarter_round(work, 2, 6, 10, 14)
    chacha20_quarter_round(work, 3, 7, 11, 15)
    chacha20_quarter_round(work, 0, 5, 10, 15)
    chacha20_quarter_round(work, 1, 6, 11, 12)
    chacha20_quarter_round(work, 2, 7, 8, 13)
    chacha20_quarter_round(work, 3, 4, 9, 14)
  }
  let out = FixedArray::make(64, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    store_le32_arr(out, i * 4, work[i] + init[i])
  }
  out
}

///|
fn chacha20_xor_slice(
  key : Bytes,
  initial_counter : UInt32,
  nonce : Bytes,
  input : Bytes,
  len : Int32,
) -> FixedArray[Byte] {
  let out = FixedArray::make(len, b'\x00')
  let mut ctr = initial_counter
  let mut off = 0
  while off < len {
    let ks = chacha20_block(key, ctr, nonce)
    let take = if len - off < 64 { len - off } else { 64 }
    for i = 0; i < take; i = i + 1 {
      out[off + i] = (input[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    ctr = ctr + 1U
    off = off + take
  }
  out
}

///|
priv struct Poly1305State {
  r0 : UInt64
  r1 : UInt64
  r2 : UInt64
  r3 : UInt64
  r4 : UInt64
  s1 : UInt64
  s2 : UInt64
  s3 : UInt64
  s4 : UInt64
  pad0 : UInt64
  pad1 : UInt64
  pad2 : UInt64
  pad3 : UInt64
  mut h0 : UInt64
  mut h1 : UInt64
  mut h2 : UInt64
  mut h3 : UInt64
  mut h4 : UInt64
  buf : FixedArray[Byte]
  mut buf_len : Int32
}

///|
fn load_le32_arr(data : FixedArray[Byte], offset : Int32) -> UInt32 {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn Poly1305State::new(otk : FixedArray[Byte]) -> Poly1305State {
  let rc = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    rc[i] = otk[i]
  }
  rc[3] = (rc[3].to_int() & 15).to_byte()
  rc[7] = (rc[7].to_int() & 15).to_byte()
  rc[11] = (rc[11].to_int() & 15).to_byte()
  rc[15] = (rc[15].to_int() & 15).to_byte()
  rc[4] = (rc[4].to_int() & 252).to_byte()
  rc[8] = (rc[8].to_int() & 252).to_byte()
  rc[12] = (rc[12].to_int() & 252).to_byte()
  let t0 = load_le32_arr(rc, 0).to_uint64()
  let t1 = load_le32_arr(rc, 4).to_uint64()
  let t2 = load_le32_arr(rc, 8).to_uint64()
  let t3 = load_le32_arr(rc, 12).to_uint64()
  let r0 = t0 & 0x03ffffffUL
  let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ffffffUL
  let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ffffffUL
  let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03ffffffUL
  let r4 = (t3 >> 8) & 0x03ffffffUL
  {
    r0,
    r1,
    r2,
    r3,
    r4,
    s1: r1 * 5UL,
    s2: r2 * 5UL,
    s3: r3 * 5UL,
    s4: r4 * 5UL,
    pad0: load_le32_arr(otk, 16).to_uint64(),
    pad1: load_le32_arr(otk, 20).to_uint64(),
    pad2: load_le32_arr(otk, 24).to_uint64(),
    pad3: load_le32_arr(otk, 28).to_uint64(),
    h0: 0UL,
    h1: 0UL,
    h2: 0UL,
    h3: 0UL,
    h4: 0UL,
    buf: FixedArray::make(16, b'\x00'),
    buf_len: 0,
  }
}

///|
fn Poly1305State::process_block(
  self : Poly1305State,
  block : FixedArray[Byte],
  hibit : UInt64,
) -> Unit {
  let t0 = load_le32_arr(block, 0).to_uint64()
  let t1 = load_le32_arr(block, 4).to_uint64()
  let t2 = load_le32_arr(block, 8).to_uint64()
  let t3 = load_le32_arr(block, 12).to_uint64()
  let h0 = self.h0 + (t0 & 0x03ffffffUL)
  let h1 = self.h1 + (((t0 >> 26) | (t1 << 6)) & 0x03ffffffUL)
  let h2 = self.h2 + (((t1 >> 20) | (t2 << 12)) & 0x03ffffffUL)
  let h3 = self.h3 + (((t2 >> 14) | (t3 << 18)) & 0x03ffffffUL)
  let h4 = self.h4 + ((t3 >> 8) & 0x03ffffffUL) + hibit
  let d0 = h0 * self.r0 +
    h1 * self.s4 +
    h2 * self.s3 +
    h3 * self.s2 +
    h4 * self.s1
  let mut d1 = h0 * self.r1 +
    h1 * self.r0 +
    h2 * self.s4 +
    h3 * self.s3 +
    h4 * self.s2
  let mut d2 = h0 * self.r2 +
    h1 * self.r1 +
    h2 * self.r0 +
    h3 * self.s4 +
    h4 * self.s3
  let mut d3 = h0 * self.r3 +
    h1 * self.r2 +
    h2 * self.r1 +
    h3 * self.r0 +
    h4 * self.s4
  let mut d4 = h0 * self.r4 +
    h1 * self.r3 +
    h2 * self.r2 +
    h3 * self.r1 +
    h4 * self.r0
  let mut c = d0 >> 26
  let mut nh0 = d0 & 0x03ffffffUL
  d1 = d1 + c
  c = d1 >> 26
  let mut nh1 = d1 & 0x03ffffffUL
  d2 = d2 + c
  c = d2 >> 26
  let nh2 = d2 & 0x03ffffffUL
  d3 = d3 + c
  c = d3 >> 26
  let nh3 = d3 & 0x03ffffffUL
  d4 = d4 + c
  c = d4 >> 26
  let nh4 = d4 & 0x03ffffffUL
  nh0 = nh0 + c * 5UL
  c = nh0 >> 26
  nh0 = nh0 & 0x03ffffffUL
  nh1 = nh1 + c
  self.h0 = nh0
  self.h1 = nh1
  self.h2 = nh2
  self.h3 = nh3
  self.h4 = nh4
}

///|
fn Poly1305State::update_slice(
  self : Poly1305State,
  data : Bytes,
  start : Int32,
  len : Int32,
) -> Unit {
  let mut i = 0
  while i < len {
    self.buf[self.buf_len] = data[start + i]
    self.buf_len = self.buf_len + 1
    i = i + 1
    if self.buf_len == 16 {
      self.process_block(self.buf, 1UL << 24)
      self.buf_len = 0
    }
  }
}

///|
fn Poly1305State::update_fixed(
  self : Poly1305State,
  data : FixedArray[Byte],
) -> Unit {
  let len = data.length()
  let mut i = 0
  while i < len {
    self.buf[self.buf_len] = data[i]
    self.buf_len = self.buf_len + 1
    i = i + 1
    if self.buf_len == 16 {
      self.process_block(self.buf, 1UL << 24)
      self.buf_len = 0
    }
  }
}

///|
fn Poly1305State::pad16(self : Poly1305State, data_len : Int32) -> Unit {
  let rem = data_len % 16
  if rem != 0 {
    let pad_len = 16 - rem
    for _i = 0; _i < pad_len; _i = _i + 1 {
      self.buf[self.buf_len] = b'\x00'
      self.buf_len = self.buf_len + 1
      if self.buf_len == 16 {
        self.process_block(self.buf, 1UL << 24)
        self.buf_len = 0
      }
    }
  }
}

///|
fn Poly1305State::finalize(self : Poly1305State) -> Bytes {
  if self.buf_len > 0 {
    self.buf[self.buf_len] = b'\x01'
    for i = self.buf_len + 1; i < 16; i = i + 1 {
      self.buf[i] = b'\x00'
    }
    self.process_block(self.buf, 0UL)
    self.buf_len = 0
  }
  let mut h0 = self.h0
  let mut h1 = self.h1
  let mut h2 = self.h2
  let mut h3 = self.h3
  let mut h4 = self.h4
  let mut c = h1 >> 26
  h1 = h1 & 0x03ffffffUL
  h2 = h2 + c
  c = h2 >> 26
  h2 = h2 & 0x03ffffffUL
  h3 = h3 + c
  c = h3 >> 26
  h3 = h3 & 0x03ffffffUL
  h4 = h4 + c
  c = h4 >> 26
  h4 = h4 & 0x03ffffffUL
  h0 = h0 + c * 5UL
  c = h0 >> 26
  h0 = h0 & 0x03ffffffUL
  h1 = h1 + c
  // Compute h + 5 - 2^130
  let mut g0 = h0 + 5UL
  c = g0 >> 26
  g0 = g0 & 0x03ffffffUL
  let mut g1 = h1 + c
  c = g1 >> 26
  g1 = g1 & 0x03ffffffUL
  let mut g2 = h2 + c
  c = g2 >> 26
  g2 = g2 & 0x03ffffffUL
  let mut g3 = h3 + c
  c = g3 >> 26
  g3 = g3 & 0x03ffffffUL
  let g4 = h4 + c - (1UL << 26)
  // Select h if h < 2^130 - 5 (g4 underflowed, top bit is 1), else g
  let mask = 0UL - (g4 >> 63)
  let inv_mask = mask.lnot()
  h0 = (h0 & mask) | (g0 & inv_mask)
  h1 = (h1 & mask) | (g1 & inv_mask)
  h2 = (h2 & mask) | (g2 & inv_mask)
  h3 = (h3 & mask) | (g3 & inv_mask)
  h4 = (h4 & mask) | (g4 & inv_mask)
  let mut f0 = (h0 | (h1 << 26)) & 0xffffffffUL
  let mut f1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffUL
  let mut f2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffUL
  let mut f3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffUL
  f0 = f0 + self.pad0
  let c0 = f0 >> 32
  f1 = f1 + self.pad1 + c0
  let c1 = f1 >> 32
  f2 = f2 + self.pad2 + c1
  let c2 = f2 >> 32
  f3 = f3 + self.pad3 + c2
  let tag = FixedArray::make(16, b'\x00')
  store_le32_arr(tag, 0, (f0 & 0xffffffffUL).to_uint())
  store_le32_arr(tag, 4, (f1 & 0xffffffffUL).to_uint())
  store_le32_arr(tag, 8, (f2 & 0xffffffffUL).to_uint())
  store_le32_arr(tag, 12, (f3 & 0xffffffffUL).to_uint())
  bytes_from_fixed(tag)
}

///|
fn chacha20_poly1305_tag(
  otk : FixedArray[Byte],
  aad : Bytes,
  ct : Bytes,
  ct_len : Int32,
) -> Bytes {
  let poly = Poly1305State::new(otk)
  poly.update_slice(aad, 0, aad.length())
  poly.pad16(aad.length())
  poly.update_slice(ct, 0, ct_len)
  poly.pad16(ct_len)
  let lens = FixedArray::make(16, b'\x00')
  store_le64_arr(lens, 0, aad.length().to_uint64())
  store_le64_arr(lens, 8, ct_len.to_uint64())
  poly.update_fixed(lens)
  poly.finalize()
}

///|
pub fn chacha20_poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CryptoError {
  if key.length() != 32 {
    raise InvalidKeyLength
  }
  if nonce.length() != 12 {
    raise InvalidNonceLength
  }
  let otk = chacha20_block(key, 0U, nonce)
  let pt_len = plaintext.length()
  let ct_arr = chacha20_xor_slice(key, 1U, nonce, plaintext, pt_len)
  let ct_bytes = bytes_from_fixed(ct_arr)
  let tag = chacha20_poly1305_tag(otk, aad, ct_bytes, pt_len)
  let out = FixedArray::make(pt_len + 16, b'\x00')
  for i = 0; i < pt_len; i = i + 1 {
    out[i] = ct_arr[i]
  }
  for i = 0; i < 16; i = i + 1 {
    out[pt_len + i] = tag[i]
  }
  bytes_from_fixed(out)
}

///|
pub fn chacha20_poly1305_open(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_and_tag : Bytes,
) -> Bytes raise CryptoError {
  if key.length() != 32 {
    raise InvalidKeyLength
  }
  if nonce.length() != 12 {
    raise InvalidNonceLength
  }
  let total_len = ciphertext_and_tag.length()
  if total_len < 16 {
    raise AuthFailed
  }
  let ct_len = total_len - 16
  let otk = chacha20_block(key, 0U, nonce)
  let expected_tag = chacha20_poly1305_tag(otk, aad, ciphertext_and_tag, ct_len)
  let provided_tag = Bytes::makei(16, fn(i) { ciphertext_and_tag[ct_len + i] })
  if !ct_equal(expected_tag, provided_tag) {
    raise AuthFailed
  }
  let pt_arr = chacha20_xor_slice(key, 1U, nonce, ciphertext_and_tag, ct_len)
  bytes_from_fixed(pt_arr)
}
