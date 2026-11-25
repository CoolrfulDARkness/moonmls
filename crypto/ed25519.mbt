///|
priv struct EdPoint {
  x : Fe
  y : Fe
  z : Fe
  t : Fe
}

///|
fn ed_identity() -> EdPoint {
  { x: fe_zero(), y: fe_one(), z: fe_one(), t: fe_zero(), }
}

///|
let ed_d : Fe = fe_mul(fe_from_int(-121665L), fe_invert(fe_from_int(121666L)))

///|
let ed_2d : Fe = fe_add(ed_d, ed_d)

///|
let ed_sqrtm1 : Fe = fe_frombytes(
  b"\xb0\xa0\x0e\x4a\x27\x1b\xee\xc4\x78\xe4\x2f\xad\x06\x18\x43\x2f\xa7\xd7\xfb\x3d\x99\x00\x4d\x2b\x0b\xdf\xc1\x4f\x80\x24\x83\x2b",
)

///|
fn compute_ed_basepoint() -> EdPoint {
  let by_bytes = Bytes::makei(32, fn(i) {
    if i == 0 {
      b'\x58'
    } else {
      b'\x66'
    }
  })
  match ed_frombytes(by_bytes) {
    Some(p) => p
    None => ed_identity()
  }
}

///|
let ed_base : EdPoint = compute_ed_basepoint()

///|
fn ed_basepoint() -> EdPoint {
  ed_base
}

///|
fn ed_add(p : EdPoint, q : EdPoint) -> EdPoint {
  let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x))
  let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x))
  let c = fe_mul(fe_mul(p.t, ed_2d), q.t)
  let d_val = fe_mul(fe_add(p.z, p.z), q.z)
  let e = fe_sub(b, a)
  let f = fe_sub(d_val, c)
  let g = fe_add(d_val, c)
  let h = fe_add(b, a)
  { x: fe_mul(e, f), y: fe_mul(g, h), t: fe_mul(e, h), z: fe_mul(f, g), }
}

///|
fn ed_double(p : EdPoint) -> EdPoint {
  let a = fe_sq(p.x)
  let b = fe_sq(p.y)
  let z2 = fe_sq(p.z)
  let c = fe_add(z2, z2)
  let h = fe_add(a, b)
  let e = fe_sub(h, fe_sq(fe_add(p.x, p.y)))
  let g = fe_sub(a, b)
  let f = fe_add(c, g)
  { x: fe_mul(e, f), y: fe_mul(g, h), t: fe_mul(e, h), z: fe_mul(f, g), }
}

///|
fn ed_cswap(p : EdPoint, q : EdPoint, b : Int32) -> (EdPoint, EdPoint) {
  let sx = fe_cswap(p.x, q.x, b)
  let sy = fe_cswap(p.y, q.y, b)
  let sz = fe_cswap(p.z, q.z, b)
  let st = fe_cswap(p.t, q.t, b)
  (
    { x: sx.0, y: sy.0, z: sz.0, t: st.0, },
    { x: sx.1, y: sy.1, z: sz.1, t: st.1, },
  )
}

///|
fn ed_scalar_mul(scalar : Bytes, point : EdPoint) -> EdPoint {
  // Constant-time Montgomery-style ladder on twisted Edwards curve
  let mut r0 = ed_identity()
  let mut r1 = point
  for i = 255; i >= 0; i = i - 1 {
    let bit = (scalar[i >> 3].to_int() >> (i & 7)) & 1
    let sw1 = ed_cswap(r0, r1, bit)
    r0 = sw1.0
    r1 = sw1.1
    let sum = ed_add(r0, r1)
    let dbl = ed_double(r0)
    r0 = dbl
    r1 = sum
    let sw2 = ed_cswap(r0, r1, bit)
    r0 = sw2.0
    r1 = sw2.1
  }
  r0
}

///|
fn ed_tobytes(p : EdPoint) -> Bytes {
  let recip = fe_invert(p.z)
  let x = fe_mul(p.x, recip)
  let y = fe_mul(p.y, recip)
  let y_bytes = fe_tobytes(y)
  let sign = fe_isnegative(x)
  Bytes::makei(32, fn(i) {
    if i == 31 {
      (y_bytes[31].to_int() | (sign << 7)).to_byte()
    } else {
      y_bytes[i]
    }
  })
}

///|
fn is_canonical_y(s : Bytes) -> Bool {
  // Check y (with bit 255 cleared) < 2^255 - 19
  // 2^255 - 19 has bytes: [0xed, 0xff, ..., 0xff, 0x7f]
  let top = s[31].to_int() & 0x7f
  if top < 0x7f {
    return true
  }
  for i = 30; i >= 1; i = i - 1 {
    if s[i].to_int() < 0xff {
      return true
    }
  }
  s[0].to_int() < 0xed
}

///|
fn ed_frombytes(s : Bytes) -> EdPoint? {
  if s.length() != 32 {
    return None
  }
  if !is_canonical_y(s) {
    return None
  }
  let sign = (s[31].to_int() >> 7) & 1
  let y = fe_frombytes(s)
  let y2 = fe_sq(y)
  let u = fe_sub(y2, fe_one())
  let v = fe_add(fe_mul(ed_d, y2), fe_one())
  let v2 = fe_sq(v)
  let v3 = fe_mul(v2, v)
  let v7 = fe_mul(fe_sq(v3), v)
  let uv7 = fe_mul(u, v7)
  let mut x = fe_mul(fe_mul(u, v3), fe_pow22523(uv7))
  let vx2 = fe_mul(v, fe_sq(x))
  if !fe_equal(vx2, u) {
    if fe_equal(vx2, fe_neg(u)) {
      x = fe_mul(x, ed_sqrtm1)
    } else {
      return None
    }
  }
  // Verify v * x^2 == u after adjustment
  if !fe_equal(fe_mul(v, fe_sq(x)), u) {
    return None
  }
  if fe_iszero(x) && sign == 1 {
    return None
  }
  if fe_isnegative(x) != sign {
    x = fe_neg(x)
  }
  Some({ x, y, z: fe_one(), t: fe_mul(x, y), })
}

///|
fn ed_point_equal(p : EdPoint, q : EdPoint) -> Bool {
  fe_equal(fe_mul(p.x, q.z), fe_mul(q.x, p.z)) &&
  fe_equal(fe_mul(p.y, q.z), fe_mul(q.y, p.z))
}

// Scalar arithmetic modulo L = 2^252 + 27742317777372353535851937790883648493

///|
let sc_l0 : UInt64 = 0x5812631a5cf5d3edUL

///|
let sc_l1 : UInt64 = 0x14def9dea2f79cd6UL

///|
let sc_l2 : UInt64 = 0x0000000000000000UL

///|
let sc_l3 : UInt64 = 0x1000000000000000UL

///|
fn sc_is_canonical(s : Bytes) -> Bool {
  if s.length() != 32 {
    return false
  }
  let s3 = load_le64(s, 24)
  if s3 != sc_l3 {
    return s3 < sc_l3
  }
  let s2 = load_le64(s, 16)
  if s2 != sc_l2 {
    return s2 < sc_l2
  }
  let s1 = load_le64(s, 8)
  if s1 != sc_l1 {
    return s1 < sc_l1
  }
  let s0 = load_le64(s, 0)
  s0 < sc_l0
}

///|
fn u64_sub_borrow(x : UInt64, y : UInt64) -> (UInt64, UInt64) {
  let d = x - y
  let b = ((x.lnot() & y) | ((x.lnot() | y) & d)) >> 63
  (d, b)
}

///|
fn sc_sub_l_if_ge(
  r0 : UInt64,
  r1 : UInt64,
  r2 : UInt64,
  r3 : UInt64,
) -> (UInt64, UInt64, UInt64, UInt64) {
  let (d0, b0) = u64_sub_borrow(r0, sc_l0)
  let (d1_tmp, b1a) = u64_sub_borrow(r1, sc_l1)
  let (d1, b1b) = u64_sub_borrow(d1_tmp, b0)
  let b1 = b1a | b1b
  let (d2, b2) = u64_sub_borrow(r2, b1)
  let (d3_tmp, b3a) = u64_sub_borrow(r3, sc_l3)
  let (d3, b3b) = u64_sub_borrow(d3_tmp, b2)
  let borrow = b3a | b3b
  // If borrow == 1 then r < L, keep r; else keep d
  let mask = 0UL - borrow
  let inv = mask.lnot()
  (
    (r0 & mask) | (d0 & inv),
    (r1 & mask) | (d1 & inv),
    (r2 & mask) | (d2 & inv),
    (r3 & mask) | (d3 & inv),
  )
}

///|
fn sc_reduce_bytes(input : Bytes) -> Bytes {
  // Constant-time MSB-first shift-and-subtract reduction mod L (works for any length, e.g. 64B)
  let mut r0 = 0UL
  let mut r1 = 0UL
  let mut r2 = 0UL
  let mut r3 = 0UL
  for byte_idx = input.length() - 1; byte_idx >= 0; byte_idx = byte_idx - 1 {
    let b = input[byte_idx].to_uint64()
    for bit_idx = 7; bit_idx >= 0; bit_idx = bit_idx - 1 {
      let bit = (b >> bit_idx) & 1UL
      r3 = (r3 << 1) | (r2 >> 63)
      r2 = (r2 << 1) | (r1 >> 63)
      r1 = (r1 << 1) | (r0 >> 63)
      r0 = (r0 << 1) | bit
      let red = sc_sub_l_if_ge(r0, r1, r2, r3)
      r0 = red.0
      r1 = red.1
      r2 = red.2
      r3 = red.3
    }
  }
  let out = FixedArray::make(32, b'\x00')
  store_le64_arr(out, 0, r0)
  store_le64_arr(out, 8, r1)
  store_le64_arr(out, 16, r2)
  store_le64_arr(out, 24, r3)
  bytes_from_fixed(out)
}

///|
fn sc_muladd(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  // Compute (a * b + c) mod L where a, b, c are 32-byte little-endian scalars
  let a_w = FixedArray::make(8, 0UL)
  let b_w = FixedArray::make(8, 0UL)
  let c_w = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    a_w[i] = load_le32(a, i * 4).to_uint64()
    b_w[i] = load_le32(b, i * 4).to_uint64()
    c_w[i] = load_le32(c, i * 4).to_uint64()
  }
  let prod = FixedArray::make(17, 0UL)
  for i = 0; i < 8; i = i + 1 {
    prod[i] = c_w[i]
  }
  for i = 0; i < 8; i = i + 1 {
    let mut carry = 0UL
    for j = 0; j < 8; j = j + 1 {
      let sum = prod[i + j] + a_w[i] * b_w[j] + carry
      prod[i + j] = sum & 0xffffffffUL
      carry = sum >> 32
    }
    for k = i + 8; k < 17; k = k + 1 {
      let sum = prod[k] + carry
      prod[k] = sum & 0xffffffffUL
      carry = sum >> 32
    }
  }
  let buf = FixedArray::make(68, b'\x00')
  for i = 0; i < 17; i = i + 1 {
    store_le32_arr(buf, i * 4, prod[i].to_uint())
  }
  sc_reduce_bytes(bytes_from_fixed(buf))
}

///|
fn ed_clamp_scalar(hash_prefix : Bytes) -> Bytes {
  let s = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    s[i] = hash_prefix[i]
  }
  s[0] = (s[0].to_int() & 248).to_byte()
  s[31] = ((s[31].to_int() & 127) | 64).to_byte()
  bytes_from_fixed(s)
}

///|
pub fn ed25519_public_key(seed : Bytes) -> Bytes raise CryptoError {
  if seed.length() != 32 {
    raise InvalidKeyLength
  }
  let h = sha512(seed)
  let a = ed_clamp_scalar(h)
  let pub_pt = ed_scalar_mul(a, ed_basepoint())
  ed_tobytes(pub_pt)
}

///|
pub fn ed25519_sign(seed : Bytes, message : Bytes) -> Bytes raise CryptoError {
  if seed.length() != 32 {
    raise InvalidKeyLength
  }
  let h = sha512(seed)
  let a = ed_clamp_scalar(h)
  let base = ed_basepoint()
  let pub_bytes = ed_tobytes(ed_scalar_mul(a, base))
  // r = SHA-512(h[32..64] || message) mod L
  let r_hasher = Sha512State::new()
  r_hasher.update_slice(h, 32, 32)
  r_hasher.update(message)
  let r = sc_reduce_bytes(r_hasher.finalize())
  let r_bytes = ed_tobytes(ed_scalar_mul(r, base))
  // k = SHA-512(R || A || message) mod L
  let k_hasher = Sha512State::new()
  k_hasher.update(r_bytes)
  k_hasher.update(pub_bytes)
  k_hasher.update(message)
  let k = sc_reduce_bytes(k_hasher.finalize())
  // S = (r + k * a) mod L
  let s = sc_muladd(k, a, r)
  let sig = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    sig[i] = r_bytes[i]
    sig[32 + i] = s[i]
  }
  bytes_from_fixed(sig)
}

///|
pub fn ed25519_verify(
  public_key : Bytes,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  if public_key.length() != 32 || signature.length() != 64 {
    return false
  }
  let r_bytes = Bytes::makei(32, fn(i) { signature[i] })
  let s_bytes = Bytes::makei(32, fn(i) { signature[32 + i] })
  // Reject non-canonical S >= L to prevent signature malleability
  if !sc_is_canonical(s_bytes) {
    return false
  }
  let a_pt = match ed_frombytes(public_key) {
    Some(p) => p
    None => return false
  }
  let a8 = ed_double(ed_double(ed_double(a_pt)))
  if ed_point_equal(a8, ed_identity()) {
    return false
  }
  let r_pt = match ed_frombytes(r_bytes) {
    Some(p) => p
    None => return false
  }
  let k_hasher = Sha512State::new()
  k_hasher.update(r_bytes)
  k_hasher.update(public_key)
  k_hasher.update(message)
  let k = sc_reduce_bytes(k_hasher.finalize())
  let lhs = ed_scalar_mul(s_bytes, ed_basepoint())
  let rhs = ed_add(r_pt, ed_scalar_mul(k, a_pt))
  ed_point_equal(lhs, rhs)
}

///|
pub fn ed25519_verify_or_raise(
  public_key : Bytes,
  message : Bytes,
  signature : Bytes,
) -> Unit raise CryptoError {
  if !ed25519_verify(public_key, message, signature) {
    raise InvalidSignature
  }
}
