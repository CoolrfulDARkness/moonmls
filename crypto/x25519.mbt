///|
pub fn x25519(scalar : Bytes, u_coord : Bytes) -> Bytes raise CryptoError {
  if scalar.length() != 32 {
    raise InvalidKeyLength
  }
  if u_coord.length() != 32 {
    raise InvalidPoint
  }
  let e = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    e[i] = scalar[i]
  }
  e[0] = (e[0].to_int() & 248).to_byte()
  e[31] = ((e[31].to_int() & 127) | 64).to_byte()
  // Clear bit 255 of u_coord per RFC 7748 section 5
  let u_masked = Bytes::makei(32, fn(i) {
    if i == 31 {
      (u_coord[31].to_int() & 127).to_byte()
    } else {
      u_coord[i]
    }
  })
  let x1 = fe_frombytes(u_masked)
  let mut x2 = fe_one()
  let mut z2 = fe_zero()
  let mut x3 = x1
  let mut z3 = fe_one()
  let mut swap = 0
  for t = 254; t >= 0; t = t - 1 {
    let kt = (e[t >> 3].to_int() >> (t & 7)) & 1
    let sw = swap ^ kt
    let sx = fe_cswap(x2, x3, sw)
    x2 = sx.0
    x3 = sx.1
    let sz = fe_cswap(z2, z3, sw)
    z2 = sz.0
    z3 = sz.1
    swap = kt
    let a = fe_add(x2, z2)
    let aa = fe_sq(a)
    let b = fe_sub(x2, z2)
    let bb = fe_sq(b)
    let e_diff = fe_sub(aa, bb)
    let c = fe_add(x3, z3)
    let d = fe_sub(x3, z3)
    let da = fe_mul(d, a)
    let cb = fe_mul(c, b)
    x3 = fe_sq(fe_add(da, cb))
    z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)))
    x2 = fe_mul(aa, bb)
    z2 = fe_mul(e_diff, fe_add(aa, fe_mul_121665(e_diff)))
  }
  let sx = fe_cswap(x2, x3, swap)
  x2 = sx.0
  let sz = fe_cswap(z2, z3, swap)
  z2 = sz.0
  fe_tobytes(fe_mul(x2, fe_invert(z2)))
}

///|
pub fn x25519_dh(scalar : Bytes, u_coord : Bytes) -> Bytes raise CryptoError {
  let shared = x25519(scalar, u_coord)
  let mut acc = 0U
  for i = 0; i < 32; i = i + 1 {
    acc = acc | shared[i].to_uint()
  }
  if acc == 0U {
    raise LowOrderPoint
  }
  shared
}

///|
pub fn x25519_public_key(private_key : Bytes) -> Bytes raise CryptoError {
  let basepoint = Bytes::makei(32, fn(i) { if i == 0 { b'\x09' } else { b'\x00' } })
  x25519(private_key, basepoint)
}
