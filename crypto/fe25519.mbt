///|
priv struct Fe {
  h0 : Int64
  h1 : Int64
  h2 : Int64
  h3 : Int64
  h4 : Int64
  h5 : Int64
  h6 : Int64
  h7 : Int64
  h8 : Int64
  h9 : Int64
}

///|
fn fe_zero() -> Fe {
  {
    h0: 0L,
    h1: 0L,
    h2: 0L,
    h3: 0L,
    h4: 0L,
    h5: 0L,
    h6: 0L,
    h7: 0L,
    h8: 0L,
    h9: 0L,
  }
}

///|
fn fe_one() -> Fe {
  {
    h0: 1L,
    h1: 0L,
    h2: 0L,
    h3: 0L,
    h4: 0L,
    h5: 0L,
    h6: 0L,
    h7: 0L,
    h8: 0L,
    h9: 0L,
  }
}

///|
fn fe_from_int(v : Int64) -> Fe {
  {
    h0: v,
    h1: 0L,
    h2: 0L,
    h3: 0L,
    h4: 0L,
    h5: 0L,
    h6: 0L,
    h7: 0L,
    h8: 0L,
    h9: 0L,
  }
}

///|
fn fe_carry(f : Fe) -> Fe {
  let mut h0 = f.h0
  let mut h1 = f.h1
  let mut h2 = f.h2
  let mut h3 = f.h3
  let mut h4 = f.h4
  let mut h5 = f.h5
  let mut h6 = f.h6
  let mut h7 = f.h7
  let mut h8 = f.h8
  let mut h9 = f.h9
  let c0 = (h0 + (1L << 25)) >> 26
  h1 = h1 + c0
  h0 = h0 - (c0 << 26)
  let c1 = (h1 + (1L << 24)) >> 25
  h2 = h2 + c1
  h1 = h1 - (c1 << 25)
  let c2 = (h2 + (1L << 25)) >> 26
  h3 = h3 + c2
  h2 = h2 - (c2 << 26)
  let c3 = (h3 + (1L << 24)) >> 25
  h4 = h4 + c3
  h3 = h3 - (c3 << 25)
  let c4 = (h4 + (1L << 25)) >> 26
  h5 = h5 + c4
  h4 = h4 - (c4 << 26)
  let c5 = (h5 + (1L << 24)) >> 25
  h6 = h6 + c5
  h5 = h5 - (c5 << 25)
  let c6 = (h6 + (1L << 25)) >> 26
  h7 = h7 + c6
  h6 = h6 - (c6 << 26)
  let c7 = (h7 + (1L << 24)) >> 25
  h8 = h8 + c7
  h7 = h7 - (c7 << 25)
  let c8 = (h8 + (1L << 25)) >> 26
  h9 = h9 + c8
  h8 = h8 - (c8 << 26)
  let c9 = (h9 + (1L << 24)) >> 25
  h0 = h0 + c9 * 19L
  h9 = h9 - (c9 << 25)
  let c0b = (h0 + (1L << 25)) >> 26
  h1 = h1 + c0b
  h0 = h0 - (c0b << 26)
  { h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, }
}

///|
fn fe_add(f : Fe, g : Fe) -> Fe {
  {
    h0: f.h0 + g.h0,
    h1: f.h1 + g.h1,
    h2: f.h2 + g.h2,
    h3: f.h3 + g.h3,
    h4: f.h4 + g.h4,
    h5: f.h5 + g.h5,
    h6: f.h6 + g.h6,
    h7: f.h7 + g.h7,
    h8: f.h8 + g.h8,
    h9: f.h9 + g.h9,
  }
}

///|
fn fe_sub(f : Fe, g : Fe) -> Fe {
  {
    h0: f.h0 - g.h0,
    h1: f.h1 - g.h1,
    h2: f.h2 - g.h2,
    h3: f.h3 - g.h3,
    h4: f.h4 - g.h4,
    h5: f.h5 - g.h5,
    h6: f.h6 - g.h6,
    h7: f.h7 - g.h7,
    h8: f.h8 - g.h8,
    h9: f.h9 - g.h9,
  }
}

///|
fn fe_neg(f : Fe) -> Fe {
  {
    h0: -f.h0,
    h1: -f.h1,
    h2: -f.h2,
    h3: -f.h3,
    h4: -f.h4,
    h5: -f.h5,
    h6: -f.h6,
    h7: -f.h7,
    h8: -f.h8,
    h9: -f.h9,
  }
}

///|
fn fe_cswap(f : Fe, g : Fe, b : Int32) -> (Fe, Fe) {
  let mask = 0L - b.to_int64()
  let t0 = mask & (f.h0 ^ g.h0)
  let t1 = mask & (f.h1 ^ g.h1)
  let t2 = mask & (f.h2 ^ g.h2)
  let t3 = mask & (f.h3 ^ g.h3)
  let t4 = mask & (f.h4 ^ g.h4)
  let t5 = mask & (f.h5 ^ g.h5)
  let t6 = mask & (f.h6 ^ g.h6)
  let t7 = mask & (f.h7 ^ g.h7)
  let t8 = mask & (f.h8 ^ g.h8)
  let t9 = mask & (f.h9 ^ g.h9)
  (
    {
      h0: f.h0 ^ t0,
      h1: f.h1 ^ t1,
      h2: f.h2 ^ t2,
      h3: f.h3 ^ t3,
      h4: f.h4 ^ t4,
      h5: f.h5 ^ t5,
      h6: f.h6 ^ t6,
      h7: f.h7 ^ t7,
      h8: f.h8 ^ t8,
      h9: f.h9 ^ t9,
    },
    {
      h0: g.h0 ^ t0,
      h1: g.h1 ^ t1,
      h2: g.h2 ^ t2,
      h3: g.h3 ^ t3,
      h4: g.h4 ^ t4,
      h5: g.h5 ^ t5,
      h6: g.h6 ^ t6,
      h7: g.h7 ^ t7,
      h8: g.h8 ^ t8,
      h9: g.h9 ^ t9,
    },
  )
}

///|
fn fe_mul(f : Fe, g : Fe) -> Fe {
  let f0 = f.h0
  let f1 = f.h1
  let f2 = f.h2
  let f3 = f.h3
  let f4 = f.h4
  let f5 = f.h5
  let f6 = f.h6
  let f7 = f.h7
  let f8 = f.h8
  let f9 = f.h9
  let g0 = g.h0
  let g1 = g.h1
  let g2 = g.h2
  let g3 = g.h3
  let g4 = g.h4
  let g5 = g.h5
  let g6 = g.h6
  let g7 = g.h7
  let g8 = g.h8
  let g9 = g.h9
  let g1_19 = 19L * g1
  let g2_19 = 19L * g2
  let g3_19 = 19L * g3
  let g4_19 = 19L * g4
  let g5_19 = 19L * g5
  let g6_19 = 19L * g6
  let g7_19 = 19L * g7
  let g8_19 = 19L * g8
  let g9_19 = 19L * g9
  let f1_2 = 2L * f1
  let f3_2 = 2L * f3
  let f5_2 = 2L * f5
  let f7_2 = 2L * f7
  let f9_2 = 2L * f9
  let h0 = f0 * g0 +
    f1_2 * g9_19 +
    f2 * g8_19 +
    f3_2 * g7_19 +
    f4 * g6_19 +
    f5_2 * g5_19 +
    f6 * g4_19 +
    f7_2 * g3_19 +
    f8 * g2_19 +
    f9_2 * g1_19
  let h1 = f0 * g1 +
    f1 * g0 +
    f2 * g9_19 +
    f3 * g8_19 +
    f4 * g7_19 +
    f5 * g6_19 +
    f6 * g5_19 +
    f7 * g4_19 +
    f8 * g3_19 +
    f9 * g2_19
  let h2 = f0 * g2 +
    f1_2 * g1 +
    f2 * g0 +
    f3_2 * g9_19 +
    f4 * g8_19 +
    f5_2 * g7_19 +
    f6 * g6_19 +
    f7_2 * g5_19 +
    f8 * g4_19 +
    f9_2 * g3_19
  let h3 = f0 * g3 +
    f1 * g2 +
    f2 * g1 +
    f3 * g0 +
    f4 * g9_19 +
    f5 * g8_19 +
    f6 * g7_19 +
    f7 * g6_19 +
    f8 * g5_19 +
    f9 * g4_19
  let h4 = f0 * g4 +
    f1_2 * g3 +
    f2 * g2 +
    f3_2 * g1 +
    f4 * g0 +
    f5_2 * g9_19 +
    f6 * g8_19 +
    f7_2 * g7_19 +
    f8 * g6_19 +
    f9_2 * g5_19
  let h5 = f0 * g5 +
    f1 * g4 +
    f2 * g3 +
    f3 * g2 +
    f4 * g1 +
    f5 * g0 +
    f6 * g9_19 +
    f7 * g8_19 +
    f8 * g7_19 +
    f9 * g6_19
  let h6 = f0 * g6 +
    f1_2 * g5 +
    f2 * g4 +
    f3_2 * g3 +
    f4 * g2 +
    f5_2 * g1 +
    f6 * g0 +
    f7_2 * g9_19 +
    f8 * g8_19 +
    f9_2 * g7_19
  let h7 = f0 * g7 +
    f1 * g6 +
    f2 * g5 +
    f3 * g4 +
    f4 * g3 +
    f5 * g2 +
    f6 * g1 +
    f7 * g0 +
    f8 * g9_19 +
    f9 * g8_19
  let h8 = f0 * g8 +
    f1_2 * g7 +
    f2 * g6 +
    f3_2 * g5 +
    f4 * g4 +
    f5_2 * g3 +
    f6 * g2 +
    f7_2 * g1 +
    f8 * g0 +
    f9_2 * g9_19
  let h9 = f0 * g9 +
    f1 * g8 +
    f2 * g7 +
    f3 * g6 +
    f4 * g5 +
    f5 * g4 +
    f6 * g3 +
    f7 * g2 +
    f8 * g1 +
    f9 * g0
  fe_carry({ h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, })
}

///|
fn fe_sq(f : Fe) -> Fe {
  fe_mul(f, f)
}

///|
fn fe_mul_121665(f : Fe) -> Fe {
  fe_carry({
    h0: f.h0 * 121665L,
    h1: f.h1 * 121665L,
    h2: f.h2 * 121665L,
    h3: f.h3 * 121665L,
    h4: f.h4 * 121665L,
    h5: f.h5 * 121665L,
    h6: f.h6 * 121665L,
    h7: f.h7 * 121665L,
    h8: f.h8 * 121665L,
    h9: f.h9 * 121665L,
  })
}

///|
fn fe_sq_n(f : Fe, n : Int32) -> Fe {
  let mut r = f
  for _i = 0; _i < n; _i = _i + 1 {
    r = fe_sq(r)
  }
  r
}

///|
fn fe_invert(z : Fe) -> Fe {
  let z2 = fe_sq(z)
  let z9 = fe_mul(fe_sq_n(z2, 2), z)
  let z11 = fe_mul(z9, z2)
  let z_5_0 = fe_mul(fe_sq(z11), z9)
  let z_10_0 = fe_mul(fe_sq_n(z_5_0, 5), z_5_0)
  let z_20_0 = fe_mul(fe_sq_n(z_10_0, 10), z_10_0)
  let z_40_0 = fe_mul(fe_sq_n(z_20_0, 20), z_20_0)
  let z_50_0 = fe_mul(fe_sq_n(z_40_0, 10), z_10_0)
  let z_100_0 = fe_mul(fe_sq_n(z_50_0, 50), z_50_0)
  let z_200_0 = fe_mul(fe_sq_n(z_100_0, 100), z_100_0)
  let z_250_0 = fe_mul(fe_sq_n(z_200_0, 50), z_50_0)
  fe_mul(fe_sq_n(z_250_0, 5), z11)
}

///|
fn fe_pow22523(z : Fe) -> Fe {
  let z2 = fe_sq(z)
  let z9 = fe_mul(fe_sq_n(z2, 2), z)
  let z11 = fe_mul(z9, z2)
  let z_5_0 = fe_mul(fe_sq(z11), z9)
  let z_10_0 = fe_mul(fe_sq_n(z_5_0, 5), z_5_0)
  let z_20_0 = fe_mul(fe_sq_n(z_10_0, 10), z_10_0)
  let z_40_0 = fe_mul(fe_sq_n(z_20_0, 20), z_20_0)
  let z_50_0 = fe_mul(fe_sq_n(z_40_0, 10), z_10_0)
  let z_100_0 = fe_mul(fe_sq_n(z_50_0, 50), z_50_0)
  let z_200_0 = fe_mul(fe_sq_n(z_100_0, 100), z_100_0)
  let z_250_0 = fe_mul(fe_sq_n(z_200_0, 50), z_50_0)
  fe_mul(fe_sq_n(z_250_0, 2), z)
}

///|
fn load3_i64(s : Bytes, off : Int32) -> Int64 {
  s[off].to_int64() |
  (s[off + 1].to_int64() << 8) |
  (s[off + 2].to_int64() << 16)
}

///|
fn load4_i64(s : Bytes, off : Int32) -> Int64 {
  s[off].to_int64() |
  (s[off + 1].to_int64() << 8) |
  (s[off + 2].to_int64() << 16) |
  (s[off + 3].to_int64() << 24)
}

///|
fn fe_frombytes(s : Bytes) -> Fe {
  let h0 = load4_i64(s, 0)
  let h1 = load3_i64(s, 4) << 6
  let h2 = load3_i64(s, 7) << 5
  let h3 = load3_i64(s, 10) << 3
  let h4 = load3_i64(s, 13) << 2
  let h5 = load4_i64(s, 16)
  let h6 = load3_i64(s, 20) << 7
  let h7 = load3_i64(s, 23) << 5
  let h8 = load3_i64(s, 26) << 4
  let h9 = (load3_i64(s, 29) & 0x7fffffL) << 2
  fe_carry({ h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, })
}

///|
fn fe_tobytes(f : Fe) -> Bytes {
  let r = fe_carry(f)
  // Add p = 2^255 - 19 so value is strictly in (0, 2*p)
  let mut h0 = r.h0 - 19L
  let mut h1 = r.h1
  let mut h2 = r.h2
  let mut h3 = r.h3
  let mut h4 = r.h4
  let mut h5 = r.h5
  let mut h6 = r.h6
  let mut h7 = r.h7
  let mut h8 = r.h8
  let mut h9 = r.h9 + (1L << 25)
  // Floor carry pass to non-negative limbs
  let mut c = h0 >> 26
  h0 = h0 - (c << 26)
  h1 = h1 + c
  c = h1 >> 25
  h1 = h1 - (c << 25)
  h2 = h2 + c
  c = h2 >> 26
  h2 = h2 - (c << 26)
  h3 = h3 + c
  c = h3 >> 25
  h3 = h3 - (c << 25)
  h4 = h4 + c
  c = h4 >> 26
  h4 = h4 - (c << 26)
  h5 = h5 + c
  c = h5 >> 25
  h5 = h5 - (c << 25)
  h6 = h6 + c
  c = h6 >> 26
  h6 = h6 - (c << 26)
  h7 = h7 + c
  c = h7 >> 25
  h7 = h7 - (c << 25)
  h8 = h8 + c
  c = h8 >> 26
  h8 = h8 - (c << 26)
  h9 = h9 + c
  // Wrap overflow above 2^255 back into h0 * 19
  c = h9 >> 25
  h9 = h9 - (c << 25)
  h0 = h0 + c * 19L
  c = h0 >> 26
  h0 = h0 - (c << 26)
  h1 = h1 + c
  c = h1 >> 25
  h1 = h1 - (c << 25)
  h2 = h2 + c
  c = h2 >> 26
  h2 = h2 - (c << 26)
  h3 = h3 + c
  c = h3 >> 25
  h3 = h3 - (c << 25)
  h4 = h4 + c
  c = h4 >> 26
  h4 = h4 - (c << 26)
  h5 = h5 + c
  c = h5 >> 25
  h5 = h5 - (c << 25)
  h6 = h6 + c
  c = h6 >> 26
  h6 = h6 - (c << 26)
  h7 = h7 + c
  c = h7 >> 25
  h7 = h7 - (c << 25)
  h8 = h8 + c
  c = h8 >> 26
  h8 = h8 - (c << 26)
  h9 = h9 + c
  // Constant-time conditional subtract p if h >= 2^255 - 19 (i.e. h + 19 >= 2^255)
  let mask26 = (1L << 26) - 1L
  let mask25 = (1L << 25) - 1L
  let mut t0 = h0 + 19L
  let mut tc = t0 >> 26
  t0 = t0 & mask26
  let mut t1 = h1 + tc
  tc = t1 >> 25
  t1 = t1 & mask25
  let mut t2 = h2 + tc
  tc = t2 >> 26
  t2 = t2 & mask26
  let mut t3 = h3 + tc
  tc = t3 >> 25
  t3 = t3 & mask25
  let mut t4 = h4 + tc
  tc = t4 >> 26
  t4 = t4 & mask26
  let mut t5 = h5 + tc
  tc = t5 >> 25
  t5 = t5 & mask25
  let mut t6 = h6 + tc
  tc = t6 >> 26
  t6 = t6 & mask26
  let mut t7 = h7 + tc
  tc = t7 >> 25
  t7 = t7 & mask25
  let mut t8 = h8 + tc
  tc = t8 >> 26
  t8 = t8 & mask26
  let mut t9 = h9 + tc
  let overflow = t9 >> 25
  t9 = t9 & mask25
  let sel = 0L - overflow
  let inv = sel.lnot()
  h0 = (h0 & inv) | (t0 & sel)
  h1 = (h1 & inv) | (t1 & sel)
  h2 = (h2 & inv) | (t2 & sel)
  h3 = (h3 & inv) | (t3 & sel)
  h4 = (h4 & inv) | (t4 & sel)
  h5 = (h5 & inv) | (t5 & sel)
  h6 = (h6 & inv) | (t6 & sel)
  h7 = (h7 & inv) | (t7 & sel)
  h8 = (h8 & inv) | (t8 & sel)
  h9 = (h9 & inv) | (t9 & sel)
  let s = FixedArray::make(32, b'\x00')
  s[0] = (h0 & 0xffL).to_byte()
  s[1] = ((h0 >> 8) & 0xffL).to_byte()
  s[2] = ((h0 >> 16) & 0xffL).to_byte()
  s[3] = (((h0 >> 24) | (h1 << 2)) & 0xffL).to_byte()
  s[4] = ((h1 >> 6) & 0xffL).to_byte()
  s[5] = ((h1 >> 14) & 0xffL).to_byte()
  s[6] = (((h1 >> 22) | (h2 << 3)) & 0xffL).to_byte()
  s[7] = ((h2 >> 5) & 0xffL).to_byte()
  s[8] = ((h2 >> 13) & 0xffL).to_byte()
  s[9] = (((h2 >> 21) | (h3 << 5)) & 0xffL).to_byte()
  s[10] = ((h3 >> 3) & 0xffL).to_byte()
  s[11] = ((h3 >> 11) & 0xffL).to_byte()
  s[12] = (((h3 >> 19) | (h4 << 6)) & 0xffL).to_byte()
  s[13] = ((h4 >> 2) & 0xffL).to_byte()
  s[14] = ((h4 >> 10) & 0xffL).to_byte()
  s[15] = ((h4 >> 18) & 0xffL).to_byte()
  s[16] = (h5 & 0xffL).to_byte()
  s[17] = ((h5 >> 8) & 0xffL).to_byte()
  s[18] = ((h5 >> 16) & 0xffL).to_byte()
  s[19] = (((h5 >> 24) | (h6 << 1)) & 0xffL).to_byte()
  s[20] = ((h6 >> 7) & 0xffL).to_byte()
  s[21] = ((h6 >> 15) & 0xffL).to_byte()
  s[22] = (((h6 >> 23) | (h7 << 3)) & 0xffL).to_byte()
  s[23] = ((h7 >> 5) & 0xffL).to_byte()
  s[24] = ((h7 >> 13) & 0xffL).to_byte()
  s[25] = (((h7 >> 21) | (h8 << 4)) & 0xffL).to_byte()
  s[26] = ((h8 >> 4) & 0xffL).to_byte()
  s[27] = ((h8 >> 12) & 0xffL).to_byte()
  s[28] = (((h8 >> 20) | (h9 << 6)) & 0xffL).to_byte()
  s[29] = ((h9 >> 2) & 0xffL).to_byte()
  s[30] = ((h9 >> 10) & 0xffL).to_byte()
  s[31] = ((h9 >> 18) & 0xffL).to_byte()
  bytes_from_fixed(s)
}

///|
fn fe_isnegative(f : Fe) -> Int32 {
  let s = fe_tobytes(f)
  s[0].to_int() & 1
}

///|
fn fe_iszero(f : Fe) -> Bool {
  let s = fe_tobytes(f)
  let mut acc = 0U
  for i = 0; i < 32; i = i + 1 {
    acc = acc | s[i].to_uint()
  }
  acc == 0U
}

///|
fn fe_equal(a : Fe, b : Fe) -> Bool {
  fe_iszero(fe_sub(a, b))
}
