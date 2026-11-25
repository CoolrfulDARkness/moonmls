///|
let aes_sbox : FixedArray[Byte] = [
  b'\x63', b'\x7c', b'\x77', b'\x7b', b'\xf2', b'\x6b', b'\x6f', b'\xc5', b'\x30',
  b'\x01', b'\x67', b'\x2b', b'\xfe', b'\xd7', b'\xab', b'\x76', b'\xca', b'\x82',
  b'\xc9', b'\x7d', b'\xfa', b'\x59', b'\x47', b'\xf0', b'\xad', b'\xd4', b'\xa2',
  b'\xaf', b'\x9c', b'\xa4', b'\x72', b'\xc0', b'\xb7', b'\xfd', b'\x93', b'\x26',
  b'\x36', b'\x3f', b'\xf7', b'\xcc', b'\x34', b'\xa5', b'\xe5', b'\xf1', b'\x71',
  b'\xd8', b'\x31', b'\x15', b'\x04', b'\xc7', b'\x23', b'\xc3', b'\x18', b'\x96',
  b'\x05', b'\x9a', b'\x07', b'\x12', b'\x80', b'\xe2', b'\xeb', b'\x27', b'\xb2',
  b'\x75', b'\x09', b'\x83', b'\x2c', b'\x1a', b'\x1b', b'\x6e', b'\x5a', b'\xa0',
  b'\x52', b'\x3b', b'\xd6', b'\xb3', b'\x29', b'\xe3', b'\x2f', b'\x84', b'\x53',
  b'\xd1', b'\x00', b'\xed', b'\x20', b'\xfc', b'\xb1', b'\x5b', b'\x6a', b'\xcb',
  b'\xbe', b'\x39', b'\x4a', b'\x4c', b'\x58', b'\xcf', b'\xd0', b'\xef', b'\xaa',
  b'\xfb', b'\x43', b'\x4d', b'\x33', b'\x85', b'\x45', b'\xf9', b'\x02', b'\x7f',
  b'\x50', b'\x3c', b'\x9f', b'\xa8', b'\x51', b'\xa3', b'\x40', b'\x8f', b'\x92',
  b'\x9d', b'\x38', b'\xf5', b'\xbc', b'\xb6', b'\xda', b'\x21', b'\x10', b'\xff',
  b'\xf3', b'\xd2', b'\xcd', b'\x0c', b'\x13', b'\xec', b'\x5f', b'\x97', b'\x44',
  b'\x17', b'\xc4', b'\xa7', b'\x7e', b'\x3d', b'\x64', b'\x5d', b'\x19', b'\x73',
  b'\x60', b'\x81', b'\x4f', b'\xdc', b'\x22', b'\x2a', b'\x90', b'\x88', b'\x46',
  b'\xee', b'\xb8', b'\x14', b'\xde', b'\x5e', b'\x0b', b'\xdb', b'\xe0', b'\x32',
  b'\x3a', b'\x0a', b'\x49', b'\x06', b'\x24', b'\x5c', b'\xc2', b'\xd3', b'\xac',
  b'\x62', b'\x91', b'\x95', b'\xe4', b'\x79', b'\xe7', b'\xc8', b'\x37', b'\x6d',
  b'\x8d', b'\xd5', b'\x4e', b'\xa9', b'\x6c', b'\x56', b'\xf4', b'\xea', b'\x65',
  b'\x7a', b'\xae', b'\x08', b'\xba', b'\x78', b'\x25', b'\x2e', b'\x1c', b'\xa6',
  b'\xb4', b'\xc6', b'\xe8', b'\xdd', b'\x74', b'\x1f', b'\x4b', b'\xbd', b'\x8b',
  b'\x8a', b'\x70', b'\x3e', b'\xb5', b'\x66', b'\x48', b'\x03', b'\xf6', b'\x0e',
  b'\x61', b'\x35', b'\x57', b'\xb9', b'\x86', b'\xc1', b'\x1d', b'\x9e', b'\xe1',
  b'\xf8', b'\x98', b'\x11', b'\x69', b'\xd9', b'\x8e', b'\x94', b'\x9b', b'\x1e',
  b'\x87', b'\xe9', b'\xce', b'\x55', b'\x28', b'\xdf', b'\x8c', b'\xa1', b'\x89',
  b'\x0d', b'\xbf', b'\xe6', b'\x42', b'\x68', b'\x41', b'\x99', b'\x2d', b'\x0f',
  b'\xb0', b'\x54', b'\xbb', b'\x16',
]

///|
let aes_rcon : FixedArray[UInt32] = [
  0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U, 0x1bU, 0x36U,
]

///|
fn aes_sub_word(w : UInt32) -> UInt32 {
  let b0 = aes_sbox[((w >> 24) & 0xFFU).reinterpret_as_int()].to_uint()
  let b1 = aes_sbox[((w >> 16) & 0xFFU).reinterpret_as_int()].to_uint()
  let b2 = aes_sbox[((w >> 8) & 0xFFU).reinterpret_as_int()].to_uint()
  let b3 = aes_sbox[(w & 0xFFU).reinterpret_as_int()].to_uint()
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
fn aes_rot_word(w : UInt32) -> UInt32 {
  (w << 8) | (w >> 24)
}

///|
fn aes128_expand_key(key : Bytes) -> FixedArray[UInt32] {
  let w = FixedArray::make(44, 0U)
  for i = 0; i < 4; i = i + 1 {
    w[i] = load_be32(key, i * 4)
  }
  for i = 4; i < 44; i = i + 1 {
    let mut temp = w[i - 1]
    if i % 4 == 0 {
      temp = aes_sub_word(aes_rot_word(temp)) ^ (aes_rcon[i / 4 - 1] << 24)
    }
    w[i] = w[i - 4] ^ temp
  }
  w
}

///|
fn aes_xtime(a : Int32) -> Int32 {
  let shifted = a << 1
  if (a & 0x80) != 0 {
    (shifted ^ 0x1b) & 0xff
  } else {
    shifted & 0xff
  }
}

///|
fn aes_add_round_key(
  s : FixedArray[Byte],
  rk : FixedArray[UInt32],
  round : Int32,
) -> Unit {
  let base = round * 4
  for c = 0; c < 4; c = c + 1 {
    let w = rk[base + c]
    let off = c * 4
    s[off] = (s[off].to_uint() ^ ((w >> 24) & 0xFFU)).to_byte()
    s[off + 1] = (s[off + 1].to_uint() ^ ((w >> 16) & 0xFFU)).to_byte()
    s[off + 2] = (s[off + 2].to_uint() ^ ((w >> 8) & 0xFFU)).to_byte()
    s[off + 3] = (s[off + 3].to_uint() ^ (w & 0xFFU)).to_byte()
  }
}

///|
fn aes_sub_bytes(s : FixedArray[Byte]) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    s[i] = aes_sbox[s[i].to_int()]
  }
}

///|
fn aes_shift_rows(s : FixedArray[Byte]) -> Unit {
  // Row 1: shift left 1
  let t1 = s[1]
  s[1] = s[5]
  s[5] = s[9]
  s[9] = s[13]
  s[13] = t1
  // Row 2: shift left 2
  let t2a = s[2]
  let t2b = s[6]
  s[2] = s[10]
  s[6] = s[14]
  s[10] = t2a
  s[14] = t2b
  // Row 3: shift left 3 (right 1)
  let t3 = s[15]
  s[15] = s[11]
  s[11] = s[7]
  s[7] = s[3]
  s[3] = t3
}

///|
fn aes_mix_columns(s : FixedArray[Byte]) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    let i = c * 4
    let a0 = s[i].to_int()
    let a1 = s[i + 1].to_int()
    let a2 = s[i + 2].to_int()
    let a3 = s[i + 3].to_int()
    let t = a0 ^ a1 ^ a2 ^ a3
    s[i] = (a0 ^ t ^ aes_xtime(a0 ^ a1)).to_byte()
    s[i + 1] = (a1 ^ t ^ aes_xtime(a1 ^ a2)).to_byte()
    s[i + 2] = (a2 ^ t ^ aes_xtime(a2 ^ a3)).to_byte()
    s[i + 3] = (a3 ^ t ^ aes_xtime(a3 ^ a0)).to_byte()
  }
}

///|
fn aes128_encrypt_block(
  rk : FixedArray[UInt32],
  input : FixedArray[Byte],
) -> FixedArray[Byte] {
  let s = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    s[i] = input[i]
  }
  aes_add_round_key(s, rk, 0)
  for round = 1; round <= 9; round = round + 1 {
    aes_sub_bytes(s)
    aes_shift_rows(s)
    aes_mix_columns(s)
    aes_add_round_key(s, rk, round)
  }
  aes_sub_bytes(s)
  aes_shift_rows(s)
  aes_add_round_key(s, rk, 10)
  s
}

///|
fn gf128_mul(
  x_hi : UInt64,
  x_lo : UInt64,
  h_hi : UInt64,
  h_lo : UInt64,
) -> (UInt64, UInt64) {
  let mut z_hi = 0UL
  let mut z_lo = 0UL
  let mut v_hi = h_hi
  let mut v_lo = h_lo
  for i = 0; i < 64; i = i + 1 {
    let bit = (x_hi >> (63 - i)) & 1UL
    let mask = 0UL - bit
    z_hi = z_hi ^ (v_hi & mask)
    z_lo = z_lo ^ (v_lo & mask)
    let lsb = v_lo & 1UL
    v_lo = (v_lo >> 1) | (v_hi << 63)
    v_hi = (v_hi >> 1) ^ ((0UL - lsb) & 0xe100000000000000UL)
  }
  for i = 0; i < 64; i = i + 1 {
    let bit = (x_lo >> (63 - i)) & 1UL
    let mask = 0UL - bit
    z_hi = z_hi ^ (v_hi & mask)
    z_lo = z_lo ^ (v_lo & mask)
    let lsb = v_lo & 1UL
    v_lo = (v_lo >> 1) | (v_hi << 63)
    v_hi = (v_hi >> 1) ^ ((0UL - lsb) & 0xe100000000000000UL)
  }
  (z_hi, z_lo)
}

///|
fn ghash_update_bytes(
  y_hi : UInt64,
  y_lo : UInt64,
  h_hi : UInt64,
  h_lo : UInt64,
  data : Bytes,
  start : Int32,
  len : Int32,
) -> (UInt64, UInt64) {
  let mut cur_hi = y_hi
  let mut cur_lo = y_lo
  let mut off = 0
  while off + 16 <= len {
    let b_hi = load_be64(data, start + off)
    let b_lo = load_be64(data, start + off + 8)
    let next = gf128_mul(cur_hi ^ b_hi, cur_lo ^ b_lo, h_hi, h_lo)
    cur_hi = next.0
    cur_lo = next.1
    off = off + 16
  }
  if off < len {
    let rem = FixedArray::make(16, b'\x00')
    for i = 0; i < len - off; i = i + 1 {
      rem[i] = data[start + off + i]
    }
    let b_hi = load_be64_arr(rem, 0)
    let b_lo = load_be64_arr(rem, 8)
    let next = gf128_mul(cur_hi ^ b_hi, cur_lo ^ b_lo, h_hi, h_lo)
    cur_hi = next.0
    cur_lo = next.1
  }
  (cur_hi, cur_lo)
}

///|
fn gcm_compute_tag(
  rk : FixedArray[UInt32],
  j0 : FixedArray[Byte],
  aad : Bytes,
  ct : Bytes,
  ct_len : Int32,
) -> Bytes {
  let zero_block = FixedArray::make(16, b'\x00')
  let h_block = aes128_encrypt_block(rk, zero_block)
  let h_hi = load_be64_arr(h_block, 0)
  let h_lo = load_be64_arr(h_block, 8)
  let s1 = ghash_update_bytes(0UL, 0UL, h_hi, h_lo, aad, 0, aad.length())
  let s2 = ghash_update_bytes(s1.0, s1.1, h_hi, h_lo, ct, 0, ct_len)
  let aad_bits = aad.length().to_uint64() * 8UL
  let ct_bits = ct_len.to_uint64() * 8UL
  let s3 = gf128_mul(s2.0 ^ aad_bits, s2.1 ^ ct_bits, h_hi, h_lo)
  let ej0 = aes128_encrypt_block(rk, j0)
  let ej0_hi = load_be64_arr(ej0, 0)
  let ej0_lo = load_be64_arr(ej0, 8)
  let tag = FixedArray::make(16, b'\x00')
  store_be64_arr(tag, 0, s3.0 ^ ej0_hi)
  store_be64_arr(tag, 8, s3.1 ^ ej0_lo)
  bytes_from_fixed(tag)
}

///|
fn gcm_make_j0(nonce : Bytes) -> FixedArray[Byte] {
  let j0 = FixedArray::make(16, b'\x00')
  for i = 0; i < 12; i = i + 1 {
    j0[i] = nonce[i]
  }
  j0[15] = b'\x01'
  j0
}

///|
fn gcm_inc32(ctr : FixedArray[Byte]) -> Unit {
  let c = load_be32_arr(ctr, 12) + 1U
  store_be32_arr(ctr, 12, c)
}

///|
fn gcm_gctr(
  rk : FixedArray[UInt32],
  j0 : FixedArray[Byte],
  input : Bytes,
  len : Int32,
) -> FixedArray[Byte] {
  let out = FixedArray::make(len, b'\x00')
  let ctr = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    ctr[i] = j0[i]
  }
  let mut off = 0
  while off < len {
    gcm_inc32(ctr)
    let ks = aes128_encrypt_block(rk, ctr)
    let take = if len - off < 16 { len - off } else { 16 }
    for i = 0; i < take; i = i + 1 {
      out[off + i] = (input[off + i].to_int() ^ ks[i].to_int()).to_byte()
    }
    off = off + take
  }
  out
}

///|
pub fn aes128_gcm_seal(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise CryptoError {
  if key.length() != 16 {
    raise InvalidKeyLength
  }
  if nonce.length() != 12 {
    raise InvalidNonceLength
  }
  let rk = aes128_expand_key(key)
  let j0 = gcm_make_j0(nonce)
  let pt_len = plaintext.length()
  let ct_arr = gcm_gctr(rk, j0, plaintext, pt_len)
  let ct_bytes = bytes_from_fixed(ct_arr)
  let tag = gcm_compute_tag(rk, j0, aad, ct_bytes, pt_len)
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
pub fn aes128_gcm_open(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_and_tag : Bytes,
) -> Bytes raise CryptoError {
  if key.length() != 16 {
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
  let rk = aes128_expand_key(key)
  let j0 = gcm_make_j0(nonce)
  let expected_tag = gcm_compute_tag(rk, j0, aad, ciphertext_and_tag, ct_len)
  let provided_tag = Bytes::makei(16, fn(i) { ciphertext_and_tag[ct_len + i] })
  if !ct_equal(expected_tag, provided_tag) {
    raise AuthFailed
  }
  let pt_arr = gcm_gctr(rk, j0, ciphertext_and_tag, ct_len)
  bytes_from_fixed(pt_arr)
}
