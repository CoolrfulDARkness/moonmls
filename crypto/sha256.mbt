///|
let sha256_k : FixedArray[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
priv struct Sha256State {
  h : FixedArray[UInt32]
  buf : FixedArray[Byte]
  mut buf_len : Int32
  mut total_len : UInt64
}

///|
fn Sha256State::new() -> Sha256State {
  {
    h: [
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
      0x1f83d9abU, 0x5be0cd19U,
    ],
    buf: FixedArray::make(64, b'\x00'),
    buf_len: 0,
    total_len: 0UL,
  }
}

///|
fn sha256_compress(h : FixedArray[UInt32], block : FixedArray[Byte]) -> Unit {
  let w = FixedArray::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = load_be32_arr(block, i * 4)
  }
  for i = 16; i < 64; i = i + 1 {
    let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
    let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut hh = h[7]
  for i = 0; i < 64; i = i + 1 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = hh + s1 + ch + sha256_k[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    hh = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
  }
  h[0] = h[0] + a
  h[1] = h[1] + b
  h[2] = h[2] + c
  h[3] = h[3] + d
  h[4] = h[4] + e
  h[5] = h[5] + f
  h[6] = h[6] + g
  h[7] = h[7] + hh
}

///|
fn Sha256State::update(self : Sha256State, data : Bytes) -> Unit {
  let len = data.length()
  self.total_len = self.total_len + len.to_uint64()
  let mut i = 0
  while i < len {
    self.buf[self.buf_len] = data[i]
    self.buf_len = self.buf_len + 1
    i = i + 1
    if self.buf_len == 64 {
      sha256_compress(self.h, self.buf)
      self.buf_len = 0
    }
  }
}

///|
fn Sha256State::update_fixed(
  self : Sha256State,
  data : FixedArray[Byte],
) -> Unit {
  let len = data.length()
  self.total_len = self.total_len + len.to_uint64()
  let mut i = 0
  while i < len {
    self.buf[self.buf_len] = data[i]
    self.buf_len = self.buf_len + 1
    i = i + 1
    if self.buf_len == 64 {
      sha256_compress(self.h, self.buf)
      self.buf_len = 0
    }
  }
}

///|
fn Sha256State::finalize(self : Sha256State) -> Bytes {
  let bit_len = self.total_len * 8UL
  self.buf[self.buf_len] = b'\x80'
  self.buf_len = self.buf_len + 1
  if self.buf_len > 56 {
    while self.buf_len < 64 {
      self.buf[self.buf_len] = b'\x00'
      self.buf_len = self.buf_len + 1
    }
    sha256_compress(self.h, self.buf)
    self.buf_len = 0
  }
  while self.buf_len < 56 {
    self.buf[self.buf_len] = b'\x00'
    self.buf_len = self.buf_len + 1
  }
  store_be64_arr(self.buf, 56, bit_len)
  sha256_compress(self.h, self.buf)
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    store_be32_arr(out, i * 4, self.h[i])
  }
  bytes_from_fixed(out)
}

///|
pub fn sha256(data : Bytes) -> Bytes {
  let st = Sha256State::new()
  st.update(data)
  st.finalize()
}
