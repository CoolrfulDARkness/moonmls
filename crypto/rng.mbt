///|
pub struct DeterministicRng {
  mut key : Bytes
  mut counter : UInt64
}

///|
pub fn DeterministicRng::from_seed(seed : Bytes) -> DeterministicRng {
  let init_key = if seed.length() == 32 {
    Bytes::makei(32, fn(i) { seed[i] })
  } else {
    sha256(seed)
  }
  { key: init_key, counter: 0UL, }
}

///|
pub fn DeterministicRng::next_bytes(
  self : DeterministicRng,
  n : Int32,
) -> Bytes {
  if n <= 0 {
    return b""
  }
  let nonce_arr = FixedArray::make(12, b'\x00')
  store_le64_arr(nonce_arr, 4, self.counter)
  let nonce = bytes_from_fixed(nonce_arr)
  // Block 0 produces the ratcheted next key for forward secrecy
  let ratchet_block = chacha20_block(self.key, 0U, nonce)
  let next_key = Bytes::makei(32, fn(i) { ratchet_block[i] })
  let out = FixedArray::make(n, b'\x00')
  let mut blk_ctr = 1U
  let mut off = 0
  while off < n {
    let ks = chacha20_block(self.key, blk_ctr, nonce)
    let take = if n - off < 64 { n - off } else { 64 }
    for i = 0; i < take; i = i + 1 {
      out[off + i] = ks[i]
    }
    blk_ctr = blk_ctr + 1U
    off = off + take
  }
  self.key = next_key
  self.counter = self.counter + 1UL
  bytes_from_fixed(out)
}
