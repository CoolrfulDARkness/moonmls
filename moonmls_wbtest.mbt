///|
test "top-level cipher suite helpers" {
  assert_eq(cs_x25519_aes128gcm().id(), 1U)
  assert_eq(cs_x25519_chacha20poly1305().id(), 3U)
}
