///|
test "C-1 SecretTree true intra-epoch FS deletes split parents and consumed leaf secrets" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let enc_secret = Bytes::make(32, b'\x5A')
  let st = SecretTree::new(cs, enc_secret, 8U)
  // Initially only root (node 7) is stored
  assert_eq(st.node_secrets.length(), 1)
  assert_true(st.node_secrets.contains(7U))
  // Consume leaf 0 application gen 0 -> splits 7->(3,11), 3->(1,5), 1->(0,2) and deletes 7, 3, 1, 0
  let (g0, k0, n0) = st.next_application_key_nonce(0U)
  assert_eq(g0, 0U)
  assert_eq(k0.length(), 16)
  assert_eq(n0.length(), 12)
  assert_false(st.node_secrets.contains(7U))
  assert_false(st.node_secrets.contains(3U))
  assert_false(st.node_secrets.contains(1U))
  assert_false(st.node_secrets.contains(0U))
  // Only sibling subtree roots 2, 5, 11 remain
  assert_eq(st.node_secrets.length(), 3)
  assert_true(st.node_secrets.contains(2U))
  assert_true(st.node_secrets.contains(5U))
  assert_true(st.node_secrets.contains(11U))
  // Leaf 0's raw leaf_secret can never be re-derived once ratchets are initialized
  let mut got_erased = false
  try {
    let _ = st.leaf_secret(0U)
  } catch {
    TreeError::ReplayDetected(0U) => got_erased = true
    _ => fail("expected ReplayDetected(0) for erased leaf secret")
  }
  assert_true(got_erased)
  // Handshake ratchet for leaf 0 was already seeded and works independently
  let (hs_g0, hs_k0, _) = st.next_handshake_key_nonce(0U)
  assert_eq(hs_g0, 0U)
  assert_true(hs_k0 != k0)
  // Sibling leaf 7 still derives exact matching keys against a fresh reference tree
  let ref_st = SecretTree::new(cs, enc_secret, 8U)
  assert_eq(
    st.application_key_nonce_for_generation(7U, 0U),
    ref_st.application_key_nonce_for_generation(7U, 0U),
  )
  assert_false(st.node_secrets.contains(11U))
  assert_false(st.node_secrets.contains(14U))
}

///|
test "C-1 next_power_of_two overflow guard and O(1) stage_key_nonce atomicity" {
  // Overflow boundary: must not hang or wrap to 0
  assert_eq(next_power_of_two(0x40000000U), 0x40000000U)
  assert_eq(next_power_of_two(0x40000001U), 0x40000000U)
  assert_eq(next_power_of_two(0xFFFFFFFFU), 0x40000000U)
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let huge = SecretTree::new(cs, Bytes::make(32, b'\x11'), 0x80000001U)
  assert_eq(huge.full_leaves, 0x40000000U)
  let mut oob = false
  try {
    let _ = huge.stage_key_nonce(0x40000000U, 0U, true)
  } catch {
    TreeError::OutOfBounds(0x40000000U) => oob = true
    _ => fail("expected OutOfBounds for leaf >= full_leaves")
  }
  assert_true(oob)
  // Staging without commit must not advance ratchet or block subsequent stage
  let st = SecretTree::new_with_window(cs, Bytes::make(32, b'\x22'), 4U, 2U, 5U)
  let s0 = st.stage_key_nonce(1U, 0U, true)
  // Forward jump beyond max_forward_distance immediately rejected without mutating
  let mut too_far = false
  try {
    let _ = st.stage_key_nonce(1U, 100U, true)
  } catch {
    TreeError::GenerationTooFarAhead(100U) => too_far = true
    _ => fail("expected GenerationTooFarAhead(100)")
  }
  assert_true(too_far)
  // Re-staging gen 0 before commit yields identical key/nonce
  let s0_again = st.stage_key_nonce(1U, 0U, true)
  assert_eq(s0.key(), s0_again.key())
  assert_eq(s0.nonce(), s0_again.nonce())
  // Commit s0 -> now gen 0 is permanently consumed (O(1) ReplayDetected on next stage)
  st.commit_stage(s0)
  let mut replayed = false
  try {
    let _ = st.stage_key_nonce(1U, 0U, true)
  } catch {
    TreeError::ReplayDetected(0U) => replayed = true
    _ => fail("expected ReplayDetected(0) after commit_stage")
  }
  assert_true(replayed)
}
