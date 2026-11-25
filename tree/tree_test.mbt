///|
fn[T] expect_tree_err(
  f : () -> T raise @tree.TreeError,
  expected : @tree.TreeError,
) -> Unit raise {
  let mut got : @tree.TreeError? = None
  try {
    let _ = f()
  } catch {
    e => got = Some(e)
  }
  assert_eq(got, Some(expected))
}

///|
fn make_signed_kp_leaf(
  cs : @cs.CipherSuite,
  seed_byte : Byte,
  identity : Bytes,
) -> (@types.LeafNode, Bytes, Bytes) raise {
  let enc_seed = Bytes::make(32, seed_byte)
  let sig_seed = Bytes::make(32, (seed_byte.to_int() + 100).to_byte())
  let (enc_priv, enc_pub) = cs.kem_keypair_from_ikm(enc_seed)
  let (sig_priv, sig_pub) = cs.signature_keypair_from_seed(sig_seed)
  let caps : @types.Capabilities = {
    versions: [@types.PROTOCOL_VERSION_MLS10],
    cipher_suites: [cs.id()],
    extensions: [],
    proposals: [],
    credentials: [@types.CREDENTIAL_TYPE_BASIC],
  }
  let unsigned : @types.LeafNode = {
    encryption_key: enc_pub,
    signature_key: sig_pub,
    credential: @types.Credential::Basic(identity),
    capabilities: caps,
    leaf_node_source: @types.LeafNodeSource::KeyPackage,
    lifetime: Some({ not_before: 0UL, not_after: 9999999999UL, }),
    parent_hash: None,
    extensions: [],
    signature: b"",
  }
  let tbs = unsigned.encode_tbs(None, None)
  let sig = cs.sign_with_label(sig_priv, "LeafNodeTBS", tbs)
  let leaf : @types.LeafNode = {
    encryption_key: unsigned.encryption_key,
    signature_key: unsigned.signature_key,
    credential: unsigned.credential,
    capabilities: unsigned.capabilities,
    leaf_node_source: unsigned.leaf_node_source,
    lifetime: unsigned.lifetime,
    parent_hash: unsigned.parent_hash,
    extensions: unsigned.extensions,
    signature: sig,
  }
  (leaf, enc_priv, sig_priv)
}

///|
test "secret_tree replay window out-of-order, replay, forward limit, and bounds" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let enc_secret = Bytes::make(32, b'\x42')
  // Sender and receiver with window: out_of_order_tolerance=3, max_forward_distance=10
  let sender_st = @tree.SecretTree::new_with_window(cs, enc_secret, 4U, 3U, 10U)
  let recv_st = @tree.SecretTree::new_with_window(cs, enc_secret, 4U, 3U, 10U)
  // Generate generations 0..6 on sender for leaf 2
  let expected_app : Array[(Bytes, Bytes)] = []
  for g = 0U; g < 7U; g = g + 1U {
    let (gen, key, nonce) = sender_st.next_application_key_nonce(2U)
    assert_eq(gen, g)
    assert_eq(key.length(), 16)
    assert_eq(nonce.length(), 12)
    expected_app.push((key, nonce))
  }
  // Receiver decrypts out-of-order: 0, then jump to 3, then 1, then 2
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 0U),
    expected_app[0],
  )
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 3U),
    expected_app[3],
  )
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 1U),
    expected_app[1],
  )
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 2U),
    expected_app[2],
  )
  // Replay of already-consumed generation 0, 1, 2, 3 MUST fail with ReplayDetected
  for g = 0U; g < 4U; g = g + 1U {
    expect_tree_err(
      () => recv_st.application_key_nonce_for_generation(2U, g),
      @tree.TreeError::ReplayDetected(g),
    )
  }
  // Forward jump beyond max_forward_distance (current_gen=4, max=10 -> 15 is dist 11 > 10)
  expect_tree_err(
    () => recv_st.application_key_nonce_for_generation(2U, 15U),
    @tree.TreeError::GenerationTooFarAhead(15U),
  )
  // State must remain intact after GenerationTooFarAhead; gen 6 (dist 2) succeeds
  // and caches gens 4, 5 (within tolerance 3 of gen 6)
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 6U),
    expected_app[6],
  )
  assert_eq(
    recv_st.application_key_nonce_for_generation(2U, 4U),
    expected_app[4],
  )
  // Eviction test: jump from current_gen=7 to 14 (dist 7 <= 10); tolerance=3 keeps 11,12,13, evicts 5
  let _ = recv_st.application_key_nonce_for_generation(2U, 14U)
  expect_tree_err(
    () => recv_st.application_key_nonce_for_generation(2U, 5U),
    @tree.TreeError::ReplayDetected(5U),
  )
  // Generation 11 is still in window (14 - 11 = 3 <= 3) and single-use
  let _ = recv_st.application_key_nonce_for_generation(2U, 11U)
  expect_tree_err(
    () => recv_st.application_key_nonce_for_generation(2U, 11U),
    @tree.TreeError::ReplayDetected(11U),
  )
  // Handshake ratchet is completely independent from application ratchet
  let (hs_gen0, hs_k0, hs_n0) = sender_st.next_handshake_key_nonce(2U)
  assert_eq(hs_gen0, 0U)
  assert_eq(recv_st.handshake_key_nonce_for_generation(2U, 0U), (hs_k0, hs_n0))
  assert_true(hs_k0 != expected_app[0].0)
  // Out-of-bounds leaf_idx MUST raise OutOfBounds
  expect_tree_err(
    () => recv_st.leaf_secret(4U),
    @tree.TreeError::OutOfBounds(4U),
  )
  expect_tree_err(
    () => sender_st.next_handshake_key_nonce(99U),
    @tree.TreeError::OutOfBounds(99U),
  )
  expect_tree_err(
    () => recv_st.handshake_key_nonce_for_generation(4U, 0U),
    @tree.TreeError::OutOfBounds(4U),
  )
}

///|
test "secret_tree cs3 key sizes and short sender_data ciphertext sample" {
  let cs3 = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let sd_secret = Bytes::make(32, b'\x11')
  let short_ct = b"\xaa\xbb\xcc"
  let sd_key = @tree.derive_sender_data_key(cs3, sd_secret, short_ct)
  let sd_nonce = @tree.derive_sender_data_nonce(cs3, sd_secret, short_ct)
  assert_eq(sd_key.length(), 32)
  assert_eq(sd_nonce.length(), 12)
  let st = @tree.SecretTree::new(cs3, Bytes::make(32, b'\x22'), 1U)
  assert_eq(st.leaf_secret(0U), Bytes::make(32, b'\x22'))
  let (g, k, n) = st.next_application_key_nonce(0U)
  assert_eq(g, 0U)
  assert_eq(k.length(), 32)
  assert_eq(n.length(), 12)
}

///|
test "ratchet_tree validation errors and structural invariants" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let group_id = b"test-group-validation"
  // Empty and even-sized arrays
  expect_tree_err(
    () => @tree.RatchetTreeState::from_nodes([]),
    @tree.TreeError::EmptyTree,
  )
  let (leaf0, _, _) = make_signed_kp_leaf(cs, b'\x01', b"alice")
  let (leaf1, _, _) = make_signed_kp_leaf(cs, b'\x02', b"bob")
  expect_tree_err(
    () => {
      @tree.RatchetTreeState::from_nodes([Some(@types.Node::Leaf(leaf0)), None])
    },
    @tree.TreeError::InvalidTreeSize(2),
  )
  // Basic queries & clone isolation
  let tree = @tree.RatchetTreeState::new(leaf0)
  let idx1 = tree.add_leaf(leaf1)
  assert_eq(idx1, 1U)
  assert_eq(tree.active_leaf_indices(), [0U, 1U])
  assert_eq(tree.find_leaf_by_sig_key(leaf1.signature_key), Some(1U))
  assert_eq(tree.find_leaf_by_sig_key(Bytes::make(32, b'\xFF')), None)
  let cloned = tree.clone()
  cloned.remove_leaf(1U)
  assert_eq(cloned.n_leaves(), 1U)
  assert_eq(tree.n_leaves(), 2U)
  // BlankLeaf on removing or updating a blank leaf
  let (leaf2, _, _) = make_signed_kp_leaf(cs, b'\x03', b"charlie")
  let _ = tree.add_leaf(leaf2)
  tree.remove_leaf(1U)
  expect_tree_err(() => tree.remove_leaf(1U), @tree.TreeError::BlankLeaf(1U))
  expect_tree_err(
    () => tree.update_leaf(1U, leaf1),
    @tree.TreeError::BlankLeaf(1U),
  )
  // DuplicateKey detection
  let dup_tree = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    None,
    Some(@types.Node::Leaf(leaf0)),
  ])
  expect_tree_err(
    () => dup_tree.validate_tree_structure(),
    @tree.TreeError::DuplicateKey,
  )
  // UnexpectedNodeType detection (parent in leaf slot)
  let bad_parent : @types.ParentNode = {
    encryption_key: Bytes::make(32, b'\x55'),
    parent_hash: b"",
    unmerged_leaves: [],
  }
  let bad_type_tree = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Parent(bad_parent)),
  ])
  expect_tree_err(
    () => bad_type_tree.validate_tree_structure(),
    @tree.TreeError::UnexpectedNodeType(0U),
  )
  // InvalidUnmergedLeaf detection (unmerged leaf points to blank leaf)
  let bad_ul_parent : @types.ParentNode = {
    encryption_key: Bytes::make(32, b'\x66'),
    parent_hash: b"",
    unmerged_leaves: [1U],
  }
  let bad_ul_tree = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    Some(@types.Node::Parent(bad_ul_parent)),
    None,
  ])
  expect_tree_err(
    () => bad_ul_tree.validate_tree_structure(),
    @tree.TreeError::InvalidUnmergedLeaf,
  )
  // InvalidLeafSignature detection
  let tampered_leaf : @types.LeafNode = {
    encryption_key: leaf0.encryption_key,
    signature_key: leaf0.signature_key,
    credential: leaf0.credential,
    capabilities: leaf0.capabilities,
    leaf_node_source: leaf0.leaf_node_source,
    lifetime: leaf0.lifetime,
    parent_hash: leaf0.parent_hash,
    extensions: leaf0.extensions,
    signature: Bytes::make(64, b'\x00'),
  }
  let bad_sig_tree = @tree.RatchetTreeState::new(tampered_leaf)
  expect_tree_err(
    () => bad_sig_tree.validate_leaf_signatures(cs, group_id),
    @tree.TreeError::InvalidLeafSignature(0U),
  )
}

///|
test "treekem end-to-end prepare, encrypt, merge, decrypt, welcome derive, and exclude_leaves" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let group_id = b"moonmls-e2e-group"
  let (leaf0, enc_priv0, sig_priv0) = make_signed_kp_leaf(cs, b'\x10', b"alice")
  let (leaf1, enc_priv1, _sig_priv1) = make_signed_kp_leaf(cs, b'\x20', b"bob")
  let (leaf2, enc_priv2, _sig_priv2) = make_signed_kp_leaf(
    cs, b'\x30', b"charlie",
  )
  let (leaf3, _enc_priv3, _sig_priv3) = make_signed_kp_leaf(
    cs, b'\x40', b"dave",
  )
  let alice_tree = @tree.RatchetTreeState::new(leaf0)
  assert_eq(alice_tree.add_leaf(leaf1), 1U)
  assert_eq(alice_tree.add_leaf(leaf2), 2U)
  // Now Alice commits adding Dave (leaf 3) with an UpdatePath (excluding leaf 3 from encryption)
  let added_leaf = alice_tree.add_leaf(leaf3)
  assert_eq(added_leaf, 3U)
  let bob_tree = alice_tree.clone()
  let charlie_tree = alice_tree.clone()
  let exclude : Array[UInt32] = [added_leaf]
  let leaf_secret = Bytes::make(32, b'\x77')
  let prepared = alice_tree.prepare_update_path_tree(
    cs, 0U, leaf0, sig_priv0, group_id, leaf_secret,
  )
  let gc : @types.GroupContext = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    group_id,
    epoch: 1UL,
    tree_hash: prepared.tree_hash,
    confirmed_transcript_hash: Bytes::make(32, b'\x00'),
    extensions: [],
  }
  let gc_bytes = gc.to_bytes()
  let rng = @crypto.DeterministicRng::from_seed(Bytes::make(32, b'\x99'))
  let update_path = alice_tree.encrypt_path_secrets(
    cs, 0U, prepared, gc_bytes, exclude, rng,
  )
  // Validate Alice's updated tree
  alice_tree.validate_tree_structure()
  alice_tree.validate_parent_hashes(cs)
  alice_tree.validate_leaf_signatures(cs, group_id)
  // Bob merges and decrypts UpdatePath
  bob_tree.merge_update_path_nodes(cs, 0U, update_path, group_id, exclude)
  assert_eq(bob_tree.tree_hash(cs), prepared.tree_hash)
  bob_tree.validate_parent_hashes(cs)
  bob_tree.validate_leaf_signatures(cs, group_id)
  let (bob_keys, bob_commit_secret) = bob_tree.decrypt_update_path(
    cs,
    0U,
    1U,
    update_path,
    gc_bytes,
    exclude,
    fn(n) { if n == 2U { Some(enc_priv1) } else { None } },
  )
  assert_eq(bob_commit_secret, prepared.commit_secret)
  assert_eq(bob_keys.length(), 2) // nodes 1 and 3
  assert_eq(bob_keys[0].0, 1U)
  assert_eq(bob_keys[0].1, prepared.path_node_keys[0].1)
  assert_eq(bob_keys[1].0, 3U)
  assert_eq(bob_keys[1].1, prepared.path_node_keys[1].1)
  // Charlie merges and decrypts UpdatePath (shared ancestor with Alice is root = node 3)
  charlie_tree.merge_update_path_nodes(cs, 0U, update_path, group_id, exclude)
  let (charlie_keys, charlie_commit_secret) = charlie_tree.decrypt_update_path(
    cs,
    0U,
    2U,
    update_path,
    gc_bytes,
    exclude,
    fn(n) { if n == 4U { Some(enc_priv2) } else { None } },
  )
  assert_eq(charlie_commit_secret, prepared.commit_secret)
  assert_eq(charlie_keys.length(), 1) // root node 3
  assert_eq(charlie_keys[0].0, 3U)
  assert_eq(charlie_keys[0].1, prepared.path_node_keys[1].1)
  // Dave (Welcome joiner at leaf 3) receives path_secret for common_ancestor(0, 6) = node 3
  let lca_dave = @treemath.common_ancestor(
    @treemath.leaf_to_node(0U),
    @treemath.leaf_to_node(3U),
  )
  assert_eq(lca_dave, 3U)
  let (dave_keys, dave_commit_secret) = alice_tree.derive_path_secrets_from(
    cs,
    0U,
    lca_dave,
    prepared.path_secrets[1].1,
  )
  assert_eq(dave_commit_secret, prepared.commit_secret)
  assert_eq(dave_keys, charlie_keys)
  // Atomicity: tampering update_path leaf parent_hash leaves tree unchanged
  let before_hash = bob_tree.tree_hash(cs)
  let bad_leaf : @types.LeafNode = {
    encryption_key: update_path.leaf_node.encryption_key,
    signature_key: update_path.leaf_node.signature_key,
    credential: update_path.leaf_node.credential,
    capabilities: update_path.leaf_node.capabilities,
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: Some(Bytes::make(32, b'\x00')),
    extensions: update_path.leaf_node.extensions,
    signature: update_path.leaf_node.signature,
  }
  let bad_up : @types.UpdatePath = {
    leaf_node: bad_leaf,
    nodes: update_path.nodes,
  }
  expect_tree_err(
    () => bob_tree.merge_update_path_nodes(cs, 0U, bad_up, group_id, exclude),
    @tree.TreeError::InvalidParentHash,
  )
  assert_eq(bob_tree.tree_hash(cs), before_hash)
  // Single-member tree prepare_update_path_tree (empty filtered_direct_path)
  let solo = @tree.RatchetTreeState::new(leaf0)
  let solo_prep = solo.prepare_update_path_tree(
    cs, 0U, leaf0, sig_priv0, group_id, leaf_secret,
  )
  assert_eq(solo_prep.path_node_keys.length(), 0)
  assert_eq(solo_prep.leaf_node.parent_hash, Some(b""))
  assert_eq(solo_prep.commit_secret, cs.derive_secret(leaf_secret, "path"))
  assert_true(enc_priv0 != solo_prep.leaf_enc_priv)
  solo.validate_tree_structure()
  solo.validate_parent_hashes(cs)
  solo.validate_leaf_signatures(cs, group_id)
}

///|
test "C-2 merge_update_path_nodes rejects unrotated key, low-order X25519 key, and duplicate keys" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let group_id = b"c2-test-gid"
  let (leaf0, _, sig_priv0) = make_signed_kp_leaf(cs, b'\x11', b"alice")
  let (leaf1, _, _) = make_signed_kp_leaf(cs, b'\x22', b"bob")
  let tree = @tree.RatchetTreeState::new(leaf0)
  let _ = tree.add_leaf(leaf1)
  let rng = @crypto.DeterministicRng::from_seed(b"c2-rng")
  let work_ref = tree.clone()
  let prep = work_ref.prepare_update_path_tree(
    cs,
    0U,
    leaf0,
    sig_priv0,
    group_id,
    Bytes::make(32, b'\x33'),
  )
  let valid_up = work_ref.encrypt_path_secrets(cs, 0U, prep, b"gc", [], rng)
  // 1. Low-order X25519 point in UpdatePathNode.encryption_key -> rejected atomically
  let before_hash = tree.tree_hash(cs)
  let low_order = Bytes::make(32, b'\x00')
  let bad_low_up : @types.UpdatePath = {
    leaf_node: valid_up.leaf_node,
    nodes: [
      {
        encryption_key: low_order,
        encrypted_path_secret: valid_up.nodes[0].encrypted_path_secret,
      },
    ],
  }
  let mut got_low = false
  tree.merge_update_path_nodes(cs, 0U, bad_low_up, group_id, []) catch {
    @tree.TreeError::CsError(
      @cs.CsError::CryptoError(@crypto.CryptoError::LowOrderPoint),
    ) => got_low = true
    _ => fail("expected LowOrderPoint in merge_update_path_nodes")
  }
  assert_true(got_low)
  assert_eq(tree.tree_hash(cs), before_hash)
  // 2. Unrotated leaf encryption_key (even with valid parent_hash & valid signature!) -> DuplicateKey
  let unrotated_unsigned : @types.LeafNode = {
    encryption_key: leaf0.encryption_key,
    signature_key: leaf0.signature_key,
    credential: leaf0.credential,
    capabilities: leaf0.capabilities,
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: valid_up.leaf_node.parent_hash,
    extensions: leaf0.extensions,
    signature: b"",
  }
  let unrotated_sig = cs.sign_with_label(
    sig_priv0,
    "LeafNodeTBS",
    unrotated_unsigned.encode_tbs(Some(group_id), Some(0U)),
  )
  let unrotated_leaf : @types.LeafNode = {
    encryption_key: unrotated_unsigned.encryption_key,
    signature_key: unrotated_unsigned.signature_key,
    credential: unrotated_unsigned.credential,
    capabilities: unrotated_unsigned.capabilities,
    leaf_node_source: unrotated_unsigned.leaf_node_source,
    lifetime: unrotated_unsigned.lifetime,
    parent_hash: unrotated_unsigned.parent_hash,
    extensions: unrotated_unsigned.extensions,
    signature: unrotated_sig,
  }
  let unrotated_up : @types.UpdatePath = {
    leaf_node: unrotated_leaf,
    nodes: valid_up.nodes,
  }
  expect_tree_err(
    () => tree.merge_update_path_nodes(cs, 0U, unrotated_up, group_id, []),
    @tree.TreeError::DuplicateKey,
  )
  assert_eq(tree.tree_hash(cs), before_hash)
  // 3. Parent key duplicating Bob's leaf encryption_key -> rejected by validate_tree_structure
  let dup_parent_tree = tree.clone()
  let dup_node : @types.UpdatePathNode = {
    encryption_key: leaf1.encryption_key,
    encrypted_path_secret: valid_up.nodes[0].encrypted_path_secret,
  }
  // Compute valid parent_hash for the colliding parent key and sign leaf0
  let tmp_t = tree.clone()
  tmp_t.nodes[1] = Some(
    @types.Node::Parent({
      encryption_key: leaf1.encryption_key,
      parent_hash: b"",
      unmerged_leaves: [],
    }),
  )
  let ph_dup = tmp_t.compute_parent_hash(cs, 1U, 0U)
  let dup_leaf_unsigned : @types.LeafNode = {
    encryption_key: valid_up.leaf_node.encryption_key,
    signature_key: leaf0.signature_key,
    credential: leaf0.credential,
    capabilities: leaf0.capabilities,
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: Some(ph_dup),
    extensions: leaf0.extensions,
    signature: b"",
  }
  let dup_leaf_sig = cs.sign_with_label(
    sig_priv0,
    "LeafNodeTBS",
    dup_leaf_unsigned.encode_tbs(Some(group_id), Some(0U)),
  )
  let dup_up : @types.UpdatePath = {
    leaf_node: {
      encryption_key: dup_leaf_unsigned.encryption_key,
      signature_key: dup_leaf_unsigned.signature_key,
      credential: dup_leaf_unsigned.credential,
      capabilities: dup_leaf_unsigned.capabilities,
      leaf_node_source: dup_leaf_unsigned.leaf_node_source,
      lifetime: dup_leaf_unsigned.lifetime,
      parent_hash: dup_leaf_unsigned.parent_hash,
      extensions: dup_leaf_unsigned.extensions,
      signature: dup_leaf_sig,
    },
    nodes: [dup_node],
  }
  expect_tree_err(
    () => dup_parent_tree.merge_update_path_nodes(cs, 0U, dup_up, group_id, []),
    @tree.TreeError::DuplicateKey,
  )
  assert_eq(dup_parent_tree.tree_hash(cs), before_hash)
}

///|
test "H-3 tree validation enforces non-empty tree, unmerged_leaves invariants, X25519, extensions, and empty root parent_hash" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (leaf0, _, _) = make_signed_kp_leaf(cs, b'\x01', b"alice")
  let (leaf1, _, _) = make_signed_kp_leaf(cs, b'\x02', b"bob")
  let (leaf2, _, _) = make_signed_kp_leaf(cs, b'\x03', b"charlie")
  // 1. All-blank tree -> EmptyTree
  let all_blank = @tree.RatchetTreeState::from_nodes([None, None, None])
  expect_tree_err(
    () => all_blank.validate_tree_structure(),
    @tree.TreeError::EmptyTree,
  )
  // 2. Non-ascending unmerged_leaves -> InvalidUnmergedLeaf
  let non_asc_tree = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    Some(
      @types.Node::Parent({
        encryption_key: Bytes::make(32, b'\x51'),
        parent_hash: b"",
        unmerged_leaves: [1U, 0U],
      }),
    ),
    Some(@types.Node::Leaf(leaf1)),
  ])
  expect_tree_err(
    () => non_asc_tree.validate_tree_structure(),
    @tree.TreeError::InvalidUnmergedLeaf,
  )
  // 3. Unmerged leaf with non-KeyPackage source (Update) -> InvalidUnmergedLeaf
  let upd_leaf1 : @types.LeafNode = {
    encryption_key: leaf1.encryption_key,
    signature_key: leaf1.signature_key,
    credential: leaf1.credential,
    capabilities: leaf1.capabilities,
    leaf_node_source: @types.LeafNodeSource::Update,
    lifetime: None,
    parent_hash: None,
    extensions: [],
    signature: leaf1.signature,
  }
  let bad_src_ul = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    Some(
      @types.Node::Parent({
        encryption_key: Bytes::make(32, b'\x52'),
        parent_hash: b"",
        unmerged_leaves: [1U],
      }),
    ),
    Some(@types.Node::Leaf(upd_leaf1)),
  ])
  expect_tree_err(
    () => bad_src_ul.validate_tree_structure(),
    @tree.TreeError::InvalidUnmergedLeaf,
  )
  // 4. Unmerged leaf in root (node 3) missing from non-blank intermediate parent (node 1) -> InvalidUnmergedLeaf
  let missing_mid_ul = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    Some(
      @types.Node::Parent({
        encryption_key: Bytes::make(32, b'\x53'),
        parent_hash: b"",
        unmerged_leaves: [],
      }),
    ),
    Some(@types.Node::Leaf(leaf1)),
    Some(
      @types.Node::Parent({
        encryption_key: Bytes::make(32, b'\x54'),
        parent_hash: b"",
        unmerged_leaves: [1U],
      }),
    ),
    Some(@types.Node::Leaf(leaf2)),
    None,
    None,
  ])
  expect_tree_err(
    () => missing_mid_ul.validate_tree_structure(),
    @tree.TreeError::InvalidUnmergedLeaf,
  )
  // 5. Low-order X25519 key in leaf -> LowOrderPoint
  let low_leaf : @types.LeafNode = {
    encryption_key: Bytes::make(32, b'\x00'),
    signature_key: leaf0.signature_key,
    credential: leaf0.credential,
    capabilities: leaf0.capabilities,
    leaf_node_source: leaf0.leaf_node_source,
    lifetime: leaf0.lifetime,
    parent_hash: leaf0.parent_hash,
    extensions: [],
    signature: leaf0.signature,
  }
  expect_tree_err(
    () => @tree.RatchetTreeState::new(low_leaf).validate_tree_structure(),
    @tree.TreeError::CsError(
      @cs.CsError::CryptoError(@crypto.CryptoError::LowOrderPoint),
    ),
  )
  // 6. Duplicate extension_type in leaf -> DuplicateExtension
  let dup_ext_leaf : @types.LeafNode = {
    encryption_key: leaf0.encryption_key,
    signature_key: leaf0.signature_key,
    credential: leaf0.credential,
    capabilities: leaf0.capabilities,
    leaf_node_source: leaf0.leaf_node_source,
    lifetime: leaf0.lifetime,
    parent_hash: leaf0.parent_hash,
    extensions: [
      { extension_type: 1U, extension_data: b"a", },
      { extension_type: 1U, extension_data: b"b", },
    ],
    signature: leaf0.signature,
  }
  expect_tree_err(
    () => @tree.RatchetTreeState::new(dup_ext_leaf).validate_tree_structure(),
    @tree.TreeError::DuplicateExtension(1U),
  )
  // 7. Non-blank root parent with non-empty parent_hash -> InvalidParentHash
  let non_empty_root_ph = @tree.RatchetTreeState::from_nodes([
    Some(@types.Node::Leaf(leaf0)),
    Some(
      @types.Node::Parent({
        encryption_key: Bytes::make(32, b'\x55'),
        parent_hash: Bytes::make(32, b'\xAA'),
        unmerged_leaves: [],
      }),
    ),
    Some(@types.Node::Leaf(leaf1)),
  ])
  expect_tree_err(
    () => non_empty_root_ph.validate_parent_hashes(cs),
    @tree.TreeError::InvalidParentHash,
  )
}
