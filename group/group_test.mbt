///|
fn flip_byte_at(data : Bytes, idx : Int) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ 0xFF).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn assert_group_sync(groups : Array[@group.MlsGroup], expected_epoch : UInt64) -> Unit raise {
  let n = groups.length()
  assert_true(n > 0)
  let ref_auth = groups[0].epoch_authenticator()
  let ref_th = groups[0].tree_hash()
  let ref_exp = groups[0].export_secret("app-session-key", b"ctx-1", 32)
  let ref_members = groups[0].members()
  for i = 0; i < n; i = i + 1 {
    assert_eq(groups[i].epoch(), expected_epoch)
    assert_true(groups[i].is_active())
    assert_eq(groups[i].epoch_authenticator(), ref_auth)
    assert_eq(groups[i].tree_hash(), ref_th)
    assert_eq(groups[i].export_secret("app-session-key", b"ctx-1", 32), ref_exp)
    assert_eq(groups[i].members(), ref_members)
  }
}

///|
fn run_full_lifecycle_for_cs(
  cs : @cs.CipherSuite,
  seed_prefix : Bytes,
) -> Unit raise {
  let rng = @crypto.DeterministicRng::from_seed(seed_prefix)
  let group_id = b"moonmls-e2e-group"
  // 1. Alice creates the group
  let alice = @group.MlsGroup::create(cs, group_id, b"alice", rng)
  assert_eq(alice.cipher_suite(), cs)
  assert_eq(alice.group_id(), group_id)
  assert_eq(alice.epoch(), 0UL)
  assert_eq(alice.my_leaf_index(), 0U)
  assert_true(alice.is_active())
  assert_eq(alice.members(), [(0U, b"alice")])
  // 2. Generate KeyPackageBundles for Bob, Charlie, Dave, Eve
  let bob_kp = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let charlie_kp = @group.KeyPackageBundle::generate(cs, b"charlie", rng)
  let dave_kp = @group.KeyPackageBundle::generate(cs, b"dave", rng)
  let eve_kp = @group.KeyPackageBundle::generate(cs, b"eve", rng)
  @group.verify_key_package(cs, bob_kp.key_package)
  @group.verify_key_package(cs, charlie_kp.key_package)
  @group.verify_key_package(cs, dave_kp.key_package)
  @group.verify_key_package(cs, eve_kp.key_package)
  // 3. Alice adds Bob via inline Add Commit -> epoch 1
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  assert_eq(c1.new_epoch, 1UL)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome for Bob")
  }
  let bob = @group.MlsGroup::from_welcome(cs, w1, bob_kp, None)
  assert_eq(bob.my_leaf_index(), 1U)
  assert_group_sync([alice, bob], 1UL)
  // 4. Bob proposes adding Charlie, Alice commits pending -> epoch 2
  let prop_add_charlie = bob.propose_add(charlie_kp.key_package, rng)
  let p_res = alice.process_message(prop_add_charlie)
  assert_true(p_res is @group.ProcessedMessage::Proposal(1U, @types.Proposal::Add(_)))
  let c2 = alice.commit_pending(rng)
  assert_eq(c2.new_epoch, 2UL)
  let bob_c2 = bob.process_message(c2.commit_msg)
  assert_eq(bob_c2, @group.ProcessedMessage::Commit(0U, 2UL))
  let w2 = match c2.welcome {
    Some(w) => w
    None => fail("expected Welcome for Charlie")
  }
  let charlie = @group.MlsGroup::from_welcome(cs, w2, charlie_kp, None)
  assert_eq(charlie.my_leaf_index(), 2U)
  assert_group_sync([alice, bob, charlie], 2UL)
  // 5. Charlie adds Dave and Eve together in one Commit -> epoch 3
  let c3 = charlie.commit(
    [
      @types.Proposal::Add(dave_kp.key_package),
      @types.Proposal::Add(eve_kp.key_package),
    ],
    rng,
  )
  assert_eq(c3.new_epoch, 3UL)
  assert_eq(
    alice.process_message(c3.commit_msg),
    @group.ProcessedMessage::Commit(2U, 3UL),
  )
  assert_eq(
    bob.process_message(c3.commit_msg),
    @group.ProcessedMessage::Commit(2U, 3UL),
  )
  let w3 = match c3.welcome {
    Some(w) => w
    None => fail("expected Welcome for Dave and Eve")
  }
  let dave = @group.MlsGroup::from_welcome(cs, w3, dave_kp, None)
  let eve = @group.MlsGroup::from_welcome(cs, w3, eve_kp, None)
  assert_eq(dave.my_leaf_index(), 3U)
  assert_eq(eve.my_leaf_index(), 4U)
  let all5 = [alice, bob, charlie, dave, eve]
  assert_group_sync(all5, 3UL)
  assert_eq(alice.members().length(), 5)
  // 6. All 5 members exchange encrypted Application messages + out-of-order delivery
  let m_a0 = alice.protect_application(b"alice-msg-0", b"aad-a0", rng)
  let m_a1 = alice.protect_application(b"alice-msg-1", b"aad-a1", rng)
  let m_a2 = alice.protect_application(b"alice-msg-2", b"aad-a2", rng)
  // Deliver out of order (2, 0, 1) to Bob, Charlie, Dave, Eve
  for i = 1; i < 5; i = i + 1 {
    assert_eq(
      all5[i].process_message(m_a2),
      @group.ProcessedMessage::Application(0U, b"alice-msg-2", b"aad-a2"),
    )
    assert_eq(
      all5[i].process_message(m_a0),
      @group.ProcessedMessage::Application(0U, b"alice-msg-0", b"aad-a0"),
    )
    assert_eq(
      all5[i].process_message(m_a1),
      @group.ProcessedMessage::Application(0U, b"alice-msg-1", b"aad-a1"),
    )
  }
  // Eve, Dave, Charlie, Bob each send to everyone else
  let m_b = bob.protect_application(b"hello-from-bob", b"", rng)
  let m_c = charlie.protect_application(b"hello-from-charlie", b"c", rng)
  let m_d = dave.protect_application(b"hello-from-dave", b"d", rng)
  let m_e = eve.protect_application(b"hello-from-eve", b"e", rng)
  for i = 0; i < 5; i = i + 1 {
    if i != 1 {
      assert_eq(
        all5[i].process_message(m_b),
        @group.ProcessedMessage::Application(1U, b"hello-from-bob", b""),
      )
    }
    if i != 2 {
      assert_eq(
        all5[i].process_message(m_c),
        @group.ProcessedMessage::Application(2U, b"hello-from-charlie", b"c"),
      )
    }
    if i != 3 {
      assert_eq(
        all5[i].process_message(m_d),
        @group.ProcessedMessage::Application(3U, b"hello-from-dave", b"d"),
      )
    }
    if i != 4 {
      assert_eq(
        all5[i].process_message(m_e),
        @group.ProcessedMessage::Application(4U, b"hello-from-eve", b"e"),
      )
    }
  }
  // 7. PCS Key Rotation: Dave proposes Update, Bob commits pending -> epoch 4
  let epoch3_auth = alice.epoch_authenticator()
  let epoch3_export = alice.export_secret("pcs-check", b"ctx", 32)
  let dave_upd_msg = dave.propose_update(rng)
  for i = 0; i < 5; i = i + 1 {
    if i != 3 {
      let r = all5[i].process_message(dave_upd_msg)
      assert_true(r is @group.ProcessedMessage::Proposal(3U, @types.Proposal::Update(_)))
    }
  }
  let c4 = bob.commit_pending(rng)
  assert_eq(c4.new_epoch, 4UL)
  assert_true(c4.welcome is None)
  for i = 0; i < 5; i = i + 1 {
    if i != 1 {
      assert_eq(
        all5[i].process_message(c4.commit_msg),
        @group.ProcessedMessage::Commit(1U, 4UL),
      )
    }
  }
  assert_group_sync(all5, 4UL)
  // Verify PCS: epoch 4 secrets are distinct from epoch 3
  assert_true(alice.epoch_authenticator() != epoch3_auth)
  assert_true(alice.export_secret("pcs-check", b"ctx", 32) != epoch3_export)
  // Dave (who rotated his leaf key) can decrypt and commit in epoch 4 -> epoch 5
  let c5 = dave.commit([], rng)
  assert_eq(c5.new_epoch, 5UL)
  for i = 0; i < 5; i = i + 1 {
    if i != 3 {
      assert_eq(
        all5[i].process_message(c5.commit_msg),
        @group.ProcessedMessage::Commit(3U, 5UL),
      )
    }
  }
  assert_group_sync(all5, 5UL)
  // 8. Remove Eve: Charlie proposes Remove(4), Alice commits pending -> epoch 6
  let rem_eve_prop = charlie.propose_remove(4U, rng)
  for i = 0; i < 5; i = i + 1 {
    if i != 2 {
      assert_eq(
        all5[i].process_message(rem_eve_prop),
        @group.ProcessedMessage::Proposal(2U, @types.Proposal::Remove(4U)),
      )
    }
  }
  // Eve sends one last message in epoch 5 before commit (saved to test old-epoch rejection later)
  let eve_old_msg = eve.protect_application(b"eve-epoch5", b"", rng)
  let c6 = alice.commit_pending(rng)
  assert_eq(c6.new_epoch, 6UL)
  // Remaining 3 members (Bob, Charlie, Dave) process Commit -> epoch 6
  assert_eq(
    bob.process_message(c6.commit_msg),
    @group.ProcessedMessage::Commit(0U, 6UL),
  )
  assert_eq(
    charlie.process_message(c6.commit_msg),
    @group.ProcessedMessage::Commit(0U, 6UL),
  )
  assert_eq(
    dave.process_message(c6.commit_msg),
    @group.ProcessedMessage::Commit(0U, 6UL),
  )
  let rem4 = [alice, bob, charlie, dave]
  assert_group_sync(rem4, 6UL)
  assert_eq(alice.members().length(), 4)
  // Eve processes Commit -> MemberRemoved and becomes inactive
  let mut eve_got_removed = false
  try {
    let _ = eve.process_message(c6.commit_msg)
  } catch {
    @group.GroupError::MemberRemoved => eve_got_removed = true
    _ => fail("expected MemberRemoved for Eve")
  }
  assert_true(eve_got_removed)
  assert_true(!eve.is_active())
  // Remaining 4 continue communicating in epoch 6
  let post_rem_msg = bob.protect_application(b"secret-without-eve", b"e6", rng)
  assert_eq(
    alice.process_message(post_rem_msg),
    @group.ProcessedMessage::Application(1U, b"secret-without-eve", b"e6"),
  )
  assert_eq(
    charlie.process_message(post_rem_msg),
    @group.ProcessedMessage::Application(1U, b"secret-without-eve", b"e6"),
  )
  assert_eq(
    dave.process_message(post_rem_msg),
    @group.ProcessedMessage::Application(1U, b"secret-without-eve", b"e6"),
  )
  // Eve cannot process new epoch messages (MemberRemoved)
  let mut eve_blocked = false
  try {
    let _ = eve.process_message(post_rem_msg)
  } catch {
    @group.GroupError::MemberRemoved => eve_blocked = true
    _ => fail("expected MemberRemoved when inactive Eve processes message")
  }
  assert_true(eve_blocked)
  // Remaining members reject Eve's epoch-5 message (EpochMismatch)
  let mut alice_rejected_old = false
  try {
    let _ = alice.process_message(eve_old_msg)
  } catch {
    @group.GroupError::EpochMismatch(6UL, 5UL) => alice_rejected_old = true
    _ => fail("expected EpochMismatch for Eve's old epoch message")
  }
  assert_true(alice_rejected_old)
  // Eve's message rewritten with epoch=6 is also rejected (AEAD/sender_data failure)
  let forged_eve_e6 : @types.PrivateMessage = {
    group_id: eve_old_msg.group_id,
    epoch: 6UL,
    content_type: eve_old_msg.content_type,
    authenticated_data: eve_old_msg.authenticated_data,
    encrypted_sender_data: eve_old_msg.encrypted_sender_data,
    ciphertext: eve_old_msg.ciphertext,
  }
  let mut alice_rejected_forged = false
  try {
    let _ = alice.process_message(forged_eve_e6)
  } catch {
    @group.GroupError::ScheduleError(_) => alice_rejected_forged = true
    _ => fail("expected ScheduleError for Eve's forged epoch-6 message")
  }
  assert_true(alice_rejected_forged)
  // 9. Tampering, Replay, and Atomicity tests on epoch 6
  let legit_msg = dave.protect_application(b"legit-after-attacks", b"ok", rng)
  // 9a. Wrong group_id
  let wrong_gid : @types.PrivateMessage = {
    group_id: b"wrong-group",
    epoch: legit_msg.epoch,
    content_type: legit_msg.content_type,
    authenticated_data: legit_msg.authenticated_data,
    encrypted_sender_data: legit_msg.encrypted_sender_data,
    ciphertext: legit_msg.ciphertext,
  }
  let mut got_gid_err = false
  try {
    let _ = alice.process_message(wrong_gid)
  } catch {
    @group.GroupError::GroupIdMismatch => got_gid_err = true
    _ => fail("expected GroupIdMismatch")
  }
  assert_true(got_gid_err)
  // 9b. Tampered ciphertext before byte 32 (breaks sender_data sample)
  let bad_ct_head : @types.PrivateMessage = {
    group_id: legit_msg.group_id,
    epoch: legit_msg.epoch,
    content_type: legit_msg.content_type,
    authenticated_data: legit_msg.authenticated_data,
    encrypted_sender_data: legit_msg.encrypted_sender_data,
    ciphertext: flip_byte_at(legit_msg.ciphertext, 0),
  }
  let mut got_ct_head_err = false
  try {
    let _ = alice.process_message(bad_ct_head)
  } catch {
    @group.GroupError::ScheduleError(_) => got_ct_head_err = true
    _ => fail("expected ScheduleError on tampered ciphertext head")
  }
  assert_true(got_ct_head_err)
  // 9c. Tampered ciphertext AFTER byte 32 (sender_data succeeds, content AEAD fails — must NOT consume generation!)
  assert_true(legit_msg.ciphertext.length() > 40)
  let bad_ct_tail : @types.PrivateMessage = {
    group_id: legit_msg.group_id,
    epoch: legit_msg.epoch,
    content_type: legit_msg.content_type,
    authenticated_data: legit_msg.authenticated_data,
    encrypted_sender_data: legit_msg.encrypted_sender_data,
    ciphertext: flip_byte_at(legit_msg.ciphertext, legit_msg.ciphertext.length() - 1),
  }
  let mut got_ct_tail_err = false
  try {
    let _ = alice.process_message(bad_ct_tail)
  } catch {
    @group.GroupError::ScheduleError(_) => got_ct_tail_err = true
    _ => fail("expected ScheduleError on tampered ciphertext tail")
  }
  assert_true(got_ct_tail_err)
  // 9d. Legitimate message at the SAME generation MUST still succeed (proving zero state pollution!)
  assert_eq(
    alice.process_message(legit_msg),
    @group.ProcessedMessage::Application(3U, b"legit-after-attacks", b"ok"),
  )
  // 9e. Same-generation replay of legit_msg MUST fail with ReplayDetected
  let mut got_replay = false
  try {
    let _ = alice.process_message(legit_msg)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(_)) =>
      got_replay = true
    _ => fail("expected ReplayDetected on same-generation replay")
  }
  assert_true(got_replay)
  // 9f. Old epoch Commit replay MUST fail with EpochMismatch
  let mut got_old_commit = false
  try {
    let _ = alice.process_message(c5.commit_msg)
  } catch {
    @group.GroupError::EpochMismatch(6UL, 4UL) => got_old_commit = true
    _ => fail("expected EpochMismatch on old Commit replay")
  }
  assert_true(got_old_commit)
  // 9g. Subsequent legitimate message still works cleanly
  let follow_up = dave.protect_application(b"still-healthy", b"", rng)
  assert_eq(
    alice.process_message(follow_up),
    @group.ProcessedMessage::Application(3U, b"still-healthy", b""),
  )
}

///|
test "end-to-end 5-member lifecycle CS1 (AES-128-GCM)" {
  run_full_lifecycle_for_cs(
    @cs.CipherSuite::X25519Aes128GcmSha256Ed25519,
    b"lifecycle-cs1-seed",
  )
}

///|
test "end-to-end 5-member lifecycle CS3 (ChaCha20-Poly1305)" {
  run_full_lifecycle_for_cs(
    @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519,
    b"lifecycle-cs3-seed",
  )
}

///|
test "KeyPackage validation & error handling" {
  let cs1 = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let cs3 = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"kp-validation-seed")
  let bundle = @group.KeyPackageBundle::generate(cs1, b"alice", rng)
  let kp = bundle.key_package
  @group.verify_key_package(cs1, kp)
  // Wrong cipher suite
  let mut err_cs = false
  try @group.verify_key_package(cs3, kp) catch {
    @group.GroupError::CipherSuiteMismatch => err_cs = true
    _ => fail("expected CipherSuiteMismatch")
  }
  assert_true(err_cs)
  // Unsupported protocol version
  let bad_ver : @types.KeyPackage = {
    version: 2U,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: kp.leaf_node,
    extensions: kp.extensions,
    signature: kp.signature,
  }
  let mut err_ver = false
  try @group.verify_key_package(cs1, bad_ver) catch {
    @group.GroupError::UnsupportedProtocolVersion(2U) => err_ver = true
    _ => fail("expected UnsupportedProtocolVersion")
  }
  assert_true(err_ver)
  // init_key == leaf_node.encryption_key
  let same_key : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.leaf_node.encryption_key,
    leaf_node: kp.leaf_node,
    extensions: kp.extensions,
    signature: kp.signature,
  }
  let mut err_same = false
  try @group.verify_key_package(cs1, same_key) catch {
    @group.GroupError::InvalidKeyPackage(_) => err_same = true
    _ => fail("expected InvalidKeyPackage for init_key == encryption_key")
  }
  assert_true(err_same)
  // Tampered KeyPackage signature
  let bad_sig : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: kp.leaf_node,
    extensions: kp.extensions,
    signature: flip_byte_at(kp.signature, 0),
  }
  let mut err_sig = false
  try @group.verify_key_package(cs1, bad_sig) catch {
    @group.GroupError::InvalidKeyPackage(_) => err_sig = true
    _ => fail("expected InvalidKeyPackage for bad signature")
  }
  assert_true(err_sig)
  // CannotRemoveSelf check
  let alice = @group.MlsGroup::create_from_bundle(cs1, b"gid", bundle, rng)
  let mut err_self_rm = false
  try {
    let _ = alice.propose_remove(0U, rng)
  } catch {
    @group.GroupError::CannotRemoveSelf => err_self_rm = true
    _ => fail("expected CannotRemoveSelf")
  }
  assert_true(err_self_rm)
}

///|
test "from_welcome with external_tree fallback and self-update commit_pending" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"ext-tree-seed")
  let alice = @group.MlsGroup::create(cs, b"ext-gid", b"alice", rng)
  let bob_kp = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let out = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let welcome = match out.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  // Passing ratchet_tree_nodes explicitly also works
  let rt = alice.ratchet_tree_nodes()
  let bob = @group.MlsGroup::from_welcome(cs, welcome, bob_kp, Some(rt))
  assert_group_sync([alice, bob], 1UL)
  // Self-update + commit_pending (RFC 9420 §12.2 omits redundant self-Update and rotates via UpdatePath)
  let old_auth = alice.epoch_authenticator()
  let upd_msg = alice.propose_update(rng)
  let _ = bob.process_message(upd_msg)
  let c2 = alice.commit_pending(rng)
  assert_eq(c2.new_epoch, 2UL)
  assert_eq(
    bob.process_message(c2.commit_msg),
    @group.ProcessedMessage::Commit(0U, 2UL),
  )
  assert_group_sync([alice, bob], 2UL)
  assert_true(alice.epoch_authenticator() != old_auth)
}

///|
test "blank leaf reuse across subtrees with unmerged_leaves and Welcome" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"blank-reuse-seed")
  let alice = @group.MlsGroup::create(cs, b"reuse-gid", b"alice", rng)
  let bob_kp = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let charlie_kp = @group.KeyPackageBundle::generate(cs, b"charlie", rng)
  let dave_kp = @group.KeyPackageBundle::generate(cs, b"dave", rng)
  let frank_kp = @group.KeyPackageBundle::generate(cs, b"frank", rng)
  // Add Bob (1), Charlie (2), Dave (3)
  let c1 = alice.commit(
    [
      @types.Proposal::Add(bob_kp.key_package),
      @types.Proposal::Add(charlie_kp.key_package),
      @types.Proposal::Add(dave_kp.key_package),
    ],
    rng,
  )
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = @group.MlsGroup::from_welcome(cs, w1, bob_kp, None)
  let charlie = @group.MlsGroup::from_welcome(cs, w1, charlie_kp, None)
  let dave = @group.MlsGroup::from_welcome(cs, w1, dave_kp, None)
  assert_group_sync([alice, bob, charlie, dave], 1UL)
  // Alice removes Bob (leaf 1), leaving a blank leaf in the left subtree
  let c2 = alice.commit([@types.Proposal::Remove(1U)], rng)
  assert_eq(
    charlie.process_message(c2.commit_msg),
    @group.ProcessedMessage::Commit(0U, 2UL),
  )
  assert_eq(
    dave.process_message(c2.commit_msg),
    @group.ProcessedMessage::Commit(0U, 2UL),
  )
  assert_group_sync([alice, charlie, dave], 2UL)
  // Charlie (right subtree, leaf 2) adds Frank -> reuses blank leaf 1 with unmerged_leaves
  let c3 = charlie.commit([@types.Proposal::Add(frank_kp.key_package)], rng)
  assert_eq(
    alice.process_message(c3.commit_msg),
    @group.ProcessedMessage::Commit(2U, 3UL),
  )
  assert_eq(
    dave.process_message(c3.commit_msg),
    @group.ProcessedMessage::Commit(2U, 3UL),
  )
  let w3 = match c3.welcome {
    Some(w) => w
    None => fail("expected Welcome for Frank")
  }
  let frank = @group.MlsGroup::from_welcome(cs, w3, frank_kp, None)
  assert_eq(frank.my_leaf_index(), 1U)
  assert_group_sync([alice, frank, charlie, dave], 3UL)
  // Alice (leaf 0, sibling of Frank) commits -> Frank decrypts via leaf key
  let c4 = alice.commit([], rng)
  assert_eq(
    frank.process_message(c4.commit_msg),
    @group.ProcessedMessage::Commit(0U, 4UL),
  )
  assert_eq(
    charlie.process_message(c4.commit_msg),
    @group.ProcessedMessage::Commit(0U, 4UL),
  )
  assert_eq(
    dave.process_message(c4.commit_msg),
    @group.ProcessedMessage::Commit(0U, 4UL),
  )
  assert_group_sync([alice, frank, charlie, dave], 4UL)
  // Frank sends application message and all 3 decrypt it
  let fm = frank.protect_application(b"frank-reused-leaf-1", b"ok", rng)
  assert_eq(
    alice.process_message(fm),
    @group.ProcessedMessage::Application(1U, b"frank-reused-leaf-1", b"ok"),
  )
  assert_eq(
    charlie.process_message(fm),
    @group.ProcessedMessage::Application(1U, b"frank-reused-leaf-1", b"ok"),
  )
  assert_eq(
    dave.process_message(fm),
    @group.ProcessedMessage::Application(1U, b"frank-reused-leaf-1", b"ok"),
  )
}
