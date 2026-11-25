///|
fn hex_prefix(data : Bytes, n_bytes : Int32) -> String {
  let take = if data.length() < n_bytes { data.length() } else { n_bytes }
  let slice = Bytes::makei(take, fn(i) { data[i] })
  @tls.bytes_to_hex(slice) + "..."
}

///|
fn ascii_bytes_to_string(data : Bytes) -> String {
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    buf.write_char(Int32::unsafe_to_char(data[i].to_int()))
  }
  buf.to_string()
}

///|
fn member_names(group : @mls.MlsGroup) -> String {
  let ms = group.members()
  let buf = StringBuilder()
  for i = 0; i < ms.length(); i = i + 1 {
    if i > 0 {
      buf.write_string(", ")
    }
    let (leaf, id) = ms[i]
    buf.write_string("\{ascii_bytes_to_string(id)}#\{leaf}")
  }
  buf.to_string()
}

///|
fn assert_cond(cond : Bool, msg : String) -> Unit raise Failure {
  if !cond {
    fail(msg)
  }
}

///|
fn verify_all_in_sync(
  label : String,
  members : Array[(String, @mls.MlsGroup)],
  expected_epoch : UInt64,
  export_ctx : Bytes,
) -> (Bytes, Bytes, Bytes) raise {
  assert_cond(members.length() > 0, "empty member list")
  let (_, first) = members[0]
  let ref_tree_hash = first.tree_hash()
  let ref_auth = first.epoch_authenticator()
  let ref_export = first.export_secret("moonmls-demo-key", export_ctx, 32)
  let ref_members = first.members()
  for i = 0; i < members.length(); i = i + 1 {
    let (name, g) = members[i]
    assert_cond(g.epoch() == expected_epoch, "\{label}: \{name} epoch mismatch")
    assert_cond(g.is_active(), "\{label}: \{name} should be active")
    assert_cond(
      g.tree_hash() == ref_tree_hash,
      "\{label}: \{name} tree_hash mismatch",
    )
    assert_cond(
      g.epoch_authenticator() == ref_auth,
      "\{label}: \{name} epoch_authenticator mismatch",
    )
    assert_cond(
      g.export_secret("moonmls-demo-key", export_ctx, 32) == ref_export,
      "\{label}: \{name} MLS-Exporter mismatch",
    )
    assert_cond(
      g.members() == ref_members,
      "\{label}: \{name} member roster mismatch",
    )
  }
  (ref_tree_hash, ref_auth, ref_export)
}

///|
fn run_demo() -> Unit raise {
  println(
    "====================================================================",
  )
  println(
    "  MoonMLS — Pure MoonBit, Zero-FFI, Sans-I/O RFC 9420 MLS Showcase  ",
  )
  println(
    "  5-Member Full Lifecycle | Forward Secrecy | PCS | Dual Suite      ",
  )
  println(
    "====================================================================",
  )
  println("")

  let cs1 = @mls.cs_x25519_aes128gcm()
  let rng = @mls.rng_from_seed(b"moonmls-2026-hackathon-demo-seed-cs1")
  let group_id = b"moonmls-demo-room"

  // ------------------------------------------------------------------
  // [1/7] Generate & verify 5 KeyPackageBundles
  // ------------------------------------------------------------------
  println("[1/7] KeyPackage Generation & Signature Verification (CS1: 0x0001)")
  let alice_kp = @mls.generate_key_package(cs1, b"Alice", rng)
  let bob_kp = @mls.generate_key_package(cs1, b"Bob", rng)
  let charlie_kp = @mls.generate_key_package(cs1, b"Charlie", rng)
  let dave_kp = @mls.generate_key_package(cs1, b"Dave", rng)
  let eve_kp = @mls.generate_key_package(cs1, b"Eve", rng)

  let kp_list : Array[(String, @mls.KeyPackageBundle)] = [
    ("Alice", alice_kp),
    ("Bob", bob_kp),
    ("Charlie", charlie_kp),
    ("Dave", dave_kp),
    ("Eve", eve_kp),
  ]
  for i = 0; i < kp_list.length(); i = i + 1 {
    let (name, bundle) = kp_list[i]
    @mls.verify_key_package(cs1, bundle.key_package)
    println(
      "  [PASS] \{name}: init_key=\{hex_prefix(bundle.key_package.init_key, 8)} sig_key=\{hex_prefix(bundle.key_package.leaf_node.signature_key, 8)}",
    )
  }
  println("")

  // ------------------------------------------------------------------
  // [2/7] 5-Member Group Onboarding: Epoch 0 -> Epoch 1 -> Epoch 2
  // ------------------------------------------------------------------
  println("[2/7] 5-Member Group Onboarding (Epoch 0 -> Epoch 1 -> Epoch 2)")
  let alice = @mls.create_group_from_bundle(cs1, group_id, alice_kp, rng)
  println(
    "  [PASS] Epoch \{alice.epoch()} | members=\{alice.members().length()} [\{member_names(alice)}] | tree_hash=\{hex_prefix(alice.tree_hash(), 8)}",
  )

  // Epoch 0 -> Epoch 1: Alice adds Bob & Charlie
  let c1 = alice.commit(
    [
      @types.Proposal::Add(bob_kp.key_package),
      @types.Proposal::Add(charlie_kp.key_package),
    ],
    rng,
  )
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("missing Welcome for Epoch 1")
  }
  let bob = @mls.join_group_from_welcome(cs1, w1, bob_kp, None)
  let charlie = @mls.join_group_from_welcome(cs1, w1, charlie_kp, None)
  let (th1, auth1, _) = verify_all_in_sync(
    "Epoch 1",
    [("Alice", alice), ("Bob", bob), ("Charlie", charlie)],
    1UL,
    b"epoch-1",
  )
  println(
    "  [PASS] Epoch \{alice.epoch()} | members=\{alice.members().length()} [\{member_names(alice)}] | tree_hash=\{hex_prefix(th1, 8)} auth=\{hex_prefix(auth1, 8)}",
  )

  // Capture an Epoch 1 ciphertext before advancing to Epoch 2 (for Step 4 FS check)
  let epoch1_msg = alice.protect_application(
    b"archived-epoch-1-secret", b"aad-e1", rng,
  )
  let e1_check = bob.process_message(epoch1_msg)
  assert_cond(
    e1_check
    is @group.ProcessedMessage::Application(
      0U,
      b"archived-epoch-1-secret",
      b"aad-e1",
    ),
    "Bob failed to decrypt Epoch 1 message",
  )

  // Epoch 1 -> Epoch 2: Bob adds Dave & Eve
  let c2 = bob.commit(
    [
      @types.Proposal::Add(dave_kp.key_package),
      @types.Proposal::Add(eve_kp.key_package),
    ],
    rng,
  )
  let a_c2 = alice.process_message(c2.commit_msg)
  let c_c2 = charlie.process_message(c2.commit_msg)
  assert_cond(
    a_c2 == @group.ProcessedMessage::Commit(1U, 2UL),
    "Alice Epoch 2 commit mismatch",
  )
  assert_cond(
    c_c2 == @group.ProcessedMessage::Commit(1U, 2UL),
    "Charlie Epoch 2 commit mismatch",
  )
  let w2 = match c2.welcome {
    Some(w) => w
    None => fail("missing Welcome for Epoch 2")
  }
  let dave = @mls.join_group_from_welcome(cs1, w2, dave_kp, None)
  let eve = @mls.join_group_from_welcome(cs1, w2, eve_kp, None)
  let all5 : Array[(String, @mls.MlsGroup)] = [
    ("Alice", alice),
    ("Bob", bob),
    ("Charlie", charlie),
    ("Dave", dave),
    ("Eve", eve),
  ]
  let (th2, auth2, exp2) = verify_all_in_sync(
    "Epoch 2", all5, 2UL, b"epoch-sync",
  )
  println(
    "  [PASS] Epoch \{alice.epoch()} | members=\{alice.members().length()} [\{member_names(alice)}]",
  )
  println(
    "  [PASS] 5/5 byte-identical sync: tree_hash=\{hex_prefix(th2, 10)} epoch_auth=\{hex_prefix(auth2, 10)} exporter=\{hex_prefix(exp2, 10)}",
  )
  println("")

  // ------------------------------------------------------------------
  // [3/7] 5-Member Encrypted Chat + Out-of-Order + Replay Window Defense
  // ------------------------------------------------------------------
  println(
    "[3/7] 5-Member Encrypted Group Chat, Out-of-Order Delivery & Replay Window",
  )
  let m0 = alice.protect_application(
    b"Hello everyone (msg #0)", b"room:general", rng,
  )
  let m1 = alice.protect_application(
    b"Second packet (msg #1)", b"room:general", rng,
  )
  let m2 = alice.protect_application(
    b"Arrived first! (msg #2)", b"room:general", rng,
  )

  // Deliver out-of-order: #2 -> #0 -> #1 to Bob, Charlie, Dave, Eve
  for i = 1; i < all5.length(); i = i + 1 {
    let (name, peer) = all5[i]
    let r2 = peer.process_message(m2)
    let r0 = peer.process_message(m0)
    let r1 = peer.process_message(m1)
    assert_cond(
      r2
      is @group.ProcessedMessage::Application(
        0U,
        b"Arrived first! (msg #2)",
        b"room:general",
      ),
      "\{name} failed out-of-order #2",
    )
    assert_cond(
      r0
      is @group.ProcessedMessage::Application(
        0U,
        b"Hello everyone (msg #0)",
        b"room:general",
      ),
      "\{name} failed out-of-order #0",
    )
    assert_cond(
      r1
      is @group.ProcessedMessage::Application(
        0U,
        b"Second packet (msg #1)",
        b"room:general",
      ),
      "\{name} failed out-of-order #1",
    )
  }
  println(
    "  [PASS] Out-of-order delivery (#2 -> #0 -> #1) decrypted by Bob, Charlie, Dave, Eve",
  )

  // Peer-to-peer broadcast check
  let bob_chat = bob.protect_application(b"Bob online in Epoch 2", b"chat", rng)
  let eve_chat = eve.protect_application(b"Eve checking in", b"chat", rng)
  for i = 0; i < all5.length(); i = i + 1 {
    let (name, peer) = all5[i]
    if i != 1 {
      let rb = peer.process_message(bob_chat)
      assert_cond(
        rb
        is @group.ProcessedMessage::Application(
          1U,
          b"Bob online in Epoch 2",
          b"chat",
        ),
        "\{name} failed Bob chat",
      )
    }
    if i != 4 {
      let re = peer.process_message(eve_chat)
      assert_cond(
        re
        is @group.ProcessedMessage::Application(4U, b"Eve checking in", b"chat"),
        "\{name} failed Eve chat",
      )
    }
  }
  println(
    "  [PASS] Bidirectional 5-member AEAD group chat verified across all peers",
  )

  // Same-generation replay attack
  let mut same_gen_blocked = false
  try {
    let _ = bob.process_message(m1)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(gen)) => {
      same_gen_blocked = true
      println(
        "  [BLOCKED] Same-generation replay (Alice msg #1 -> Bob) rejected: ReplayDetected(gen=\{gen})",
      )
    }
    other => fail("unexpected error on replay: \{other}")
  }
  assert_cond(same_gen_blocked, "same-generation replay must be blocked")
  println("")

  // ------------------------------------------------------------------
  // [4/7] Forward Secrecy (FS) Proof
  // ------------------------------------------------------------------
  println(
    "[4/7] Forward Secrecy (FS) Proof — One-Time Key Erasure & Cross-Epoch Isolation",
  )
  let mut gen0_erased = false
  try {
    let _ = charlie.process_message(m0)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(gen)) => {
      gen0_erased = true
      println(
        "  [BLOCKED] Consumed generation key (gen=\{gen}) destroyed on use: ReplayDetected(gen=\{gen})",
      )
    }
    other => fail("expected ReplayDetected for gen 0: \{other}")
  }
  assert_cond(gen0_erased, "consumed gen 0 key must be erased")

  let mut cross_epoch_blocked = false
  try {
    let _ = charlie.process_message(epoch1_msg)
  } catch {
    @group.GroupError::EpochMismatch(cur, got) => {
      cross_epoch_blocked = true
      println(
        "  [BLOCKED] Epoch 1 ciphertext replayed in Epoch 2 rejected: EpochMismatch(current=\{cur}, msg=\{got})",
      )
    }
    other => fail("expected EpochMismatch for Epoch 1 msg: \{other}")
  }
  assert_cond(cross_epoch_blocked, "cross-epoch replay must be blocked")
  println("")

  // ------------------------------------------------------------------
  // [5/7] Key Rotation & Post-Compromise Security (PCS): Epoch 2 -> Epoch 3
  // ------------------------------------------------------------------
  println(
    "[5/7] Key Rotation & Post-Compromise Security (PCS) — Charlie Update + Commit",
  )
  let upd_prop = charlie.propose_update(rng)
  for i = 0; i < all5.length(); i = i + 1 {
    if i != 2 {
      let (name, peer) = all5[i]
      let pr = peer.process_message(upd_prop)
      assert_cond(
        pr is @group.ProcessedMessage::Proposal(2U, @types.Proposal::Update(_)),
        "\{name} failed Update proposal",
      )
    }
  }
  let c3 = charlie.commit_pending(rng)
  assert_cond(c3.new_epoch == 3UL, "expected Epoch 3")
  for i = 0; i < all5.length(); i = i + 1 {
    if i != 2 {
      let (name, peer) = all5[i]
      let cr = peer.process_message(c3.commit_msg)
      assert_cond(
        cr == @group.ProcessedMessage::Commit(2U, 3UL),
        "\{name} failed Epoch 3 commit",
      )
    }
  }
  let (th3, auth3, exp3) = verify_all_in_sync(
    "Epoch 3", all5, 3UL, b"epoch-sync",
  )
  assert_cond(th3 != th2, "PCS failed: tree_hash unchanged")
  assert_cond(auth3 != auth2, "PCS failed: epoch_authenticator unchanged")
  assert_cond(exp3 != exp2, "PCS failed: exporter secret unchanged")
  println(
    "  [PASS] Epoch 2 -> Epoch 3 TreeKEM UpdatePath rotated by Charlie (members=5)",
  )
  println(
    "         Epoch 2: tree_hash=\{hex_prefix(th2, 10)} auth=\{hex_prefix(auth2, 10)} exp=\{hex_prefix(exp2, 10)}",
  )
  println(
    "         Epoch 3: tree_hash=\{hex_prefix(th3, 10)} auth=\{hex_prefix(auth3, 10)} exp=\{hex_prefix(exp3, 10)}",
  )
  println(
    "  [PASS] All 3 cryptographic fingerprints completely independent (PCS verified)",
  )

  // Capture an Eve Epoch 3 message before removal
  let eve_epoch3_msg = eve.protect_application(b"eve-last-word-e3", b"e3", rng)
  println("")

  // ------------------------------------------------------------------
  // [6/7] Dynamic Member Removal: Alice Remove(Eve) + Commit -> Epoch 4
  // ------------------------------------------------------------------
  println(
    "[6/7] Dynamic Member Removal — Alice Remove(Eve#4) + Commit (Epoch 3 -> Epoch 4)",
  )
  let c4 = alice.commit([@types.Proposal::Remove(4U)], rng)
  assert_cond(c4.new_epoch == 4UL, "expected Epoch 4")
  let rem4 : Array[(String, @mls.MlsGroup)] = [
    ("Alice", alice),
    ("Bob", bob),
    ("Charlie", charlie),
    ("Dave", dave),
  ]
  for i = 1; i < rem4.length(); i = i + 1 {
    let (name, peer) = rem4[i]
    let cr = peer.process_message(c4.commit_msg)
    assert_cond(
      cr == @group.ProcessedMessage::Commit(0U, 4UL),
      "\{name} failed Epoch 4 commit",
    )
  }
  let (th4, auth4, exp4) = verify_all_in_sync(
    "Epoch 4", rem4, 4UL, b"epoch-sync",
  )
  assert_cond(alice.members().length() == 4, "expected 4 remaining members")
  println(
    "  [PASS] Epoch \{alice.epoch()} | members=\{alice.members().length()} [\{member_names(alice)}]",
  )
  println(
    "  [PASS] New secrets after removal: tree_hash=\{hex_prefix(th4, 10)} auth=\{hex_prefix(auth4, 10)} exp=\{hex_prefix(exp4, 10)}",
  )

  // Eve receives Commit -> MemberRemoved
  let mut eve_removed = false
  try {
    let _ = eve.process_message(c4.commit_msg)
  } catch {
    @group.GroupError::MemberRemoved => {
      eve_removed = true
      println(
        "  [BLOCKED] Eve processed removal Commit -> MemberRemoved (active=\{eve.is_active()})",
      )
    }
    other => fail("expected MemberRemoved for Eve: \{other}")
  }
  assert_cond(
    eve_removed && !eve.is_active(),
    "Eve must be inactive after removal",
  )

  // Remaining 4 members continue chatting in Epoch 4
  let post_rm_msg = dave.protect_application(
    b"Confidential Epoch 4 message (no Eve)", b"e4", rng,
  )
  for i = 0; i < rem4.length(); i = i + 1 {
    if i != 3 {
      let (name, peer) = rem4[i]
      let r = peer.process_message(post_rm_msg)
      assert_cond(
        r
        is @group.ProcessedMessage::Application(
          3U,
          b"Confidential Epoch 4 message (no Eve)",
          b"e4",
        ),
        "\{name} failed Epoch 4 post-removal msg",
      )
    }
  }
  println(
    "  [PASS] Remaining 4 members (Alice, Bob, Charlie, Dave) communicate cleanly in Epoch 4",
  )

  // Eve cannot decrypt Epoch 4 message
  let mut eve_cant_read = false
  try {
    let _ = eve.process_message(post_rm_msg)
  } catch {
    @group.GroupError::MemberRemoved => {
      eve_cant_read = true
      println("  [BLOCKED] Eve cannot decrypt Epoch 4 message: MemberRemoved")
    }
    other =>
      fail("expected MemberRemoved when Eve decrypts Epoch 4 msg: \{other}")
  }
  assert_cond(eve_cant_read, "Eve must not decrypt Epoch 4 message")

  // Eve's forged Epoch 4 message (re-stamped Epoch 3 ciphertext) is rejected by Alice
  let eve_forged_e4 : @types.PrivateMessage = {
    group_id: eve_epoch3_msg.group_id,
    epoch: 4UL,
    content_type: eve_epoch3_msg.content_type,
    authenticated_data: eve_epoch3_msg.authenticated_data,
    encrypted_sender_data: eve_epoch3_msg.encrypted_sender_data,
    ciphertext: eve_epoch3_msg.ciphertext,
  }
  let mut eve_forged_blocked = false
  try {
    let _ = alice.process_message(eve_forged_e4)
  } catch {
    @group.GroupError::ScheduleError(se) => {
      eve_forged_blocked = true
      println(
        "  [BLOCKED] Eve forged Epoch 4 message rejected by Alice: ScheduleError(\{se})",
      )
    }
    other => fail("expected ScheduleError on Eve forged msg: \{other}")
  }
  assert_cond(eve_forged_blocked, "Eve forged Epoch 4 message must be rejected")
  println("")

  // ------------------------------------------------------------------
  // [7/7] Dual CipherSuite CS3 Self-Check (ChaCha20-Poly1305)
  // ------------------------------------------------------------------
  println(
    "[7/7] Dual CipherSuite CS3 Self-Check (0x0003: X25519 + ChaCha20-Poly1305 + SHA-256 + Ed25519)",
  )
  let cs3 = @mls.cs_x25519_chacha20poly1305()
  let rng3 = @mls.rng_from_seed(b"moonmls-2026-hackathon-demo-seed-cs3")
  let a3 = @mls.create_group(cs3, b"moonmls-cs3-room", b"Alice", rng3)
  let b3_kp = @mls.generate_key_package(cs3, b"Bob", rng3)
  let c3_kp = @mls.generate_key_package(cs3, b"Charlie", rng3)
  @mls.verify_key_package(cs3, b3_kp.key_package)
  @mls.verify_key_package(cs3, c3_kp.key_package)
  let cs3_c1 = a3.commit(
    [
      @types.Proposal::Add(b3_kp.key_package),
      @types.Proposal::Add(c3_kp.key_package),
    ],
    rng3,
  )
  let cs3_w1 = match cs3_c1.welcome {
    Some(w) => w
    None => fail("missing CS3 Welcome")
  }
  let b3 = @mls.join_group_from_welcome(cs3, cs3_w1, b3_kp, None)
  let ch3 = @mls.join_group_from_welcome(cs3, cs3_w1, c3_kp, None)
  let (cs3_th, cs3_auth, cs3_exp) = verify_all_in_sync(
    "CS3 Epoch 1",
    [("Alice", a3), ("Bob", b3), ("Charlie", ch3)],
    1UL,
    b"cs3-check",
  )
  let cs3_msg = b3.protect_application(
    b"ChaCha20-Poly1305 E2EE works!", b"cs3", rng3,
  )
  assert_cond(
    a3.process_message(cs3_msg)
    is @group.ProcessedMessage::Application(
      1U,
      b"ChaCha20-Poly1305 E2EE works!",
      b"cs3",
    ),
    "CS3 Alice decrypt failed",
  )
  assert_cond(
    ch3.process_message(cs3_msg)
    is @group.ProcessedMessage::Application(
      1U,
      b"ChaCha20-Poly1305 E2EE works!",
      b"cs3",
    ),
    "CS3 Charlie decrypt failed",
  )
  // CS3 PCS rotation
  let cs3_c2 = ch3.commit([], rng3)
  assert_cond(
    a3.process_message(cs3_c2.commit_msg) ==
    @group.ProcessedMessage::Commit(2U, 2UL),
    "CS3 Alice Epoch 2 commit failed",
  )
  assert_cond(
    b3.process_message(cs3_c2.commit_msg) ==
    @group.ProcessedMessage::Commit(2U, 2UL),
    "CS3 Bob Epoch 2 commit failed",
  )
  let (_, cs3_auth2, _) = verify_all_in_sync(
    "CS3 Epoch 2",
    [("Alice", a3), ("Bob", b3), ("Charlie", ch3)],
    2UL,
    b"cs3-check",
  )
  assert_cond(
    cs3_auth2 != cs3_auth,
    "CS3 epoch_authenticator must change after Commit",
  )
  println(
    "  [PASS] CS3 3-member onboarding + ChaCha20-Poly1305 AEAD chat + PCS Commit verified",
  )
  println(
    "         Epoch 1: tree_hash=\{hex_prefix(cs3_th, 10)} auth=\{hex_prefix(cs3_auth, 10)} exp=\{hex_prefix(cs3_exp, 10)}",
  )
  println("         Epoch 2: auth=\{hex_prefix(cs3_auth2, 10)} (rotated)")
  println("")
  println(
    "====================================================================",
  )
  println(
    "  ALL 7 SCENARIOS PASSED — MoonMLS Ready Across wasm-gc/js/native   ",
  )
  println(
    "====================================================================",
  )
}

///|
fn main {
  run_demo() catch {
    e => {
      println("DEMO FAILED: \{e}")
      abort("MoonMLS demo failed")
    }
  }
}
