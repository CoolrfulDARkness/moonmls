///|
fn sec_flip_bit(data : Bytes, byte_idx : Int32, mask : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == byte_idx {
      (data[i].to_int() ^ mask).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn sec_flip_last_bit(data : Bytes) -> Bytes {
  sec_flip_bit(data, data.length() - 1, 0x01)
}

///|
fn sec_add_le256(a : Bytes, b : Bytes) -> Bytes {
  let out = FixedArray::make(32, b'\x00')
  let mut carry = 0
  for i = 0; i < 32; i = i + 1 {
    let sum = a[i].to_int() + b[i].to_int() + carry
    out[i] = (sum & 0xFF).to_byte()
    carry = sum >> 8
  }
  Bytes::makei(32, fn(i) { out[i] })
}

///|
/// Creates a synchronized 2-member (Alice=0, Bob=1) group at epoch 1 and
/// returns `(alice, bob, alice_bundle, bob_bundle, welcome, rng)`.
fn setup_two_member_group(
  cs : @cs.CipherSuite,
  group_id : Bytes,
  seed : Bytes,
) -> (
  @group.MlsGroup,
  @group.MlsGroup,
  @group.KeyPackageBundle,
  @group.KeyPackageBundle,
  @types.Welcome,
  @crypto.DeterministicRng,
) raise {
  let rng = @crypto.DeterministicRng::from_seed(seed)
  let alice_bundle = @group.KeyPackageBundle::generate(cs, b"alice", rng)
  let bob_bundle = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let alice = @group.MlsGroup::create_from_bundle(
    cs, group_id, alice_bundle, rng,
  )
  let _ = alice.propose_add(bob_bundle.key_package, rng)
  let out = alice.commit_pending(rng)
  let welcome = match out.welcome {
    Some(w) => w
    None => fail("expected Welcome for Bob")
  }
  let bob = @group.MlsGroup::from_welcome(cs, welcome, bob_bundle, None)
  assert_eq(alice.epoch(), 1UL)
  assert_eq(bob.epoch(), 1UL)
  assert_eq(alice.epoch_authenticator(), bob.epoch_authenticator())
  (alice, bob, alice_bundle, bob_bundle, welcome, rng)
}

///|
/// Creates a synchronized 3-member (Alice=0, Bob=1, Charlie=2) group at epoch 2.
fn setup_three_member_group(
  cs : @cs.CipherSuite,
  group_id : Bytes,
  seed : Bytes,
) -> (
  @group.MlsGroup,
  @group.MlsGroup,
  @group.MlsGroup,
  @crypto.DeterministicRng,
) raise {
  let (alice, bob, _ab, _bb, _w1, rng) = setup_two_member_group(
    cs, group_id, seed,
  )
  let charlie_bundle = @group.KeyPackageBundle::generate(cs, b"charlie", rng)
  let prop_c = alice.propose_add(charlie_bundle.key_package, rng)
  let _ = bob.process_message(prop_c)
  let out2 = alice.commit_pending(rng)
  let _ = bob.process_message(out2.commit_msg)
  let welcome_c = match out2.welcome {
    Some(w) => w
    None => fail("expected Welcome for Charlie")
  }
  let charlie = @group.MlsGroup::from_welcome(
    cs,
    welcome_c,
    charlie_bundle,
    None,
  )
  assert_eq(alice.epoch(), 2UL)
  assert_eq(bob.epoch(), 2UL)
  assert_eq(charlie.epoch(), 2UL)
  assert_eq(alice.epoch_authenticator(), charlie.epoch_authenticator())
  (alice, bob, charlie, rng)
}

///|
/// Re-packages a `GroupInfo` and `GroupSecrets` into a freshly AEAD/HPKE-sealed
/// `Welcome` addressed to `bob_bundle.key_package` (used to test inner Welcome
/// validation after outer AEAD/HPKE decryption succeeds).
fn repackage_welcome(
  cs : @cs.CipherSuite,
  group_info : @types.GroupInfo,
  group_secrets : @types.GroupSecrets,
  bob_kp : @types.KeyPackage,
  rng : @crypto.DeterministicRng,
) -> @types.Welcome raise {
  let welcome_secret = @schedule.derive_welcome_secret(
    cs,
    group_secrets.joiner_secret,
    cs.zero_secret(),
  )
  let (w_key, w_nonce) = @schedule.derive_welcome_key_nonce(cs, welcome_secret)
  let encrypted_group_info = cs.aead_seal(
    w_key,
    w_nonce,
    b"",
    group_info.to_bytes(),
  )
  let kp_ref = cs.make_key_package_ref(bob_kp.to_bytes())
  let (kem_output, ciphertext) = cs.encrypt_with_label(
    bob_kp.init_key,
    "Welcome",
    encrypted_group_info,
    group_secrets.to_bytes(),
    rng,
  )
  {
    cipher_suite: cs.id(),
    secrets: [
      {
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output, ciphertext, },
      },
    ],
    encrypted_group_info,
  }
}

///|
test "SEC-01: Old epoch application message replay rejected with EpochMismatch and zero state pollution" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-01-gid", b"sec-01-seed",
  )
  let old_msg = alice.protect_application(b"epoch-1-payload", b"aad-1", rng)
  // Advance both members to epoch 2
  let out2 = alice.commit_pending(rng)
  let _ = bob.process_message(out2.commit_msg)
  assert_eq(bob.epoch(), 2UL)
  let auth_before = bob.epoch_authenticator()
  let th_before = bob.tree_hash()
  // Replay epoch-1 application message at epoch 2
  let mut got_err = false
  try {
    let _ = bob.process_message(old_msg)
  } catch {
    @group.GroupError::EpochMismatch(2UL, 1UL) => got_err = true
    _ => fail("expected EpochMismatch(2, 1)")
  }
  assert_true(got_err)
  // Verify zero state pollution and normal epoch-2 operation
  assert_eq(bob.epoch(), 2UL)
  assert_eq(bob.epoch_authenticator(), auth_before)
  assert_eq(bob.tree_hash(), th_before)
  assert_true(bob.is_active())
  let ep2_msg = alice.protect_application(b"epoch-2-ok", b"aad-2", rng)
  assert_true(
    bob.process_message(ep2_msg) is Application(0U, b"epoch-2-ok", b"aad-2"),
  )
}

///|
test "SEC-02: Future epoch forged message injection rejected with EpochMismatch" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-02-gid", b"sec-02-seed",
  )
  let legit = alice.protect_application(b"valid-ep1", b"", rng)
  let future_2 : @types.PrivateMessage = {
    group_id: legit.group_id,
    epoch: 2UL,
    content_type: legit.content_type,
    authenticated_data: legit.authenticated_data,
    encrypted_sender_data: legit.encrypted_sender_data,
    ciphertext: legit.ciphertext,
  }
  let future_999 : @types.PrivateMessage = {
    group_id: legit.group_id,
    epoch: 999UL,
    content_type: legit.content_type,
    authenticated_data: legit.authenticated_data,
    encrypted_sender_data: legit.encrypted_sender_data,
    ciphertext: legit.ciphertext,
  }
  let mut err2 = false
  try {
    let _ = bob.process_message(future_2)
  } catch {
    @group.GroupError::EpochMismatch(1UL, 2UL) => err2 = true
    _ => fail("expected EpochMismatch(1, 2)")
  }
  assert_true(err2)
  let mut err999 = false
  try {
    let _ = bob.process_message(future_999)
  } catch {
    @group.GroupError::EpochMismatch(1UL, 999UL) => err999 = true
    _ => fail("expected EpochMismatch(1, 999)")
  }
  assert_true(err999)
  // Original valid epoch-1 message must still succeed (no state pollution)
  assert_true(bob.process_message(legit) is Application(0U, b"valid-ep1", b""))
}

///|
test "SEC-03: Same-epoch same-generation message replay rejected with ReplayDetected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-03-gid", b"sec-03-seed",
  )
  let m0 = alice.protect_application(b"msg-gen-0", b"a0", rng)
  let m1 = alice.protect_application(b"msg-gen-1", b"a1", rng)
  let m2 = alice.protect_application(b"msg-gen-2", b"a2", rng)
  assert_true(bob.process_message(m0) is Application(0U, b"msg-gen-0", b"a0"))
  assert_true(bob.process_message(m1) is Application(0U, b"msg-gen-1", b"a1"))
  // Replay gen 0 -> ReplayDetected(0U)
  let mut r0 = false
  try {
    let _ = bob.process_message(m0)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(0U)) =>
      r0 = true
    _ => fail("expected ReplayDetected(0)")
  }
  assert_true(r0)
  // Replay gen 1 -> ReplayDetected(1U)
  let mut r1 = false
  try {
    let _ = bob.process_message(m1)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(1U)) =>
      r1 = true
    _ => fail("expected ReplayDetected(1)")
  }
  assert_true(r1)
  // Also test handshake ratchet replay (Proposal gen 0)
  let prop = alice.propose_update(rng)
  assert_true(bob.process_message(prop) is Proposal(0U, _))
  let mut r_hs = false
  try {
    let _ = bob.process_message(prop)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(0U)) =>
      r_hs = true
    _ => fail("expected ReplayDetected(0) on handshake replay")
  }
  assert_true(r_hs)
  // Next valid generation still works
  assert_true(bob.process_message(m2) is Application(0U, b"msg-gen-2", b"a2"))
}

///|
test "SEC-04: Expired generation beyond out-of-order window rejected with ReplayDetected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-04-gid", b"sec-04-seed",
  )
  // Default out_of_order_tolerance = 16; send gens 0..19 (20 messages)
  let msgs : Array[@types.PrivateMessage] = []
  for i = 0; i < 20; i = i + 1 {
    msgs.push(alice.protect_application(b"ooo-msg", b"", rng))
  }
  // Deliver gen 19 first -> caches gens 3..18, evicts gens 0..2
  assert_true(bob.process_message(msgs[19]) is Application(0U, b"ooo-msg", b""))
  // Boundary gen 3 is still within window and decrypts exactly once
  assert_true(bob.process_message(msgs[3]) is Application(0U, b"ooo-msg", b""))
  let mut r3 = false
  try {
    let _ = bob.process_message(msgs[3])
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(3U)) =>
      r3 = true
    _ => fail("expected ReplayDetected(3) on second use")
  }
  assert_true(r3)
  // Gens 0, 1, 2 fell outside the window -> must all fail with ReplayDetected
  for g = 0; g < 3; g = g + 1 {
    let mut expired = false
    try {
      let _ = bob.process_message(msgs[g])
    } catch {
      @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(gen)) =>
        expired = gen == g.reinterpret_as_uint()
      _ => fail("expected ReplayDetected for expired generation")
    }
    assert_true(expired)
  }
}

///|
test "SEC-05: Excessive forward generation jump DoS rejected with GenerationTooFarAhead" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  // Layer 1: SecretTree direct check
  let st = @tree.SecretTree::new(cs, Bytes::make(32, b'\x42'), 4U)
  let mut st_app_err = false
  try {
    let _ = st.application_key_nonce_for_generation(0U, 1001U)
  } catch {
    @tree.TreeError::GenerationTooFarAhead(1001U) => st_app_err = true
    _ => fail("expected GenerationTooFarAhead(1001)")
  }
  assert_true(st_app_err)
  let mut st_hs_err = false
  try {
    let _ = st.handshake_key_nonce_for_generation(1U, 0xFFFFFFFFU)
  } catch {
    @tree.TreeError::GenerationTooFarAhead(0xFFFFFFFFU) => st_hs_err = true
    _ => fail("expected GenerationTooFarAhead(0xFFFFFFFF)")
  }
  assert_true(st_hs_err)
  // Layer 2: End-to-end MlsGroup::process_message DoS attack with crafted sender_data (gen = 50000)
  let (alice, bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-05-gid", b"sec-05-seed",
  )
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  let fake_ct = Bytes::make(48, b'\xAA')
  let (sd_key, sd_nonce) = @schedule.derive_sender_data_key_nonce(
    cs,
    verified.secrets.sender_data_secret,
    fake_ct,
  )
  let dos_sd : @types.MlsSenderData = {
    leaf_index: 0U,
    generation: 50000U,
    reuse_guard: b"\x01\x02\x03\x04",
  }
  let sd_aad : @types.MlsSenderDataAad = {
    group_id: b"sec-05-gid",
    epoch: 1UL,
    content_type: @types.ContentType::Application,
  }
  let enc_sd = cs.aead_seal(
    sd_key,
    sd_nonce,
    sd_aad.to_bytes(),
    dos_sd.to_bytes(),
  )
  let dos_msg : @types.PrivateMessage = {
    group_id: b"sec-05-gid",
    epoch: 1UL,
    content_type: @types.ContentType::Application,
    authenticated_data: b"",
    encrypted_sender_data: enc_sd,
    ciphertext: fake_ct,
  }
  let mut group_dos_err = false
  try {
    let _ = bob.process_message(dos_msg)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::GenerationTooFarAhead(50000U)) =>
      group_dos_err = true
    _ => fail("expected GenerationTooFarAhead(50000) in MlsGroup")
  }
  assert_true(group_dos_err)
  // Honest gen-0 message from Alice still works with zero state pollution
  let ok_msg = alice.protect_application(b"still-alive", b"", rng)
  assert_true(
    bob.process_message(ok_msg) is Application(0U, b"still-alive", b""),
  )
}

///|
test "SEC-06: 1-bit Commit ciphertext tamper rejected with zero state pollution and subsequent valid Commit succeeds" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-06-gid", b"sec-06-seed",
  )
  let auth_ep1 = bob.epoch_authenticator()
  let th_ep1 = bob.tree_hash()
  let out2 = alice.commit_pending(rng)
  // Flip 1 bit at end of ciphertext (AEAD tag)
  let bad_end : @types.PrivateMessage = {
    group_id: out2.commit_msg.group_id,
    epoch: out2.commit_msg.epoch,
    content_type: out2.commit_msg.content_type,
    authenticated_data: out2.commit_msg.authenticated_data,
    encrypted_sender_data: out2.commit_msg.encrypted_sender_data,
    ciphertext: sec_flip_last_bit(out2.commit_msg.ciphertext),
  }
  // Flip 1 bit at byte 0 of ciphertext (also breaks sender_data sample derivation)
  let bad_start : @types.PrivateMessage = {
    group_id: out2.commit_msg.group_id,
    epoch: out2.commit_msg.epoch,
    content_type: out2.commit_msg.content_type,
    authenticated_data: out2.commit_msg.authenticated_data,
    encrypted_sender_data: out2.commit_msg.encrypted_sender_data,
    ciphertext: sec_flip_bit(out2.commit_msg.ciphertext, 0, 0x01),
  }
  for tampered in [bad_end, bad_start] {
    let mut rejected = false
    try {
      let _ = bob.process_message(tampered)
    } catch {
      @group.GroupError::ScheduleError(
        @schedule.ScheduleError::DecryptionFailed,
      ) => rejected = true
      _ => fail("expected DecryptionFailed on 1-bit tampered Commit")
    }
    assert_true(rejected)
    assert_eq(bob.epoch(), 1UL)
    assert_eq(bob.epoch_authenticator(), auth_ep1)
    assert_eq(bob.tree_hash(), th_ep1)
  }
  // Now deliver the authentic Commit -> must cleanly advance Bob to epoch 2
  assert_true(bob.process_message(out2.commit_msg) is Commit(0U, 2UL))
  assert_eq(bob.epoch(), 2UL)
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
  assert_eq(bob.tree_hash(), alice.tree_hash())
}

///|
test "SEC-07: 1-bit Commit ConfirmationTag tamper triggers ConfirmationTagMismatch with zero state pollution" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-07-gid", b"sec-07-seed",
  )
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  // Layer 1: verify_confirmation_tag directly rejects 1-bit flip
  assert_true(
    @schedule.verify_confirmation_tag(
      cs,
      verified.secrets.confirmation_key,
      verified.group_info.group_context.confirmed_transcript_hash,
      verified.group_info.confirmation_tag,
    ),
  )
  assert_false(
    @schedule.verify_confirmation_tag(
      cs,
      verified.secrets.confirmation_key,
      verified.group_info.group_context.confirmed_transcript_hash,
      sec_flip_last_bit(verified.group_info.confirmation_tag),
    ),
  )
  // Layer 2: Forge a validly signed & encrypted Commit PrivateMessage with 1-bit flipped confirmation_tag
  let auth_ep1 = bob.epoch_authenticator()
  let th_ep1 = bob.tree_hash()
  let out2 = alice.commit_pending(rng)
  let sd = @schedule.decrypt_sender_data(
    cs,
    verified.secrets.sender_data_secret,
    out2.commit_msg,
  )
  let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
  let (hs_key, hs_nonce) = st.handshake_key_nonce_for_generation(
    sd.leaf_index,
    sd.generation,
  )
  let ac = @schedule.decrypt_private_message_with_keys(
    cs,
    alice_bundle.key_package.leaf_node.signature_key,
    verified.group_info.group_context,
    sd,
    hs_key,
    hs_nonce,
    out2.commit_msg,
  )
  let real_tag = match ac.auth.confirmation_tag {
    Some(t) => t
    None => fail("Commit must carry confirmation_tag")
  }
  let bad_auth : @types.FramedContentAuthData = {
    signature: ac.auth.signature,
    confirmation_tag: Some(sec_flip_last_bit(real_tag)),
  }
  let forged_commit_msg = @schedule.encrypt_private_message_with_keys(
    cs,
    verified.secrets.sender_data_secret,
    sd,
    hs_key,
    hs_nonce,
    ac.content,
    bad_auth,
    0,
  )
  let mut got_conf_err = false
  try {
    let _ = bob.process_message(forged_commit_msg)
  } catch {
    @group.GroupError::ConfirmationTagMismatch => got_conf_err = true
    _ =>
      fail("expected ConfirmationTagMismatch on forged Commit confirmation_tag")
  }
  assert_true(got_conf_err)
  // Zero state pollution: Bob still at epoch 1 and genuine Commit succeeds
  assert_eq(bob.epoch(), 1UL)
  assert_eq(bob.epoch_authenticator(), auth_ep1)
  assert_eq(bob.tree_hash(), th_ep1)
  assert_true(bob.process_message(out2.commit_msg) is Commit(0U, 2UL))
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
}

///|
test "SEC-08: PublicMessage MembershipTag tamper / strip / spurious tag rejected with InvalidMembershipTag" {
  let suites = [
    @cs.CipherSuite::X25519Aes128GcmSha256Ed25519,
    @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519,
  ]
  for s_i = 0; s_i < suites.length(); s_i = s_i + 1 {
    let cs = suites[s_i]
    let rng = @crypto.DeterministicRng::from_seed(b"sec-08-seed")
    let (sig_priv, sig_pub) = cs.signature_keypair_from_seed(rng.next_bytes(32))
    let membership_key = rng.next_bytes(32)
    let gc : @types.GroupContext = {
      version: @types.PROTOCOL_VERSION_MLS10,
      cipher_suite: cs.id(),
      group_id: b"sec-08-gid",
      epoch: 3UL,
      tree_hash: Bytes::make(32, b'\x11'),
      confirmed_transcript_hash: Bytes::make(32, b'\x22'),
      extensions: [],
    }
    let fc : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(0U),
      authenticated_data: b"meta",
      content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(1U)),
    }
    let pm = @schedule.protect_public_message(
      cs,
      sig_priv,
      Some(membership_key),
      fc,
      Some(gc),
      None,
    )
    // Valid passes
    let _ = @schedule.unprotect_public_message(
      cs,
      sig_pub,
      Some(membership_key),
      pm,
      Some(gc),
    )
    // 1. Flip 1 bit in membership_tag
    let bad_tag = match pm.membership_tag {
      Some(t) => sec_flip_last_bit(t)
      None => fail("expected membership_tag")
    }
    let pm_tampered : @types.PublicMessage = {
      content: pm.content,
      auth: pm.auth,
      membership_tag: Some(bad_tag),
    }
    let mut e1 = false
    try {
      let _ = @schedule.unprotect_public_message(
        cs,
        sig_pub,
        Some(membership_key),
        pm_tampered,
        Some(gc),
      )
    } catch {
      @schedule.ScheduleError::InvalidMembershipTag => e1 = true
      _ => fail("expected InvalidMembershipTag on 1-bit flip")
    }
    assert_true(e1)
    // 2. Strip membership_tag on Member PublicMessage
    let pm_stripped : @types.PublicMessage = {
      content: pm.content,
      auth: pm.auth,
      membership_tag: None,
    }
    let mut e2 = false
    try {
      let _ = @schedule.unprotect_public_message(
        cs,
        sig_pub,
        Some(membership_key),
        pm_stripped,
        Some(gc),
      )
    } catch {
      @schedule.ScheduleError::InvalidMembershipTag => e2 = true
      _ => fail("expected InvalidMembershipTag on stripped tag")
    }
    assert_true(e2)
    // 3. Spurious membership_tag on External sender PublicMessage
    let ext_fc : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::External(0U),
      authenticated_data: b"",
      content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(1U)),
    }
    let ext_pm = @schedule.protect_public_message(
      cs,
      sig_priv,
      None,
      ext_fc,
      None,
      None,
    )
    let ext_spurious : @types.PublicMessage = {
      content: ext_pm.content,
      auth: ext_pm.auth,
      membership_tag: Some(Bytes::make(32, b'\x99')),
    }
    let mut e3 = false
    try {
      let _ = @schedule.unprotect_public_message(
        cs,
        sig_pub,
        None,
        ext_spurious,
        None,
      )
    } catch {
      @schedule.ScheduleError::InvalidMembershipTag => e3 = true
      _ => fail("expected InvalidMembershipTag on spurious external tag")
    }
    assert_true(e3)
  }
}

///|
test "SEC-09: Forged Ed25519 signature attacks (tampered content / 1-bit sig flip / wrong pubkey / wrong label)" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"sec-09-seed")
  let seed1 = rng.next_bytes(32)
  let seed2 = rng.next_bytes(32)
  let pk1 = @crypto.ed25519_public_key(seed1)
  let pk2 = @crypto.ed25519_public_key(seed2)
  let msg = b"authentic MLS handshake payload"
  let sig = @crypto.ed25519_sign(seed1, msg)
  assert_true(@crypto.ed25519_verify(pk1, msg, sig))
  // 1. Tamper content by 1 bit
  assert_false(@crypto.ed25519_verify(pk1, sec_flip_bit(msg, 0, 0x01), sig))
  // 2. Flip 1 bit in R (byte 0) and in S (byte 32 and byte 63)
  assert_false(@crypto.ed25519_verify(pk1, msg, sec_flip_bit(sig, 0, 0x01)))
  assert_false(@crypto.ed25519_verify(pk1, msg, sec_flip_bit(sig, 32, 0x01)))
  assert_false(@crypto.ed25519_verify(pk1, msg, sec_flip_bit(sig, 63, 0x80)))
  // 3. Replace public key (other valid key or 1-bit flipped key)
  assert_false(@crypto.ed25519_verify(pk2, msg, sig))
  assert_false(@crypto.ed25519_verify(sec_flip_bit(pk1, 10, 0x01), msg, sig))
  // 4. Truncated / oversized signature
  let short_sig = @tls.bytes_slice(sig, 0, 63)
  assert_false(@crypto.ed25519_verify(pk1, msg, short_sig))
  let mut got_invalid = false
  @crypto.ed25519_verify_or_raise(pk2, msg, sig) catch {
    @crypto.CryptoError::InvalidSignature => got_invalid = true
    _ => fail("expected CryptoError::InvalidSignature")
  }
  assert_true(got_invalid)
  // 5. MLS SignWithLabel domain separation check
  let labeled_sig = cs.sign_with_label(seed1, "LeafNodeTBS", msg)
  assert_true(cs.verify_with_label(pk1, "LeafNodeTBS", msg, labeled_sig))
  assert_false(cs.verify_with_label(pk1, "KeyPackageTBS", msg, labeled_sig))
  assert_false(
    cs.verify_with_label(pk1, "LeafNodeTBS", b"tampered", labeled_sig),
  )
  assert_false(
    cs.verify_with_label(
      pk1,
      "LeafNodeTBS",
      msg,
      sec_flip_last_bit(labeled_sig),
    ),
  )
}

///|
test "SEC-10: Ed25519 non-canonical scalar S >= L malleability attack rejected" {
  let seed = @crypto.DeterministicRng::from_seed(b"sec-10-seed").next_bytes(32)
  let pk = @crypto.ed25519_public_key(seed)
  let msg = b"RFC 8032 canonical S enforcement test"
  let sig = @crypto.ed25519_sign(seed, msg)
  assert_true(@crypto.ed25519_verify(pk, msg, sig))
  // Curve order L in little-endian (2^252 + 27742317777372353535851937790883648493)
  let order_l = @tls.bytes_from_hex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let r_part = @tls.bytes_slice(sig, 0, 32)
  let s_part = @tls.bytes_slice(sig, 32, 64)
  // S' = S + L satisfies S'*B == S*B == R + k*A, but S' >= L is non-canonical!
  let s_plus_l = sec_add_le256(s_part, order_l)
  let malleable_sig = @tls.bytes_concat([r_part, s_plus_l])
  assert_false(@crypto.ed25519_verify(pk, msg, malleable_sig))
  let mut raised = false
  @crypto.ed25519_verify_or_raise(pk, msg, malleable_sig) catch {
    @crypto.CryptoError::InvalidSignature => raised = true
    _ => fail("expected InvalidSignature for S + L malleability")
  }
  assert_true(raised)
  // Also reject boundary S == L, S == L + 1, and S == 0xFF..FF
  let sig_eq_l = @tls.bytes_concat([r_part, order_l])
  let one_le = @tls.bytes_from_hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let sig_l_plus_1 = @tls.bytes_concat([r_part, sec_add_le256(order_l, one_le)])
  let sig_all_ff = @tls.bytes_concat([r_part, Bytes::make(32, b'\xFF')])
  assert_false(@crypto.ed25519_verify(pk, msg, sig_eq_l))
  assert_false(@crypto.ed25519_verify(pk, msg, sig_l_plus_1))
  assert_false(@crypto.ed25519_verify(pk, msg, sig_all_ff))
}

///|
test "SEC-11: Tampered KeyPackage signature and LeafNode signature rejected by verify_key_package and propose_add" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"sec-11-seed")
  let alice = @group.MlsGroup::create(cs, b"sec-11-gid", b"alice", rng)
  let bob_b = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let kp = bob_b.key_package
  // Case A: Tampered KeyPackage signature
  let bad_kp_sig : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: kp.leaf_node,
    extensions: kp.extensions,
    signature: sec_flip_last_bit(kp.signature),
  }
  // Case B: Tampered LeafNode signature (even with KeyPackage re-signed over the bad leaf_node!)
  let bad_leaf : @types.LeafNode = {
    encryption_key: kp.leaf_node.encryption_key,
    signature_key: kp.leaf_node.signature_key,
    credential: kp.leaf_node.credential,
    capabilities: kp.leaf_node.capabilities,
    leaf_node_source: kp.leaf_node.leaf_node_source,
    lifetime: kp.leaf_node.lifetime,
    parent_hash: kp.leaf_node.parent_hash,
    extensions: kp.leaf_node.extensions,
    signature: sec_flip_last_bit(kp.leaf_node.signature),
  }
  let bad_leaf_kp_unsigned : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: bad_leaf,
    extensions: kp.extensions,
    signature: b"",
  }
  let bad_leaf_kp : @types.KeyPackage = {
    version: bad_leaf_kp_unsigned.version,
    cipher_suite: bad_leaf_kp_unsigned.cipher_suite,
    init_key: bad_leaf_kp_unsigned.init_key,
    leaf_node: bad_leaf_kp_unsigned.leaf_node,
    extensions: bad_leaf_kp_unsigned.extensions,
    signature: cs.sign_with_label(
      bob_b.signature_priv,
      "KeyPackageTBS",
      bad_leaf_kp_unsigned.encode_tbs(),
    ),
  }
  // Case C: Tampered credential identity without re-signing
  let spoofed_cred_leaf : @types.LeafNode = {
    encryption_key: kp.leaf_node.encryption_key,
    signature_key: kp.leaf_node.signature_key,
    credential: @types.Credential::Basic(b"eve-impersonator"),
    capabilities: kp.leaf_node.capabilities,
    leaf_node_source: kp.leaf_node.leaf_node_source,
    lifetime: kp.leaf_node.lifetime,
    parent_hash: kp.leaf_node.parent_hash,
    extensions: kp.leaf_node.extensions,
    signature: kp.leaf_node.signature,
  }
  let bad_cred_kp : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: spoofed_cred_leaf,
    extensions: kp.extensions,
    signature: kp.signature,
  }
  for bad in [bad_kp_sig, bad_leaf_kp, bad_cred_kp] {
    let mut v_err = false
    @group.verify_key_package(cs, bad) catch {
      @group.GroupError::InvalidKeyPackage(_) => v_err = true
      _ => fail("expected InvalidKeyPackage from verify_key_package")
    }
    assert_true(v_err)
    let mut p_err = false
    try {
      let _ = alice.propose_add(bad, rng)
    } catch {
      @group.GroupError::InvalidKeyPackage(_) => p_err = true
      _ => fail("expected InvalidKeyPackage from propose_add")
    }
    assert_true(p_err)
  }
}

///|
test "SEC-12: KeyPackage key reuse attack (init_key == leaf_node.encryption_key) rejected even with valid signatures" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"sec-12-seed")
  let alice = @group.MlsGroup::create(cs, b"sec-12-gid", b"alice", rng)
  let base_b = @group.KeyPackageBundle::generate(cs, b"reuser", rng)
  // Construct a validly signed KeyPackage where init_key == leaf_node.encryption_key
  let reused_unsigned : @types.KeyPackage = {
    version: base_b.key_package.version,
    cipher_suite: base_b.key_package.cipher_suite,
    init_key: base_b.key_package.leaf_node.encryption_key,
    leaf_node: base_b.key_package.leaf_node,
    extensions: [],
    signature: b"",
  }
  let reused_sig = cs.sign_with_label(
    base_b.signature_priv,
    "KeyPackageTBS",
    reused_unsigned.encode_tbs(),
  )
  let reused_kp : @types.KeyPackage = {
    version: reused_unsigned.version,
    cipher_suite: reused_unsigned.cipher_suite,
    init_key: reused_unsigned.init_key,
    leaf_node: reused_unsigned.leaf_node,
    extensions: reused_unsigned.extensions,
    signature: reused_sig,
  }
  // Confirm both signatures are genuinely valid, proving rejection is specifically key-reuse enforcement
  assert_true(
    cs.verify_with_label(
      reused_kp.leaf_node.signature_key,
      "KeyPackageTBS",
      reused_kp.encode_tbs(),
      reused_kp.signature,
    ),
  )
  let mut e_verify = false
  @group.verify_key_package(cs, reused_kp) catch {
    @group.GroupError::InvalidKeyPackage(_) => e_verify = true
    _ => fail("expected InvalidKeyPackage on key reuse")
  }
  assert_true(e_verify)
  let mut e_prop = false
  try {
    let _ = alice.propose_add(reused_kp, rng)
  } catch {
    @group.GroupError::InvalidKeyPackage(_) => e_prop = true
    _ => fail("expected InvalidKeyPackage in propose_add on key reuse")
  }
  assert_true(e_prop)
  let bad_bundle : @group.KeyPackageBundle = {
    key_package: reused_kp,
    init_priv: base_b.encryption_priv,
    encryption_priv: base_b.encryption_priv,
    signature_priv: base_b.signature_priv,
  }
  let mut e_create = false
  try {
    let _ = @group.MlsGroup::create_from_bundle(cs, b"g", bad_bundle, rng)
  } catch {
    @group.GroupError::InvalidKeyPackage(_) => e_create = true
    _ => fail("expected InvalidKeyPackage in create_from_bundle on key reuse")
  }
  assert_true(e_create)
}

///|
test "SEC-13: Tampered Welcome encrypted_group_info or GroupInfo signature rejected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (_alice, _bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-13-gid", b"sec-13-seed",
  )
  let alice_sig_pub = alice_bundle.key_package.leaf_node.signature_key
  // Case A: Flip 1 bit in Welcome.encrypted_group_info
  let bad_egi_welcome : @types.Welcome = {
    cipher_suite: welcome.cipher_suite,
    secrets: welcome.secrets,
    encrypted_group_info: sec_flip_last_bit(welcome.encrypted_group_info),
  }
  let mut e_egi = false
  try {
    let _ = @group.MlsGroup::from_welcome(cs, bad_egi_welcome, bob_bundle, None)
  } catch {
    @group.GroupError::CsError(@cs.CsError::DecryptionFailed) => e_egi = true
    _ =>
      fail(
        "expected CsError(DecryptionFailed) on tampered encrypted_group_info",
      )
  }
  assert_true(e_egi)
  // Case B: Re-package Welcome with 1-bit flipped GroupInfo.signature (outer AEAD/HPKE valid!)
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_sig_pub,
  )
  let bad_sig_gi : @types.GroupInfo = {
    group_context: verified.group_info.group_context,
    extensions: verified.group_info.extensions,
    confirmation_tag: verified.group_info.confirmation_tag,
    signer: verified.group_info.signer,
    signature: sec_flip_last_bit(verified.group_info.signature),
  }
  let bad_sig_welcome = repackage_welcome(
    cs,
    bad_sig_gi,
    verified.group_secrets,
    bob_bundle.key_package,
    rng,
  )
  let mut e_gisig = false
  try {
    let _ = @group.MlsGroup::from_welcome(cs, bad_sig_welcome, bob_bundle, None)
  } catch {
    @group.GroupError::InvalidGroupInfoSignature => e_gisig = true
    _ => fail("expected InvalidGroupInfoSignature in from_welcome")
  }
  assert_true(e_gisig)
  // Case C: Wrong signer_pub in verify_and_decrypt_welcome
  let mut e_wrong_pub = false
  try {
    let _ = @group.verify_and_decrypt_welcome(
      cs,
      welcome,
      bob_bundle.init_priv,
      bob_bundle.key_package,
      sec_flip_last_bit(alice_sig_pub),
    )
  } catch {
    @group.GroupError::InvalidGroupInfoSignature => e_wrong_pub = true
    _ => fail("expected InvalidGroupInfoSignature on wrong signer_pub")
  }
  assert_true(e_wrong_pub)
}

///|
test "SEC-14: Tampered Welcome ConfirmationTag (with validly re-signed GroupInfo) rejected with ConfirmationTagMismatch" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let (_alice, _bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-14-gid", b"sec-14-seed",
  )
  let alice_sig_pub = alice_bundle.key_package.leaf_node.signature_key
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_sig_pub,
  )
  // Flip 1 bit in confirmation_tag AND validly re-sign GroupInfoTBS with Alice's signature_priv!
  let bad_tag_gi_unsigned : @types.GroupInfo = {
    group_context: verified.group_info.group_context,
    extensions: verified.group_info.extensions,
    confirmation_tag: sec_flip_last_bit(verified.group_info.confirmation_tag),
    signer: verified.group_info.signer,
    signature: b"",
  }
  let valid_sig = cs.sign_with_label(
    alice_bundle.signature_priv,
    "GroupInfoTBS",
    bad_tag_gi_unsigned.encode_tbs(),
  )
  let bad_tag_gi : @types.GroupInfo = {
    group_context: bad_tag_gi_unsigned.group_context,
    extensions: bad_tag_gi_unsigned.extensions,
    confirmation_tag: bad_tag_gi_unsigned.confirmation_tag,
    signer: bad_tag_gi_unsigned.signer,
    signature: valid_sig,
  }
  let forged_welcome = repackage_welcome(
    cs,
    bad_tag_gi,
    verified.group_secrets,
    bob_bundle.key_package,
    rng,
  )
  // Both from_welcome and verify_and_decrypt_welcome must reject with ConfirmationTagMismatch
  let mut e1 = false
  try {
    let _ = @group.MlsGroup::from_welcome(cs, forged_welcome, bob_bundle, None)
  } catch {
    @group.GroupError::ConfirmationTagMismatch => e1 = true
    _ => fail("expected ConfirmationTagMismatch in from_welcome")
  }
  assert_true(e1)
  let mut e2 = false
  try {
    let _ = @group.verify_and_decrypt_welcome(
      cs,
      forged_welcome,
      bob_bundle.init_priv,
      bob_bundle.key_package,
      alice_sig_pub,
    )
  } catch {
    @group.GroupError::ConfirmationTagMismatch => e2 = true
    _ => fail("expected ConfirmationTagMismatch in verify_and_decrypt_welcome")
  }
  assert_true(e2)
}

///|
test "SEC-15: Cross-group group_id confusion injection rejected with GroupIdMismatch" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice_a, _bob_a, _ab_a, _bb_a, _wa, rng_a) = setup_two_member_group(
    cs, b"group-alpha", b"sec-15-a",
  )
  let (alice_b, bob_b, _ab_b, _bb_b, _wb, rng_b) = setup_two_member_group(
    cs, b"group-beta", b"sec-15-b",
  )
  let msg_from_a = alice_a.protect_application(b"alpha-secret", b"aad", rng_a)
  let prop_from_a = alice_a.propose_update(rng_a)
  let mut e_app = false
  try {
    let _ = bob_b.process_message(msg_from_a)
  } catch {
    @group.GroupError::GroupIdMismatch => e_app = true
    _ => fail("expected GroupIdMismatch for cross-group Application")
  }
  assert_true(e_app)
  let mut e_prop = false
  try {
    let _ = bob_b.process_message(prop_from_a)
  } catch {
    @group.GroupError::GroupIdMismatch => e_prop = true
    _ => fail("expected GroupIdMismatch for cross-group Proposal")
  }
  assert_true(e_prop)
  // Group B remains completely healthy
  let msg_from_b = alice_b.protect_application(b"beta-ok", b"", rng_b)
  assert_true(
    bob_b.process_message(msg_from_b) is Application(0U, b"beta-ok", b""),
  )
}

///|
test "SEC-16: Tampered PrivateMessage authenticated_data (AAD) rejected by AEAD in CS1 and CS3" {
  let suites = [
    @cs.CipherSuite::X25519Aes128GcmSha256Ed25519,
    @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519,
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let cs = suites[i]
    let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
      cs, b"sec-16-gid", b"sec-16-seed",
    )
    let msg = alice.protect_application(b"top-secret", b"header-v1", rng)
    let tampered_aad : @types.PrivateMessage = {
      group_id: msg.group_id,
      epoch: msg.epoch,
      content_type: msg.content_type,
      authenticated_data: b"header-v2",
      encrypted_sender_data: msg.encrypted_sender_data,
      ciphertext: msg.ciphertext,
    }
    let mut rejected = false
    try {
      let _ = bob.process_message(tampered_aad)
    } catch {
      @group.GroupError::ScheduleError(
        @schedule.ScheduleError::DecryptionFailed,
      ) => rejected = true
      _ => fail("expected DecryptionFailed on tampered AAD")
    }
    assert_true(rejected)
    // Generation key was NOT consumed; genuine message still decrypts cleanly
    assert_true(
      bob.process_message(msg) is Application(0U, b"top-secret", b"header-v1"),
    )
  }
}

///|
test "SEC-17: Tampered PrivateMessage encrypted_sender_data rejected by AEAD in CS1 and CS3" {
  let suites = [
    @cs.CipherSuite::X25519Aes128GcmSha256Ed25519,
    @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519,
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let cs = suites[i]
    let (alice, bob, _ab, _bb, _w, rng) = setup_two_member_group(
      cs, b"sec-17-gid", b"sec-17-seed",
    )
    let msg = alice.protect_application(b"sender-data-protected", b"aad", rng)
    let bad_sd_first : @types.PrivateMessage = {
      group_id: msg.group_id,
      epoch: msg.epoch,
      content_type: msg.content_type,
      authenticated_data: msg.authenticated_data,
      encrypted_sender_data: sec_flip_bit(msg.encrypted_sender_data, 0, 0x01),
      ciphertext: msg.ciphertext,
    }
    let bad_sd_last : @types.PrivateMessage = {
      group_id: msg.group_id,
      epoch: msg.epoch,
      content_type: msg.content_type,
      authenticated_data: msg.authenticated_data,
      encrypted_sender_data: sec_flip_last_bit(msg.encrypted_sender_data),
      ciphertext: msg.ciphertext,
    }
    let bad_sd_trunc : @types.PrivateMessage = {
      group_id: msg.group_id,
      epoch: msg.epoch,
      content_type: msg.content_type,
      authenticated_data: msg.authenticated_data,
      encrypted_sender_data: @tls.bytes_slice(msg.encrypted_sender_data, 0, 8),
      ciphertext: msg.ciphertext,
    }
    for tampered in [bad_sd_first, bad_sd_last, bad_sd_trunc] {
      let mut rejected = false
      try {
        let _ = bob.process_message(tampered)
      } catch {
        @group.GroupError::ScheduleError(
          @schedule.ScheduleError::DecryptionFailed,
        ) => rejected = true
        _ => fail("expected DecryptionFailed on tampered encrypted_sender_data")
      }
      assert_true(rejected)
    }
    // Original valid message still succeeds
    assert_true(
      bob.process_message(msg)
      is Application(0U, b"sender-data-protected", b"aad"),
    )
  }
}

///|
test "SEC-18: PrivateMessageContent non-zero trailing padding injection rejected (codec + AEAD + MlsGroup)" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-18-gid", b"sec-18-seed",
  )
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  let fc : @types.FramedContent = {
    group_id: b"sec-18-gid",
    epoch: 1UL,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"pad-test",
    content: @types.FramedContentBody::Application(b"hello"),
  }
  let sig = @schedule.sign_framed_content(
    cs,
    alice_bundle.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc,
    Some(verified.group_info.group_context),
  )
  let pmc : @types.PrivateMessageContent = {
    content: fc.content,
    auth: { signature: sig, confirmation_tag: None, },
    padding_len: 0,
  }
  let base_bytes = pmc.to_bytes()
  // Valid all-zero padding decodes cleanly
  let zero_padded = @tls.bytes_concat([base_bytes, b"\x00\x00\x00\x00"])
  let decoded_ok = @types.PrivateMessageContent::from_bytes(
    zero_padded,
    @types.ContentType::Application,
  )
  assert_eq(decoded_ok.padding_len, 4)
  // Layer 1: Non-zero padding byte rejected by codec
  let bad_padded = @tls.bytes_concat([base_bytes, b"\x00\x00\x01\x00"])
  let mut codec_err = false
  try {
    let _ = @types.PrivateMessageContent::from_bytes(
      bad_padded,
      @types.ContentType::Application,
    )
  } catch {
    @tls.TlsError::InvalidEnum(_) => codec_err = true
    _ => fail("expected TlsError::InvalidEnum on non-zero padding")
  }
  assert_true(codec_err)
  // Layer 2: Validly AEAD-encrypted PrivateMessage carrying non-zero padding rejected by MlsGroup
  let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
  let (key0, nonce0) = st.application_key_nonce_for_generation(0U, 0U)
  let reuse_guard = b"\x11\x22\x33\x44"
  let xored_nonce = Bytes::makei(nonce0.length(), fn(i) {
    if i < 4 {
      (nonce0[i].to_int() ^ reuse_guard[i].to_int()).to_byte()
    } else {
      nonce0[i]
    }
  })
  let aad_struct : @types.PrivateContentAad = {
    group_id: fc.group_id,
    epoch: fc.epoch,
    content_type: @types.ContentType::Application,
    authenticated_data: fc.authenticated_data,
  }
  let ciphertext = cs.aead_seal(
    key0,
    xored_nonce,
    aad_struct.to_bytes(),
    bad_padded,
  )
  let (sd_key, sd_nonce) = @schedule.derive_sender_data_key_nonce(
    cs,
    verified.secrets.sender_data_secret,
    ciphertext,
  )
  let sd : @types.MlsSenderData = {
    leaf_index: 0U,
    generation: 0U,
    reuse_guard,
  }
  let sd_aad : @types.MlsSenderDataAad = {
    group_id: fc.group_id,
    epoch: fc.epoch,
    content_type: @types.ContentType::Application,
  }
  let enc_sd = cs.aead_seal(sd_key, sd_nonce, sd_aad.to_bytes(), sd.to_bytes())
  let bad_pad_msg : @types.PrivateMessage = {
    group_id: fc.group_id,
    epoch: fc.epoch,
    content_type: @types.ContentType::Application,
    authenticated_data: fc.authenticated_data,
    encrypted_sender_data: enc_sd,
    ciphertext,
  }
  let mut group_pad_err = false
  try {
    let _ = bob.process_message(bad_pad_msg)
  } catch {
    @group.GroupError::ScheduleError(
      @schedule.ScheduleError::TlsError(@tls.TlsError::InvalidEnum(_)),
    ) => group_pad_err = true
    _ =>
      fail("expected ScheduleError(TlsError(InvalidEnum)) on non-zero padding")
  }
  assert_true(group_pad_err)
  // Gen 0 was NOT consumed on failure; Alice's honest gen-0 message still succeeds
  let ok_msg = alice.protect_application(b"clean-msg", b"ok", rng)
  assert_true(
    bob.process_message(ok_msg) is Application(0U, b"clean-msg", b"ok"),
  )
}

///|
test "SEC-19: Out-of-bounds tree node and leaf index attacks rejected with OutOfBounds" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, _bob, _ab, _bb, _w, rng) = setup_two_member_group(
    cs, b"sec-19-gid", b"sec-19-seed",
  )
  let rt = @tree.RatchetTreeState::from_nodes(alice.ratchet_tree_nodes())
  let nl = rt.n_leaves()
  let nn = rt.n_nodes()
  // RatchetTreeState out-of-bounds
  let mut e_leaf = false
  try {
    let _ = rt.get_leaf(nl)
  } catch {
    @tree.TreeError::OutOfBounds(idx) => e_leaf = idx == nl
    _ => fail("expected OutOfBounds on get_leaf")
  }
  assert_true(e_leaf)
  let mut e_node = false
  try {
    let _ = rt.get_node(nn)
  } catch {
    @tree.TreeError::OutOfBounds(idx) => e_node = idx == nn
    _ => fail("expected OutOfBounds on get_node")
  }
  assert_true(e_node)
  let mut e_hash = false
  try {
    let _ = rt.node_hash(cs, nn + 5U)
  } catch {
    @tree.TreeError::OutOfBounds(idx) => e_hash = idx == nn + 5U
    _ => fail("expected OutOfBounds on node_hash")
  }
  assert_true(e_hash)
  let mut e_res = false
  try {
    let _ = rt.resolution(nn)
  } catch {
    @tree.TreeError::OutOfBounds(idx) => e_res = idx == nn
    _ => fail("expected OutOfBounds on resolution")
  }
  assert_true(e_res)
  // SecretTree out-of-bounds
  let st = @tree.SecretTree::new(cs, Bytes::make(32, b'\x07'), 2U)
  let mut e_st1 = false
  try {
    let _ = st.leaf_secret(2U)
  } catch {
    @tree.TreeError::OutOfBounds(2U) => e_st1 = true
    _ => fail("expected OutOfBounds(2) on SecretTree::leaf_secret")
  }
  assert_true(e_st1)
  let mut e_st2 = false
  try {
    let _ = st.application_key_nonce_for_generation(99U, 0U)
  } catch {
    @tree.TreeError::OutOfBounds(99U) => e_st2 = true
    _ => fail("expected OutOfBounds(99) on SecretTree::application")
  }
  assert_true(e_st2)
  // MlsGroup::propose_remove out-of-bounds
  let mut e_rm = false
  try {
    let _ = alice.propose_remove(99U, rng)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::OutOfBounds(99U)) =>
      e_rm = true
    _ => fail("expected GroupError::TreeError(OutOfBounds(99))")
  }
  assert_true(e_rm)
}

///|
test "SEC-20: RatchetTree duplicate keys (DuplicateKey) and invalid unmerged_leaves (InvalidUnmergedLeaf) rejected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, _bob, _charlie, _rng) = setup_three_member_group(
    cs, b"sec-20-gid", b"sec-20-seed",
  )
  let base_nodes = alice.ratchet_tree_nodes()
  let leaf0 = match base_nodes[0] {
    Some(@types.Node::Leaf(l)) => l
    _ => fail("expected leaf 0")
  }
  let leaf1 = match base_nodes[2] {
    Some(@types.Node::Leaf(l)) => l
    _ => fail("expected leaf 1")
  }
  // Case A: Duplicate leaf encryption_key
  let dup_enc_nodes = base_nodes.copy()
  dup_enc_nodes[2] = Some(
    @types.Node::Leaf({
      encryption_key: leaf0.encryption_key,
      signature_key: leaf1.signature_key,
      credential: leaf1.credential,
      capabilities: leaf1.capabilities,
      leaf_node_source: leaf1.leaf_node_source,
      lifetime: leaf1.lifetime,
      parent_hash: leaf1.parent_hash,
      extensions: leaf1.extensions,
      signature: leaf1.signature,
    }),
  )
  let mut e_dup_enc = false
  @tree.RatchetTreeState::from_nodes(dup_enc_nodes).validate_tree_structure() catch {
    @tree.TreeError::DuplicateKey => e_dup_enc = true
    _ => fail("expected DuplicateKey for duplicate leaf encryption_key")
  }
  assert_true(e_dup_enc)
  // Case B: Duplicate leaf signature_key
  let dup_sig_nodes = base_nodes.copy()
  dup_sig_nodes[2] = Some(
    @types.Node::Leaf({
      encryption_key: leaf1.encryption_key,
      signature_key: leaf0.signature_key,
      credential: leaf1.credential,
      capabilities: leaf1.capabilities,
      leaf_node_source: leaf1.leaf_node_source,
      lifetime: leaf1.lifetime,
      parent_hash: leaf1.parent_hash,
      extensions: leaf1.extensions,
      signature: leaf1.signature,
    }),
  )
  let mut e_dup_sig = false
  @tree.RatchetTreeState::from_nodes(dup_sig_nodes).validate_tree_structure() catch {
    @tree.TreeError::DuplicateKey => e_dup_sig = true
    _ => fail("expected DuplicateKey for duplicate leaf signature_key")
  }
  assert_true(e_dup_sig)
  // Case C: Parent encryption_key duplicates leaf 0 encryption_key
  let dup_parent_nodes = base_nodes.copy()
  dup_parent_nodes[1] = Some(
    @types.Node::Parent({
      encryption_key: leaf0.encryption_key,
      parent_hash: b"",
      unmerged_leaves: [],
    }),
  )
  let mut e_dup_par = false
  @tree.RatchetTreeState::from_nodes(dup_parent_nodes).validate_tree_structure() catch {
    @tree.TreeError::DuplicateKey => e_dup_par = true
    _ => fail("expected DuplicateKey for parent/leaf encryption_key collision")
  }
  assert_true(e_dup_par)
  // Case D: Out-of-subtree leaf (leaf 2) listed in parent node 1's unmerged_leaves (subtree covers 0..1 only)
  let bad_ul_subtree = base_nodes.copy()
  bad_ul_subtree[1] = Some(
    @types.Node::Parent({
      encryption_key: Bytes::make(32, b'\xA1'),
      parent_hash: b"",
      unmerged_leaves: [2U],
    }),
  )
  let mut e_ul1 = false
  @tree.RatchetTreeState::from_nodes(bad_ul_subtree).validate_tree_structure() catch {
    @tree.TreeError::InvalidUnmergedLeaf => e_ul1 = true
    _ => fail("expected InvalidUnmergedLeaf for non-descendant leaf")
  }
  assert_true(e_ul1)
  // Case E: Duplicate leaf in unmerged_leaves
  let bad_ul_dup = base_nodes.copy()
  bad_ul_dup[1] = Some(
    @types.Node::Parent({
      encryption_key: Bytes::make(32, b'\xA2'),
      parent_hash: b"",
      unmerged_leaves: [0U, 0U],
    }),
  )
  let mut e_ul2 = false
  @tree.RatchetTreeState::from_nodes(bad_ul_dup).validate_tree_structure() catch {
    @tree.TreeError::InvalidUnmergedLeaf => e_ul2 = true
    _ => fail("expected InvalidUnmergedLeaf for duplicate entry")
  }
  assert_true(e_ul2)
  // Case F: Blank leaf listed in unmerged_leaves
  let bad_ul_blank = base_nodes.copy()
  bad_ul_blank[2] = None
  bad_ul_blank[1] = Some(
    @types.Node::Parent({
      encryption_key: Bytes::make(32, b'\xA3'),
      parent_hash: b"",
      unmerged_leaves: [1U],
    }),
  )
  let mut e_ul3 = false
  @tree.RatchetTreeState::from_nodes(bad_ul_blank).validate_tree_structure() catch {
    @tree.TreeError::InvalidUnmergedLeaf => e_ul3 = true
    _ => fail("expected InvalidUnmergedLeaf for blank leaf")
  }
  assert_true(e_ul3)
}

///|
test "SEC-21: RatchetTree parent_hash chain tampering rejected with InvalidParentHash" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, charlie, rng) = setup_three_member_group(
    cs, b"sec-21-gid", b"sec-21-seed",
  )
  // Have Alice commit once more so full parent_hash chain (root -> parent 1 -> leaf 0) is active
  let out3 = alice.commit_pending(rng)
  let _ = bob.process_message(out3.commit_msg)
  let _ = charlie.process_message(out3.commit_msg)
  let base_nodes = alice.ratchet_tree_nodes()
  // Baseline passes
  let good_tree = @tree.RatchetTreeState::from_nodes(base_nodes)
  good_tree.validate_parent_hashes(cs)
  // Case A: Tamper leaf 0's Commit parent_hash by 1 bit
  let leaf0 = match base_nodes[0] {
    Some(@types.Node::Leaf(l)) => l
    _ => fail("expected leaf 0")
  }
  let orig_ph = match leaf0.parent_hash {
    Some(ph) => ph
    None => fail("expected Commit leaf 0 to have parent_hash")
  }
  let bad_leaf_nodes = base_nodes.copy()
  bad_leaf_nodes[0] = Some(
    @types.Node::Leaf({
      encryption_key: leaf0.encryption_key,
      signature_key: leaf0.signature_key,
      credential: leaf0.credential,
      capabilities: leaf0.capabilities,
      leaf_node_source: leaf0.leaf_node_source,
      lifetime: leaf0.lifetime,
      parent_hash: Some(sec_flip_last_bit(orig_ph)),
      extensions: leaf0.extensions,
      signature: leaf0.signature,
    }),
  )
  let mut e_leaf_ph = false
  @tree.RatchetTreeState::from_nodes(bad_leaf_nodes).validate_parent_hashes(cs) catch {
    @tree.TreeError::InvalidParentHash => e_leaf_ph = true
    _ => fail("expected InvalidParentHash on tampered leaf parent_hash")
  }
  assert_true(e_leaf_ph)
  // Case B: Tamper parent node 1's parent_hash by 1 bit
  let par1 = match base_nodes[1] {
    Some(@types.Node::Parent(p)) => p
    _ => fail("expected non-blank parent node 1")
  }
  let bad_par_nodes = base_nodes.copy()
  bad_par_nodes[1] = Some(
    @types.Node::Parent({
      encryption_key: par1.encryption_key,
      parent_hash: sec_flip_last_bit(par1.parent_hash),
      unmerged_leaves: par1.unmerged_leaves,
    }),
  )
  let mut e_par_ph = false
  @tree.RatchetTreeState::from_nodes(bad_par_nodes).validate_parent_hashes(cs) catch {
    @tree.TreeError::InvalidParentHash => e_par_ph = true
    _ => fail("expected InvalidParentHash on tampered parent node parent_hash")
  }
  assert_true(e_par_ph)
}

///|
test "SEC-22: Removed member messages rejected by group and removed member cannot decrypt post-removal epochs" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, charlie, rng) = setup_three_member_group(
    cs, b"sec-22-gid", b"sec-22-seed",
  )
  // Charlie creates a message at epoch 2 before being removed
  let charlie_stale_msg = charlie.protect_application(
    b"still-in-group?", b"", rng,
  )
  // Alice removes Charlie (leaf 2) and commits -> epoch 3
  let prop_rm = alice.propose_remove(2U, rng)
  let _ = bob.process_message(prop_rm)
  let out3 = alice.commit_pending(rng)
  let _ = bob.process_message(out3.commit_msg)
  assert_eq(alice.epoch(), 3UL)
  assert_eq(bob.epoch(), 3UL)
  assert_eq(alice.members().length(), 2)
  // 1. Charlie's epoch-2 message rejected by Alice & Bob at epoch 3
  let mut e_stale = false
  try {
    let _ = bob.process_message(charlie_stale_msg)
  } catch {
    @group.GroupError::EpochMismatch(3UL, 2UL) => e_stale = true
    _ => fail("expected EpochMismatch for removed member stale message")
  }
  assert_true(e_stale)
  // 2. Alice sends an epoch-3 secret message; Charlie (still at epoch 2) cannot decrypt it
  let ep3_secret = alice.protect_application(b"post-kick-secret", b"aad", rng)
  let mut e_ep = false
  try {
    let _ = charlie.process_message(ep3_secret)
  } catch {
    @group.GroupError::EpochMismatch(2UL, 3UL) => e_ep = true
    _ =>
      fail(
        "expected EpochMismatch when removed member receives epoch-3 message",
      )
  }
  assert_true(e_ep)
  // Even if attacker rewrites epoch field to 2UL, Charlie's epoch-2 keys cannot decrypt it!
  let spoofed_ep : @types.PrivateMessage = {
    group_id: ep3_secret.group_id,
    epoch: 2UL,
    content_type: ep3_secret.content_type,
    authenticated_data: ep3_secret.authenticated_data,
    encrypted_sender_data: ep3_secret.encrypted_sender_data,
    ciphertext: ep3_secret.ciphertext,
  }
  let mut e_dec = false
  try {
    let _ = charlie.process_message(spoofed_ep)
  } catch {
    @group.GroupError::ScheduleError(@schedule.ScheduleError::DecryptionFailed) =>
      e_dec = true
    _ =>
      fail(
        "expected DecryptionFailed when removed member tries epoch-3 ciphertext",
      )
  }
  assert_true(e_dec)
  // 3. When Charlie processes the removal Commit, Charlie becomes inactive (MemberRemoved)
  let _ = charlie.process_message(prop_rm)
  let mut e_removed = false
  try {
    let _ = charlie.process_message(out3.commit_msg)
  } catch {
    @group.GroupError::MemberRemoved => e_removed = true
    _ => fail("expected MemberRemoved for Charlie")
  }
  assert_true(e_removed)
  assert_false(charlie.is_active())
  let mut e_send_after = false
  try {
    let _ = charlie.protect_application(b"zombie", b"", rng)
  } catch {
    @group.GroupError::MemberRemoved => e_send_after = true
    _ => fail("expected MemberRemoved when inactive member tries to send")
  }
  assert_true(e_send_after)
  // Bob still decrypts Alice's epoch-3 secret cleanly
  assert_true(
    bob.process_message(ep3_secret)
    is Application(0U, b"post-kick-secret", b"aad"),
  )
}

///|
test "SEC-23: Self-removal (CannotRemoveSelf) and blank-leaf removal (BlankLeaf) rejected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (alice, bob, charlie, rng) = setup_three_member_group(
    cs, b"sec-23-gid", b"sec-23-seed",
  )
  // 1. Self-removal via propose_remove -> CannotRemoveSelf
  let mut e_self1 = false
  try {
    let _ = alice.propose_remove(alice.my_leaf_index(), rng)
  } catch {
    @group.GroupError::CannotRemoveSelf => e_self1 = true
    _ => fail("expected CannotRemoveSelf from propose_remove")
  }
  assert_true(e_self1)
  // 2. Self-removal via inline Commit proposal -> CannotRemoveSelf
  let mut e_self2 = false
  try {
    let _ = alice.commit([@types.Proposal::Remove(alice.my_leaf_index())], rng)
  } catch {
    @group.GroupError::CannotRemoveSelf => e_self2 = true
    _ => fail("expected CannotRemoveSelf from inline Commit")
  }
  assert_true(e_self2)
  // 3. Remove Bob (leaf 1) so leaf 1 becomes blank while leaf 2 (Charlie) stays occupied
  let out3 = alice.commit([@types.Proposal::Remove(1U)], rng)
  let _ = charlie.process_message(out3.commit_msg)
  ignore(bob)
  // 4. RatchetTreeState::remove_leaf(1U) on blank leaf -> BlankLeaf(1U)
  let rt = @tree.RatchetTreeState::from_nodes(alice.ratchet_tree_nodes())
  let mut e_blank_tree = false
  rt.remove_leaf(1U) catch {
    @tree.TreeError::BlankLeaf(1U) => e_blank_tree = true
    _ => fail("expected TreeError::BlankLeaf(1)")
  }
  assert_true(e_blank_tree)
  // 5. MlsGroup::propose_remove(1U) and inline commit on blank leaf -> InvalidProposal
  let mut e_blank_prop = false
  try {
    let _ = alice.propose_remove(1U, rng)
  } catch {
    @group.GroupError::InvalidProposal(_) => e_blank_prop = true
    _ => fail("expected InvalidProposal on blank leaf propose_remove")
  }
  assert_true(e_blank_prop)
  let mut e_blank_commit = false
  try {
    let _ = alice.commit([@types.Proposal::Remove(1U)], rng)
  } catch {
    @group.GroupError::InvalidProposal(_) => e_blank_commit = true
    _ => fail("expected InvalidProposal on blank leaf commit")
  }
  assert_true(e_blank_commit)
}

///|
test "SEC-24: TLS codec malformed wire inputs (non-minimal varint, 0xC0 prefix, truncation, TrailingData)" {
  // 1. Non-minimal 2-byte varint encoding 0 (0x40 0x00) and 63 (0x40 0x3F)
  for raw in [b"\x40\x00", b"\x40\x3F", b"\x80\x00\x3F\xFF"] {
    let mut e = false
    try {
      let _ = @tls.Reader::new(raw).read_varint()
    } catch {
      @tls.TlsError::NonMinimalVarint => e = true
      _ => fail("expected NonMinimalVarint")
    }
    assert_true(e)
  }
  // 2. Illegal 0b11 prefix (0xC0 / 0xFF)
  for raw in [b"\xC0", b"\xFF\xFF\xFF\xFF"] {
    let mut e = false
    try {
      let _ = @tls.Reader::new(raw).read_varint()
    } catch {
      @tls.TlsError::InvalidVarint => e = true
      _ => fail("expected InvalidVarint for 0xC0/0xFF prefix")
    }
    assert_true(e)
  }
  // 3. Truncated varint & truncated opaque payload -> UnexpectedEof
  for raw in [b"", b"\x40", b"\x80\x01\x02", b"\x05\xAA\xBB"] {
    let mut e = false
    try {
      let _ = @tls.Reader::new(raw).read_opaque()
    } catch {
      @tls.TlsError::UnexpectedEof => e = true
      _ => fail("expected UnexpectedEof on truncated input")
    }
    assert_true(e)
  }
  // 4. TrailingData on strict MLS struct decode
  let sd : @types.MlsSenderData = {
    leaf_index: 1U,
    generation: 2U,
    reuse_guard: b"\xAA\xBB\xCC\xDD",
  }
  let with_trailing = @tls.bytes_concat([sd.to_bytes(), b"\x00"])
  let mut e_trail = false
  try {
    let _ = @types.MlsSenderData::from_bytes(with_trailing)
  } catch {
    @tls.TlsError::TrailingData => e_trail = true
    _ => fail("expected TrailingData")
  }
  assert_true(e_trail)
  // 5. Varint overflow on write
  let mut e_ovf = false
  try {
    let _ = @tls.encode_varint_bytes(0x40000000)
  } catch {
    @tls.TlsError::VarintOverflow => e_ovf = true
    _ => fail("expected VarintOverflow")
  }
  assert_true(e_ovf)
  // 6. Invalid optional presence byte (0x02)
  let mut e_opt = false
  try {
    let _ = @tls.Reader::new(b"\x02").read_optional(r => r.read_u8())
  } catch {
    @tls.TlsError::InvalidEnum(_) => e_opt = true
    _ => fail("expected InvalidEnum on invalid optional tag")
  }
  assert_true(e_opt)
}

///|
test "SEC-25: X25519 low-order points (all-zero, u=1, order-8 points, p-1, p, p+1) rejected with LowOrderPoint" {
  let rng = @crypto.DeterministicRng::from_seed(b"sec-25-seed")
  let sk = rng.next_bytes(32)
  let low_order_hexes : Array[String] = [
    // u = 0 (all-zero point)
    "0000000000000000000000000000000000000000000000000000000000000000",
    // u = 1 (order 4)
     "0100000000000000000000000000000000000000000000000000000000000000",
    // Order-8 point 1 (RFC 7748)
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    // Order-8 point 2 (RFC 7748)
     "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    // u = p - 1
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // u = p
     "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // u = p + 1
     "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]
  let cs1 = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let cs3 = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  for i = 0; i < low_order_hexes.length(); i = i + 1 {
    let pt = @tls.bytes_from_hex(low_order_hexes[i])
    let mut e_dh = false
    try {
      let _ = @crypto.x25519_dh(sk, pt)
    } catch {
      @crypto.CryptoError::LowOrderPoint => e_dh = true
      _ => fail("expected CryptoError::LowOrderPoint from x25519_dh")
    }
    assert_true(e_dh)
    // Also verify HPKE EncryptWithLabel rejects low-order recipient keys in both CS1 & CS3
    for cs in [cs1, cs3] {
      let mut e_hpke = false
      try {
        let _ = cs.encrypt_with_label(pt, "Welcome", b"ctx", b"secret", rng)
      } catch {
        @cs.CsError::CryptoError(@crypto.CryptoError::LowOrderPoint) =>
          e_hpke = true
        _ => fail("expected CsError(CryptoError(LowOrderPoint)) from HPKE")
      }
      assert_true(e_hpke)
    }
  }
}

///|
fn verify_fs_pcs_for_suite(cs : @cs.CipherSuite, seed : Bytes) -> Unit raise {
  let (alice, bob, alice_bundle, bob_bundle, welcome1, rng) = setup_two_member_group(
    cs, b"sec-26-gid", seed,
  )
  // Simulate full state compromise of Bob at epoch 1 by creating a second Bob
  // instance from the exact same epoch-1 Welcome (cloned epoch-1 state!)
  let bob_compromised_ep1 = @group.MlsGroup::from_welcome(
    cs,
    welcome1,
    bob_bundle,
    None,
  )
  ignore(alice_bundle)
  let auth_ep1 = alice.epoch_authenticator()
  let th_ep1 = alice.tree_hash()
  let exp_ep1 = alice.export_secret("app-key", b"session", 32)
  assert_eq(bob.epoch_authenticator(), auth_ep1)
  assert_eq(bob_compromised_ep1.epoch_authenticator(), auth_ep1)

  // --- Forward Secrecy (FS): intra-epoch generation keys are single-use ---
  let m0 = alice.protect_application(b"ep1-gen0", b"", rng)
  let m1 = alice.protect_application(b"ep1-gen1", b"", rng)
  assert_true(bob.process_message(m0) is Application(0U, b"ep1-gen0", b""))
  assert_true(bob.process_message(m1) is Application(0U, b"ep1-gen1", b""))
  let mut fs_replay = false
  try {
    let _ = bob.process_message(m0)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::ReplayDetected(0U)) =>
      fs_replay = true
    _ => fail("FS violated: consumed gen-0 key reused")
  }
  assert_true(fs_replay)

  // --- Post-Compromise Security (PCS): Bob rotates key via Update + Alice commits (ep 1 -> 2) ---
  let upd_prop = bob.propose_update(rng)
  let _ = alice.process_message(upd_prop)
  let out2 = alice.commit_pending(rng)
  let _ = bob.process_message(out2.commit_msg)
  assert_eq(alice.epoch(), 2UL)
  assert_eq(bob.epoch(), 2UL)
  let auth_ep2 = alice.epoch_authenticator()
  let th_ep2 = alice.tree_hash()
  let exp_ep2 = alice.export_secret("app-key", b"session", 32)
  assert_eq(bob.epoch_authenticator(), auth_ep2)
  assert_eq(bob.tree_hash(), th_ep2)
  assert_eq(bob.export_secret("app-key", b"session", 32), exp_ep2)
  // All epoch secrets & tree hash completely rotated
  assert_true(auth_ep2 != auth_ep1)
  assert_true(th_ep2 != th_ep1)
  assert_true(exp_ep2 != exp_ep1)

  // Compromised epoch-1 state CANNOT process Bob's post-update epoch-2 traffic
  let ep2_secret = alice.protect_application(b"pcs-healed-ep2", b"aad", rng)
  assert_true(
    bob.process_message(ep2_secret)
    is Application(0U, b"pcs-healed-ep2", b"aad"),
  )
  // Even if attacker tries to follow out2.commit_msg with bob_compromised_ep1:
  // bob_compromised_ep1 does NOT have Bob's newly generated update private key -> MissingPrivateKey!
  let _ = bob_compromised_ep1.process_message(upd_prop)
  let mut pcs_blocked = false
  try {
    let _ = bob_compromised_ep1.process_message(out2.commit_msg)
  } catch {
    @group.GroupError::MissingPrivateKey(_) => pcs_blocked = true
    _ => fail("expected MissingPrivateKey for stale compromised Bob state")
  }
  assert_true(pcs_blocked)
  // And compromised state cannot decrypt epoch-2 message (even with spoofed epoch=1)
  let ep2_spoofed : @types.PrivateMessage = {
    group_id: ep2_secret.group_id,
    epoch: 1UL,
    content_type: ep2_secret.content_type,
    authenticated_data: ep2_secret.authenticated_data,
    encrypted_sender_data: ep2_secret.encrypted_sender_data,
    ciphertext: ep2_secret.ciphertext,
  }
  let mut dec_blocked = false
  try {
    let _ = bob_compromised_ep1.process_message(ep2_spoofed)
  } catch {
    @group.GroupError::ScheduleError(@schedule.ScheduleError::DecryptionFailed) =>
      dec_blocked = true
    _ => fail("expected DecryptionFailed on compromised state decrypting ep2")
  }
  assert_true(dec_blocked)

  // --- PCS via member removal (add Charlie -> ep 3, remove Charlie -> ep 4) ---
  let charlie_b = @group.KeyPackageBundle::generate(cs, b"charlie", rng)
  let add_c = alice.propose_add(charlie_b.key_package, rng)
  let _ = bob.process_message(add_c)
  let out3 = alice.commit_pending(rng)
  let _ = bob.process_message(out3.commit_msg)
  let charlie_w = match out3.welcome {
    Some(w) => w
    None => fail("expected Welcome for Charlie")
  }
  let charlie = @group.MlsGroup::from_welcome(cs, charlie_w, charlie_b, None)
  let auth_ep3 = alice.epoch_authenticator()
  let th_ep3 = alice.tree_hash()
  let exp_ep3 = alice.export_secret("app-key", b"session", 32)
  assert_eq(charlie.epoch_authenticator(), auth_ep3)
  assert_true(auth_ep3 != auth_ep2)

  // Remove Charlie -> ep 4
  let rm_c = alice.propose_remove(2U, rng)
  let _ = bob.process_message(rm_c)
  let out4 = alice.commit_pending(rng)
  let _ = bob.process_message(out4.commit_msg)
  let auth_ep4 = alice.epoch_authenticator()
  let th_ep4 = alice.tree_hash()
  let exp_ep4 = alice.export_secret("app-key", b"session", 32)
  assert_eq(bob.epoch_authenticator(), auth_ep4)
  assert_true(auth_ep4 != auth_ep3)
  assert_true(th_ep4 != th_ep3 && th_ep4 != th_ep2)
  assert_true(exp_ep4 != exp_ep3 && exp_ep4 != exp_ep2)
  // Post-removal secret is readable by Bob, unreadable by Charlie
  let ep4_msg = alice.protect_application(b"post-kick-pcs", b"", rng)
  assert_true(
    bob.process_message(ep4_msg) is Application(0U, b"post-kick-pcs", b""),
  )
  let ep4_spoofed : @types.PrivateMessage = {
    group_id: ep4_msg.group_id,
    epoch: 3UL,
    content_type: ep4_msg.content_type,
    authenticated_data: ep4_msg.authenticated_data,
    encrypted_sender_data: ep4_msg.encrypted_sender_data,
    ciphertext: ep4_msg.ciphertext,
  }
  let mut charlie_blocked = false
  try {
    let _ = charlie.process_message(ep4_spoofed)
  } catch {
    @group.GroupError::ScheduleError(@schedule.ScheduleError::DecryptionFailed) =>
      charlie_blocked = true
    _ => fail("expected DecryptionFailed for kicked Charlie on ep4 message")
  }
  assert_true(charlie_blocked)
}

///|
test "SEC-26: Cryptographic Forward Secrecy (FS) & Post-Compromise Security (PCS) across CS1 and CS3" {
  verify_fs_pcs_for_suite(
    @cs.CipherSuite::X25519Aes128GcmSha256Ed25519,
    b"sec-26-cs1",
  )
  verify_fs_pcs_for_suite(
    @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519,
    b"sec-26-cs3",
  )
}

///|
/// Re-signs a `LeafNode` (KeyPackage source) and wrapping `KeyPackage` using
/// `sig_priv` so structural/capability/key rejections are tested independently
/// of signature validity.
fn sec_resign_key_package(
  cs : @cs.CipherSuite,
  base_kp : @types.KeyPackage,
  sig_priv : Bytes,
  init_key : Bytes,
  leaf_enc_key : Bytes,
  capabilities : @types.Capabilities,
  leaf_extensions : Array[@types.Extension],
  kp_extensions : Array[@types.Extension],
) -> @types.KeyPackage raise {
  let unsigned_leaf : @types.LeafNode = {
    encryption_key: leaf_enc_key,
    signature_key: base_kp.leaf_node.signature_key,
    credential: base_kp.leaf_node.credential,
    capabilities,
    leaf_node_source: @types.LeafNodeSource::KeyPackage,
    lifetime: base_kp.leaf_node.lifetime,
    parent_hash: None,
    extensions: leaf_extensions,
    signature: b"",
  }
  let leaf_sig = cs.sign_with_label(
    sig_priv,
    "LeafNodeTBS",
    unsigned_leaf.encode_tbs(None, None),
  )
  let signed_leaf : @types.LeafNode = {
    encryption_key: unsigned_leaf.encryption_key,
    signature_key: unsigned_leaf.signature_key,
    credential: unsigned_leaf.credential,
    capabilities: unsigned_leaf.capabilities,
    leaf_node_source: unsigned_leaf.leaf_node_source,
    lifetime: unsigned_leaf.lifetime,
    parent_hash: unsigned_leaf.parent_hash,
    extensions: unsigned_leaf.extensions,
    signature: leaf_sig,
  }
  let unsigned_kp : @types.KeyPackage = {
    version: base_kp.version,
    cipher_suite: base_kp.cipher_suite,
    init_key,
    leaf_node: signed_leaf,
    extensions: kp_extensions,
    signature: b"",
  }
  let kp_sig = cs.sign_with_label(
    sig_priv,
    "KeyPackageTBS",
    unsigned_kp.encode_tbs(),
  )
  {
    version: unsigned_kp.version,
    cipher_suite: unsigned_kp.cipher_suite,
    init_key: unsigned_kp.init_key,
    leaf_node: unsigned_kp.leaf_node,
    extensions: unsigned_kp.extensions,
    signature: kp_sig,
  }
}

///|
/// Builds a `Commit` `LeafNode` with a custom `encryption_key` and computes the
/// exact `parent_hash` chain top-down for a given `path_nodes` list, signing it
/// with `sign_priv` so `merge_update_path_nodes` reaches key validation checks.
fn sec_forge_signed_update_path(
  cs : @cs.CipherSuite,
  base_tree : @tree.RatchetTreeState,
  sender_leaf : UInt32,
  group_id : Bytes,
  sign_priv : Bytes,
  base_leaf : @types.LeafNode,
  new_leaf_enc_key : Bytes,
  path_nodes : Array[@types.UpdatePathNode],
) -> @types.UpdatePath raise {
  let work = base_tree.clone()
  let n_leaves = work.n_leaves()
  let fdp = work.filtered_direct_path(sender_leaf)
  let dp = @treemath.direct_path(@treemath.leaf_to_node(sender_leaf), n_leaves)
  for i = 0; i < dp.length(); i = i + 1 {
    work.nodes[dp[i].reinterpret_as_int()] = None
  }
  let k = fdp.length()
  let mut cur_ph = b""
  for rev = 0; rev < k; rev = rev + 1 {
    let i = k - 1 - rev
    let (d_node, c_node) = fdp[i]
    let enc_key = path_nodes[i].encryption_key
    work.nodes[d_node.reinterpret_as_int()] = Some(
      @types.Node::Parent({
        encryption_key: enc_key,
        parent_hash: cur_ph,
        unmerged_leaves: [],
      }),
    )
    let sibling_hash = work.node_hash(cs, c_node)
    let w = @tls.Writer::new()
    w.write_opaque(enc_key)
    w.write_opaque(cur_ph)
    w.write_opaque(sibling_hash)
    cur_ph = cs.hash(w.to_bytes())
  }
  let unsigned_leaf : @types.LeafNode = {
    encryption_key: new_leaf_enc_key,
    signature_key: base_leaf.signature_key,
    credential: base_leaf.credential,
    capabilities: base_leaf.capabilities,
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: Some(cur_ph),
    extensions: base_leaf.extensions,
    signature: b"",
  }
  let sig = cs.sign_with_label(
    sign_priv,
    "LeafNodeTBS",
    unsigned_leaf.encode_tbs(Some(group_id), Some(sender_leaf)),
  )
  let signed_leaf : @types.LeafNode = {
    encryption_key: unsigned_leaf.encryption_key,
    signature_key: unsigned_leaf.signature_key,
    credential: unsigned_leaf.credential,
    capabilities: unsigned_leaf.capabilities,
    leaf_node_source: unsigned_leaf.leaf_node_source,
    lifetime: unsigned_leaf.lifetime,
    parent_hash: unsigned_leaf.parent_hash,
    extensions: unsigned_leaf.extensions,
    signature: sig,
  }
  { leaf_node: signed_leaf, nodes: path_nodes, }
}

///|
test "SEC-27: Ed25519 identity point and order-8 small-order torsion public key signature forgery rejected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"sec-27-seed")
  // Identity point O = (0, 1): compressed [0x01, 0x00, ..., 0x00]
  let identity_pk = @tls.bytes_from_hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  // Forged signature with R = O, S = 0: satisfies [0]B == O + [k]O without torsion rejection
  let forged_sig_o = @tls.bytes_concat([identity_pk, Bytes::make(32, b'\x00')])
  // 1. Direct Ed25519 verification rejects identity public key
  assert_false(@crypto.ed25519_verify(identity_pk, b"", forged_sig_o))
  assert_false(
    @crypto.ed25519_verify(identity_pk, b"forged MLS Commit", forged_sig_o),
  )
  let mut id_raised = false
  @crypto.ed25519_verify_or_raise(identity_pk, b"forged", forged_sig_o) catch {
    @crypto.CryptoError::InvalidSignature => id_raised = true
    _ => fail("expected CryptoError::InvalidSignature for identity public key")
  }
  assert_true(id_raised)
  assert_false(
    cs.verify_with_label(identity_pk, "KeyPackageTBS", b"any", forged_sig_o),
  )
  // 2. All remaining 7 canonical 8-torsion points (order 2, 4, and 8) rejected
  let small_order_pks : Array[Bytes] = [
    // Order 2: (0, -1)
    @tls.bytes_from_hex(
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
    // Order 4: (+sqrt(-1), 0) and (-sqrt(-1), 0)
    @tls.bytes_from_hex(
      "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    @tls.bytes_from_hex(
      "0000000000000000000000000000000000000000000000000000000000000080",
    ),
    // Order 8: four points of exact order 8
    @tls.bytes_from_hex(
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ),
    @tls.bytes_from_hex(
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ),
    @tls.bytes_from_hex(
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    ),
    @tls.bytes_from_hex(
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ),
  ]
  for i = 0; i < small_order_pks.length(); i = i + 1 {
    let pk = small_order_pks[i]
    // Sweep 32 messages so k mod 8 == 0 collisions are guaranteed to be hit
    for m = 0; m < 32; m = m + 1 {
      let msg = Bytes::make(1, m.to_byte())
      assert_false(@crypto.ed25519_verify(pk, msg, forged_sig_o))
    }
  }
  // 3. End-to-end KeyPackage forgery using identity_pk and order-8 torsion pk with R=O, S=0
  let alice = @group.MlsGroup::create(cs, b"sec-27-gid", b"alice", rng)
  let base_b = @group.KeyPackageBundle::generate(cs, b"forger", rng)
  let base_kp = base_b.key_package
  let forged_pks = [identity_pk, small_order_pks[3], small_order_pks[5]]
  for i = 0; i < forged_pks.length(); i = i + 1 {
    let bad_leaf : @types.LeafNode = {
      encryption_key: base_kp.leaf_node.encryption_key,
      signature_key: forged_pks[i],
      credential: base_kp.leaf_node.credential,
      capabilities: base_kp.leaf_node.capabilities,
      leaf_node_source: base_kp.leaf_node.leaf_node_source,
      lifetime: base_kp.leaf_node.lifetime,
      parent_hash: base_kp.leaf_node.parent_hash,
      extensions: base_kp.leaf_node.extensions,
      signature: forged_sig_o,
    }
    let forged_kp : @types.KeyPackage = {
      version: base_kp.version,
      cipher_suite: base_kp.cipher_suite,
      init_key: base_kp.init_key,
      leaf_node: bad_leaf,
      extensions: base_kp.extensions,
      signature: forged_sig_o,
    }
    let mut kp_err = false
    @group.verify_key_package(cs, forged_kp) catch {
      @group.GroupError::InvalidKeyPackage(_) => kp_err = true
      _ => fail("expected InvalidKeyPackage for torsion signature_key")
    }
    assert_true(kp_err)
    let mut prop_err = false
    try {
      let _ = alice.propose_add(forged_kp, rng)
    } catch {
      @group.GroupError::InvalidKeyPackage(_) => prop_err = true
      _ =>
        fail(
          "expected InvalidKeyPackage in propose_add for torsion signature_key",
        )
    }
    assert_true(prop_err)
  }
}

///|
test "SEC-28: Malicious UpdatePath duplicate encryption_key and low-order public key rejected with zero state pollution" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let gid = b"sec-28-gid"
  let (alice, bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, gid, b"sec-28-seed",
  )
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  let rt = @tree.RatchetTreeState::from_nodes(alice.ratchet_tree_nodes())
  let nodes_before = rt.to_nodes()
  let th_before = rt.tree_hash(cs)
  let alice_leaf = match rt.get_leaf(0U) {
    Some(l) => l
    None => fail("expected Alice leaf 0")
  }
  let bob_leaf = match rt.get_leaf(1U) {
    Some(l) => l
    None => fail("expected Bob leaf 1")
  }
  // Generate a baseline genuine UpdatePath from Alice on a cloned tree
  let rt_gen = rt.clone()
  let prepared = rt_gen.prepare_update_path_tree(
    cs,
    0U,
    alice_leaf,
    alice_bundle.signature_priv,
    gid,
    rng.next_bytes(32),
  )
  let dummy_gc = verified.group_info.group_context.to_bytes()
  let genuine_up = rt_gen.encrypt_path_secrets(
    cs,
    0U,
    prepared,
    dummy_gc,
    [],
    rng,
  )
  let (_, fresh_leaf_pub) = cs.kem_keypair_from_ikm(rng.next_bytes(32))
  // Case A: UpdatePath parent node duplicates Bob's leaf encryption_key (with valid parent_hash & leaf sig!)
  let dup_parent_nodes : Array[@types.UpdatePathNode] = [
    {
      encryption_key: bob_leaf.encryption_key,
      encrypted_path_secret: genuine_up.nodes[0].encrypted_path_secret,
    },
  ]
  let dup_parent_up = sec_forge_signed_update_path(
    cs,
    rt,
    0U,
    gid,
    alice_bundle.signature_priv,
    alice_leaf,
    fresh_leaf_pub,
    dup_parent_nodes,
  )
  let mut e_dup_parent = false
  rt.merge_update_path_nodes(cs, 0U, dup_parent_up, gid, []) catch {
    @tree.TreeError::DuplicateKey => e_dup_parent = true
    _ => fail("expected DuplicateKey for UpdatePath parent key collision")
  }
  assert_true(e_dup_parent)
  assert_eq(rt.to_nodes(), nodes_before)
  assert_eq(rt.tree_hash(cs), th_before)

  // Case B: UpdatePath leaf reuses Alice's old leaf encryption_key (with valid parent_hash & leaf sig!)
  let dup_self_up = sec_forge_signed_update_path(
    cs,
    rt,
    0U,
    gid,
    alice_bundle.signature_priv,
    alice_leaf,
    alice_leaf.encryption_key,
    genuine_up.nodes,
  )
  let mut e_dup_self = false
  rt.merge_update_path_nodes(cs, 0U, dup_self_up, gid, []) catch {
    @tree.TreeError::DuplicateKey => e_dup_self = true
    _ => fail("expected DuplicateKey for UpdatePath self leaf key reuse")
  }
  assert_true(e_dup_self)
  assert_eq(rt.to_nodes(), nodes_before)
  assert_eq(rt.tree_hash(cs), th_before)

  // Case C: UpdatePath parent node injects low-order X25519 point (all-zero & order-8)
  let low_zero = Bytes::make(32, b'\x00')
  let low_order8 = @tls.bytes_from_hex(
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  )
  for low_pk in [low_zero, low_order8] {
    let low_parent_up : @types.UpdatePath = {
      leaf_node: genuine_up.leaf_node,
      nodes: [
        {
          encryption_key: low_pk,
          encrypted_path_secret: genuine_up.nodes[0].encrypted_path_secret,
        },
      ],
    }
    let mut e_low_par = false
    rt.merge_update_path_nodes(cs, 0U, low_parent_up, gid, []) catch {
      @tree.TreeError::CsError(
        @cs.CsError::CryptoError(@crypto.CryptoError::LowOrderPoint),
      ) => e_low_par = true
      _ => fail("expected LowOrderPoint for UpdatePath parent node")
    }
    assert_true(e_low_par)
    assert_eq(rt.to_nodes(), nodes_before)
    assert_eq(rt.tree_hash(cs), th_before)
  }

  // Case D: UpdatePath leaf injects low-order X25519 point (u = 1)
  let low_u1 = @tls.bytes_from_hex(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let low_leaf_up : @types.UpdatePath = {
    leaf_node: {
      encryption_key: low_u1,
      signature_key: genuine_up.leaf_node.signature_key,
      credential: genuine_up.leaf_node.credential,
      capabilities: genuine_up.leaf_node.capabilities,
      leaf_node_source: genuine_up.leaf_node.leaf_node_source,
      lifetime: genuine_up.leaf_node.lifetime,
      parent_hash: genuine_up.leaf_node.parent_hash,
      extensions: genuine_up.leaf_node.extensions,
      signature: genuine_up.leaf_node.signature,
    },
    nodes: genuine_up.nodes,
  }
  let mut e_low_leaf = false
  rt.merge_update_path_nodes(cs, 0U, low_leaf_up, gid, []) catch {
    @tree.TreeError::CsError(
      @cs.CsError::CryptoError(@crypto.CryptoError::LowOrderPoint),
    ) => e_low_leaf = true
    _ => fail("expected LowOrderPoint for UpdatePath leaf_node")
  }
  assert_true(e_low_leaf)
  assert_eq(rt.to_nodes(), nodes_before)
  assert_eq(rt.tree_hash(cs), th_before)

  // Case E: Live MlsGroup receives signed+encrypted Commit with duplicate-key UpdatePath -> rejected, group NOT bricked!
  let bob_auth_before = bob.epoch_authenticator()
  let bob_th_before = bob.tree_hash()
  let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
  let (hs_key, hs_nonce) = st.handshake_key_nonce_for_generation(0U, 0U)
  let bad_commit_fc : @types.FramedContent = {
    group_id: gid,
    epoch: 1UL,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit({
      proposals: [],
      path: Some(dup_parent_up),
    }),
  }
  let bad_commit_sig = @schedule.sign_framed_content(
    cs,
    alice_bundle.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    bad_commit_fc,
    Some(verified.group_info.group_context),
  )
  let bad_commit_msg = @schedule.encrypt_private_message_with_keys(
    cs,
    verified.secrets.sender_data_secret,
    { leaf_index: 0U, generation: 0U, reuse_guard: b"\x28\x28\x28\x28", },
    hs_key,
    hs_nonce,
    bad_commit_fc,
    {
      signature: bad_commit_sig,
      confirmation_tag: Some(Bytes::make(32, b'\xEE')),
    },
    0,
  )
  let mut e_group_dup = false
  try {
    let _ = bob.process_message(bad_commit_msg)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::DuplicateKey) =>
      e_group_dup = true
    _ =>
      fail("expected GroupError::TreeError(DuplicateKey) on malicious Commit")
  }
  assert_true(e_group_dup)
  assert_eq(bob.epoch(), 1UL)
  assert_eq(bob.epoch_authenticator(), bob_auth_before)
  assert_eq(bob.tree_hash(), bob_th_before)
  assert_true(bob.is_active())

  // Genuine UpdatePath merges cleanly into rt, and live group advances & communicates normally
  rt.merge_update_path_nodes(cs, 0U, genuine_up, gid, [])
  let out2 = alice.commit_pending(rng)
  assert_true(bob.process_message(out2.commit_msg) is Commit(0U, 2UL))
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
  let ok_msg = alice.protect_application(
    b"group-healthy-after-attack", b"", rng,
  )
  assert_true(
    bob.process_message(ok_msg)
    is Application(0U, b"group-healthy-after-attack", b""),
  )
}

///|
test "SEC-29: Malicious Commit with Remove(victim) and path=None (or invalid UpdatePath) rejected without deactivating victim" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let gid = b"sec-29-gid"
  let (alice, bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, gid, b"sec-29-seed",
  )
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  let bob_auth_before = bob.epoch_authenticator()
  let bob_th_before = bob.tree_hash()
  // Construct a validly signed & encrypted Commit containing Remove(Bob=1U) with path = None
  let malicious_commit : @types.Commit = {
    proposals: [@types.ProposalOrRef::Proposal(@types.Proposal::Remove(1U))],
    path: None,
  }
  let fc : @types.FramedContent = {
    group_id: gid,
    epoch: 1UL,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit(malicious_commit),
  }
  let sig = @schedule.sign_framed_content(
    cs,
    alice_bundle.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc,
    Some(verified.group_info.group_context),
  )
  // Compute realistic confirmation_tag for the path-less Commit (using zero commit_secret)
  let post_rm_tree = @tree.RatchetTreeState::from_nodes(
    alice.ratchet_tree_nodes(),
  )
  post_rm_tree.remove_leaf(1U)
  let interim_ep1 = @schedule.compute_interim_transcript_hash(
    cs,
    verified.group_info.group_context.confirmed_transcript_hash,
    verified.group_info.confirmation_tag,
  )
  let conf_th_ep2 = @schedule.compute_confirmed_transcript_hash(
    cs,
    interim_ep1,
    {
      wire_format: @types.WireFormat::MlsPrivateMessage,
      content: fc,
      signature: sig,
    },
  )
  let forged_gc2 : @types.GroupContext = {
    version: verified.group_info.group_context.version,
    cipher_suite: verified.group_info.group_context.cipher_suite,
    group_id: gid,
    epoch: 2UL,
    tree_hash: post_rm_tree.tree_hash(cs),
    confirmed_transcript_hash: conf_th_ep2,
    extensions: [],
  }
  let forged_secrets = @schedule.derive_epoch_secrets(
    cs,
    verified.secrets.init_secret,
    cs.zero_secret(),
    cs.zero_secret(),
    forged_gc2.to_bytes(),
  )
  let forged_conf_tag = @schedule.compute_confirmation_tag(
    cs,
    forged_secrets.confirmation_key,
    conf_th_ep2,
  )
  let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
  let (hs_key, hs_nonce) = st.handshake_key_nonce_for_generation(0U, 0U)
  let sd : @types.MlsSenderData = {
    leaf_index: 0U,
    generation: 0U,
    reuse_guard: b"\x29\x01\x02\x03",
  }
  let forged_kick_msg = @schedule.encrypt_private_message_with_keys(
    cs,
    verified.secrets.sender_data_secret,
    sd,
    hs_key,
    hs_nonce,
    fc,
    { signature: sig, confirmation_tag: Some(forged_conf_tag), },
    0,
  )
  // Bob MUST reject the illegal path-less Remove Commit and remain active!
  let mut got_invalid_commit = false
  try {
    let _ = bob.process_message(forged_kick_msg)
  } catch {
    @group.GroupError::InvalidCommit(_) => got_invalid_commit = true
    _ => fail("expected GroupError::InvalidCommit on path-less Remove(Bob)")
  }
  assert_true(got_invalid_commit)
  assert_true(bob.is_active())
  assert_eq(bob.epoch(), 1UL)
  assert_eq(bob.epoch_authenticator(), bob_auth_before)
  assert_eq(bob.tree_hash(), bob_th_before)

  // Also verify Remove(Bob) with an invalid UpdatePath (reusing Alice's old leaf key) is rejected
  let bad_leaf = match post_rm_tree.get_leaf(0U) {
    Some(l) => l
    None => fail("expected Alice leaf 0")
  }
  let bad_up = sec_forge_signed_update_path(
    cs,
    post_rm_tree,
    0U,
    gid,
    alice_bundle.signature_priv,
    bad_leaf,
    bad_leaf.encryption_key,
    [],
  )
  let fc_bad_up : @types.FramedContent = {
    group_id: gid,
    epoch: 1UL,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit({
      proposals: [@types.ProposalOrRef::Proposal(@types.Proposal::Remove(1U))],
      path: Some(bad_up),
    }),
  }
  let sig_bad_up = @schedule.sign_framed_content(
    cs,
    alice_bundle.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc_bad_up,
    Some(verified.group_info.group_context),
  )
  let forged_bad_up_msg = @schedule.encrypt_private_message_with_keys(
    cs,
    verified.secrets.sender_data_secret,
    sd,
    hs_key,
    hs_nonce,
    fc_bad_up,
    { signature: sig_bad_up, confirmation_tag: Some(forged_conf_tag), },
    0,
  )
  let mut got_bad_up_err = false
  try {
    let _ = bob.process_message(forged_bad_up_msg)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::DuplicateKey) =>
      got_bad_up_err = true
    _ => fail("expected TreeError(DuplicateKey) on Remove(Bob) with bad path")
  }
  assert_true(got_bad_up_err)
  assert_true(bob.is_active())
  assert_eq(bob.epoch(), 1UL)

  // Bob continues receiving legitimate application and Commit messages cleanly (gen 0 ratchet unpolluted!)
  let legit_app = alice.protect_application(b"bob-still-active", b"aad", rng)
  assert_true(
    bob.process_message(legit_app)
    is Application(0U, b"bob-still-active", b"aad"),
  )
  let legit_commit = alice.commit_pending(rng)
  assert_true(bob.process_message(legit_commit.commit_msg) is Commit(0U, 2UL))
  assert_true(bob.is_active())
  assert_eq(bob.epoch(), 2UL)
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
}

///|
test "SEC-30: Concurrent and poisoned pending_proposals deterministically filtered by commit_pending without deadlock" {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let (alice, bob, charlie, rng) = setup_three_member_group(
    cs, b"sec-30-gid", b"sec-30-seed",
  )
  // Add Eve (leaf 3) -> epoch 3
  let eve_bundle = @group.KeyPackageBundle::generate(cs, b"eve", rng)
  let prop_add_eve = alice.propose_add(eve_bundle.key_package, rng)
  let _ = bob.process_message(prop_add_eve)
  let _ = charlie.process_message(prop_add_eve)
  let out3 = alice.commit_pending(rng)
  let _ = bob.process_message(out3.commit_msg)
  let _ = charlie.process_message(out3.commit_msg)
  let welcome_eve = match out3.welcome {
    Some(w) => w
    None => fail("expected Welcome for Eve")
  }
  let eve = @group.MlsGroup::from_welcome(cs, welcome_eve, eve_bundle, None)
  assert_eq(eve.my_leaf_index(), 3U)
  assert_eq(alice.epoch(), 3UL)
  assert_eq(eve.epoch_authenticator(), alice.epoch_authenticator())

  // Flood conflicting & poisoned proposals at epoch 3:
  // 1. Alice and Charlie both concurrently propose_remove(Eve=3U)
  let rm_eve_a = alice.propose_remove(3U, rng)
  let rm_eve_c = charlie.propose_remove(3U, rng)
  // 2. Eve maliciously proposes removing Alice (the committer!) and also sends Update for herself
  let rm_alice_e = eve.propose_remove(0U, rng)
  let upd_eve = eve.propose_update(rng)
  // 3. Alice sends her own Update; Bob and Charlie each send multiple Updates
  let upd_alice = alice.propose_update(rng)
  let upd_charlie_1 = charlie.propose_update(rng)
  let upd_charlie_2 = charlie.propose_update(rng)
  let upd_bob_1 = bob.propose_update(rng)
  let upd_bob_2 = bob.propose_update(rng)

  // Deliver all proposals to every other member (Alice receives every conflicting proposal!)
  for
    msg in [
      rm_eve_c, rm_alice_e, upd_eve, upd_charlie_1, upd_charlie_2, upd_bob_1, upd_bob_2,
    ] {
    let _ = alice.process_message(msg)
  }
  for
    msg in [
      rm_eve_a, rm_eve_c, rm_alice_e, upd_eve, upd_alice, upd_charlie_1, upd_charlie_2,
    ] {
    let _ = bob.process_message(msg)
  }
  for msg in [rm_eve_a, rm_alice_e, upd_eve, upd_alice, upd_bob_1, upd_bob_2] {
    let _ = charlie.process_message(msg)
  }
  for
    msg in [
      rm_eve_a, rm_eve_c, upd_alice, upd_charlie_1, upd_charlie_2, upd_bob_1, upd_bob_2,
    ] {
    let _ = eve.process_message(msg)
  }

  // Alice calls commit_pending -> must deterministically filter conflicts & advance to epoch 4!
  let out4 = alice.commit_pending(rng)
  assert_eq(out4.new_epoch, 4UL)
  assert_eq(alice.epoch(), 4UL)
  assert_eq(alice.members().length(), 3)

  // Bob and Charlie synchronize cleanly to epoch 4
  assert_true(bob.process_message(out4.commit_msg) is Commit(0U, 4UL))
  assert_true(charlie.process_message(out4.commit_msg) is Commit(0U, 4UL))
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
  assert_eq(charlie.epoch_authenticator(), alice.epoch_authenticator())
  assert_eq(bob.tree_hash(), alice.tree_hash())
  assert_eq(charlie.tree_hash(), alice.tree_hash())

  // Eve is cleanly evicted when processing the Commit
  let mut eve_kicked = false
  try {
    let _ = eve.process_message(out4.commit_msg)
  } catch {
    @group.GroupError::MemberRemoved => eve_kicked = true
    _ => fail("expected MemberRemoved for Eve")
  }
  assert_true(eve_kicked)
  assert_false(eve.is_active())

  // All surviving members communicate bidirectionally at epoch 4
  let m_a = alice.protect_application(b"from-alice-ep4", b"", rng)
  let m_b = bob.protect_application(b"from-bob-ep4", b"", rng)
  let m_c = charlie.protect_application(b"from-charlie-ep4", b"", rng)
  assert_true(
    bob.process_message(m_a) is Application(0U, b"from-alice-ep4", b""),
  )
  assert_true(
    charlie.process_message(m_a) is Application(0U, b"from-alice-ep4", b""),
  )
  assert_true(
    alice.process_message(m_b) is Application(1U, b"from-bob-ep4", b""),
  )
  assert_true(
    charlie.process_message(m_b) is Application(1U, b"from-bob-ep4", b""),
  )
  assert_true(
    alice.process_message(m_c) is Application(2U, b"from-charlie-ep4", b""),
  )
  assert_true(
    bob.process_message(m_c) is Application(2U, b"from-charlie-ep4", b""),
  )
}

///|
test "SEC-31: SecretTree O(1) atomic staging, non-empty root parent_hash, all-blank tree, and Welcome missing path_secret unmerged check" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  // Part A: SecretTree O(1) atomic stage_key_nonce / commit_stage anti-replay & zero state pollution
  let st = @tree.SecretTree::new(cs, Bytes::make(32, b'\x5A'), 4U)
  let s0_trial = st.stage_key_nonce(0U, 0U, true)
  // Stage forward jump (gen 5) and discard without committing -> must NOT pollute live ratchet
  let _ = st.stage_key_nonce(0U, 5U, true)
  // Excessive forward jump rejected without mutating ratchet
  let mut e_far = false
  try {
    let _ = st.stage_key_nonce(0U, 1001U, true)
  } catch {
    @tree.TreeError::GenerationTooFarAhead(1001U) => e_far = true
    _ => fail("expected GenerationTooFarAhead(1001)")
  }
  assert_true(e_far)
  // Gen 0 is still unconsumed and produces identical (key, nonce)
  let s0_commit = st.stage_key_nonce(0U, 0U, true)
  assert_eq(s0_commit.key(), s0_trial.key())
  assert_eq(s0_commit.nonce(), s0_trial.nonce())
  st.commit_stage(s0_commit)
  // After commit_stage, gen 0 replay is immediately rejected
  let mut e_replay_app = false
  try {
    let _ = st.stage_key_nonce(0U, 0U, true)
  } catch {
    @tree.TreeError::ReplayDetected(0U) => e_replay_app = true
    _ => fail("expected ReplayDetected(0) after commit_stage")
  }
  assert_true(e_replay_app)
  // Handshake ratchet staging & commit works independently
  let hs0 = st.stage_key_nonce(0U, 0U, false)
  st.commit_stage(hs0)
  let mut e_replay_hs = false
  try {
    let _ = st.stage_key_nonce(0U, 0U, false)
  } catch {
    @tree.TreeError::ReplayDetected(0U) => e_replay_hs = true
    _ => fail("expected ReplayDetected(0) on handshake ratchet")
  }
  assert_true(e_replay_hs)

  // Part B: Non-blank root with non-empty parent_hash rejected even when child parent_hash matches it
  let (alice, _bob, alice_bundle, bob_bundle, welcome, rng) = setup_two_member_group(
    cs, b"sec-31-gid", b"sec-31-seed",
  )
  let base_nodes = alice.ratchet_tree_nodes()
  let root_parent = match base_nodes[1] {
    Some(@types.Node::Parent(p)) => p
    _ => fail("expected non-blank root parent node 1")
  }
  let leaf0 = match base_nodes[0] {
    Some(@types.Node::Leaf(l)) => l
    _ => fail("expected Alice leaf 0")
  }
  let bad_root_nodes = base_nodes.copy()
  bad_root_nodes[1] = Some(
    @types.Node::Parent({
      encryption_key: root_parent.encryption_key,
      parent_hash: Bytes::make(32, b'\x99'),
      unmerged_leaves: root_parent.unmerged_leaves,
    }),
  )
  let bad_root_tree = @tree.RatchetTreeState::from_nodes(bad_root_nodes)
  // Recompute leaf 0's parent_hash to match the forged non-empty root parent_hash
  let forged_child_ph = bad_root_tree.compute_parent_hash(cs, 1U, 0U)
  bad_root_tree.nodes[0] = Some(
    @types.Node::Leaf({
      encryption_key: leaf0.encryption_key,
      signature_key: leaf0.signature_key,
      credential: leaf0.credential,
      capabilities: leaf0.capabilities,
      leaf_node_source: leaf0.leaf_node_source,
      lifetime: leaf0.lifetime,
      parent_hash: Some(forged_child_ph),
      extensions: leaf0.extensions,
      signature: leaf0.signature,
    }),
  )
  let mut e_root_ph = false
  bad_root_tree.validate_parent_hashes(cs) catch {
    @tree.TreeError::InvalidParentHash => e_root_ph = true
    _ =>
      fail(
        "expected InvalidParentHash for non-blank root with non-empty parent_hash",
      )
  }
  assert_true(e_root_ph)

  // Part C: Empty / all-blank RatchetTree rejected with EmptyTree
  let mut e_zero = false
  try {
    let _ = @tree.RatchetTreeState::from_nodes([])
  } catch {
    @tree.TreeError::EmptyTree => e_zero = true
    _ => fail("expected EmptyTree for 0-length nodes")
  }
  assert_true(e_zero)
  for blank_nodes in [[None], [None, None, None]] {
    let blank_tree = @tree.RatchetTreeState::from_nodes(blank_nodes)
    let mut e_blank = false
    blank_tree.validate_tree_structure() catch {
      @tree.TreeError::EmptyTree => e_blank = true
      _ => fail("expected EmptyTree for all-blank RatchetTree")
    }
    assert_true(e_blank)
  }

  // Part D: Welcome with path_secret = None rejected when joiner is NOT in ancestor unmerged_leaves
  let verified = @group.verify_and_decrypt_welcome(
    cs,
    welcome,
    bob_bundle.init_priv,
    bob_bundle.key_package,
    alice_bundle.key_package.leaf_node.signature_key,
  )
  // Root node 1 is non-blank with unmerged_leaves = [], so stripping path_secret violates RFC 9420 §12.4.3.1
  let stripped_gs : @types.GroupSecrets = {
    joiner_secret: verified.group_secrets.joiner_secret,
    path_secret: None,
    psks: verified.group_secrets.psks,
  }
  let forged_welcome = repackage_welcome(
    cs,
    verified.group_info,
    stripped_gs,
    bob_bundle.key_package,
    rng,
  )
  let mut e_unmerged = false
  try {
    let _ = @group.MlsGroup::from_welcome(cs, forged_welcome, bob_bundle, None)
  } catch {
    @group.GroupError::TreeError(@tree.TreeError::InvalidUnmergedLeaf) =>
      e_unmerged = true
    _ =>
      fail(
        "expected GroupError::TreeError(InvalidUnmergedLeaf) on Welcome missing path_secret",
      )
  }
  assert_true(e_unmerged)
}

///|
test "SEC-32: KeyPackage invalid Capabilities / duplicate extensions / low-order init_key and schedule context/sender mismatch rejected" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"sec-32-seed")
  let alice = @group.MlsGroup::create(cs, b"sec-32-gid", b"alice", rng)
  let base_b = @group.KeyPackageBundle::generate(cs, b"bob", rng)
  let base_kp = base_b.key_package
  let base_caps = base_kp.leaf_node.capabilities

  // 1. Capabilities missing mls10 protocol version (validly re-signed!)
  let kp_no_mls10 = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    base_kp.leaf_node.encryption_key,
    {
      versions: [2U],
      cipher_suites: base_caps.cipher_suites,
      extensions: base_caps.extensions,
      proposals: base_caps.proposals,
      credentials: base_caps.credentials,
    },
    [],
    [],
  )
  // 2. Capabilities missing current cipher_suite CS1 (validly re-signed!)
  let kp_no_cs = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    base_kp.leaf_node.encryption_key,
    {
      versions: base_caps.versions,
      cipher_suites: [
        @types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
      ],
      extensions: base_caps.extensions,
      proposals: base_caps.proposals,
      credentials: base_caps.credentials,
    },
    [],
    [],
  )
  // 3. Capabilities missing leaf credential type (validly re-signed!)
  let kp_no_cred = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    base_kp.leaf_node.encryption_key,
    {
      versions: base_caps.versions,
      cipher_suites: base_caps.cipher_suites,
      extensions: base_caps.extensions,
      proposals: base_caps.proposals,
      credentials: [@types.CREDENTIAL_TYPE_X509],
    },
    [],
    [],
  )
  // 4. Duplicate extension_type in KeyPackage.extensions (validly re-signed!)
  let dup_exts : Array[@types.Extension] = [
    { extension_type: @types.EXT_APPLICATION_ID, extension_data: b"id-1", },
    { extension_type: @types.EXT_APPLICATION_ID, extension_data: b"id-2", },
  ]
  let kp_dup_kp_ext = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    base_kp.leaf_node.encryption_key,
    base_caps,
    [],
    dup_exts,
  )
  // 5. Duplicate extension_type in LeafNode.extensions (validly re-signed!)
  let kp_dup_leaf_ext = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    base_kp.leaf_node.encryption_key,
    base_caps,
    dup_exts,
    [],
  )
  // 6. Low-order init_key (all-zero & order-8 X25519 point) and low-order leaf encryption_key (validly re-signed!)
  let low_zero = Bytes::make(32, b'\x00')
  let low_order8 = @tls.bytes_from_hex(
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  )
  let kp_low_init_zero = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    low_zero,
    base_kp.leaf_node.encryption_key,
    base_caps,
    [],
    [],
  )
  let kp_low_init_ord8 = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    low_order8,
    base_kp.leaf_node.encryption_key,
    base_caps,
    [],
    [],
  )
  let kp_low_leaf_enc = sec_resign_key_package(
    cs,
    base_kp,
    base_b.signature_priv,
    base_kp.init_key,
    low_zero,
    base_caps,
    [],
    [],
  )
  for
    bad_kp in [
      kp_no_mls10, kp_no_cs, kp_no_cred, kp_dup_kp_ext, kp_dup_leaf_ext, kp_low_init_zero,
      kp_low_init_ord8, kp_low_leaf_enc,
    ] {
    let mut v_err = false
    @group.verify_key_package(cs, bad_kp) catch {
      @group.GroupError::InvalidKeyPackage(_) => v_err = true
      _ => fail("expected InvalidKeyPackage from verify_key_package")
    }
    assert_true(v_err)
    let mut p_err = false
    try {
      let _ = alice.propose_add(bad_kp, rng)
    } catch {
      @group.GroupError::InvalidKeyPackage(_) => p_err = true
      _ => fail("expected InvalidKeyPackage from propose_add")
    }
    assert_true(p_err)
  }

  // 7. schedule public API checks: sender != leaf_index and cross-group group_id / epoch mismatch
  let (sig_priv, sig_pub) = cs.signature_keypair_from_seed(rng.next_bytes(32))
  let sd_secret = rng.next_bytes(32)
  let membership_key = rng.next_bytes(32)
  let content_key = rng.next_bytes(16)
  let content_nonce = rng.next_bytes(12)
  let gc : @types.GroupContext = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    group_id: b"sec-32-group-a",
    epoch: 7UL,
    tree_hash: Bytes::make(32, b'\x12'),
    confirmed_transcript_hash: Bytes::make(32, b'\x34'),
    extensions: [],
  }
  let gc_wrong_gid : @types.GroupContext = {
    version: gc.version,
    cipher_suite: gc.cipher_suite,
    group_id: b"sec-32-group-b",
    epoch: gc.epoch,
    tree_hash: gc.tree_hash,
    confirmed_transcript_hash: gc.confirmed_transcript_hash,
    extensions: gc.extensions,
  }
  let gc_wrong_epoch : @types.GroupContext = {
    version: gc.version,
    cipher_suite: gc.cipher_suite,
    group_id: gc.group_id,
    epoch: 8UL,
    tree_hash: gc.tree_hash,
    confirmed_transcript_hash: gc.confirmed_transcript_hash,
    extensions: gc.extensions,
  }
  let app_fc : @types.FramedContent = {
    group_id: gc.group_id,
    epoch: gc.epoch,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"aad",
    content: @types.FramedContentBody::Application(b"payload"),
  }
  let app_sig = @schedule.sign_framed_content(
    cs,
    sig_priv,
    @types.WireFormat::MlsPrivateMessage,
    app_fc,
    Some(gc),
  )
  let app_auth : @types.FramedContentAuthData = {
    signature: app_sig,
    confirmation_tag: None,
  }
  // 7a. encrypt_private_message_with_keys rejects sender (0U) != sender_data.leaf_index (1U)
  let mut e_sender = false
  try {
    let _ = @schedule.encrypt_private_message_with_keys(
      cs,
      sd_secret,
      { leaf_index: 1U, generation: 0U, reuse_guard: b"\xAA\xBB\xCC\xDD", },
      content_key,
      content_nonce,
      app_fc,
      app_auth,
      0,
    )
  } catch {
    @schedule.ScheduleError::SenderMismatch => e_sender = true
    _ => fail("expected ScheduleError::SenderMismatch")
  }
  assert_true(e_sender)

  // 7b. decrypt_private_message_with_keys rejects group_id / epoch mismatch against GroupContext
  let good_sd : @types.MlsSenderData = {
    leaf_index: 0U,
    generation: 0U,
    reuse_guard: b"\xAA\xBB\xCC\xDD",
  }
  let pm = @schedule.encrypt_private_message_with_keys(
    cs, sd_secret, good_sd, content_key, content_nonce, app_fc, app_auth, 0,
  )
  let _ = @schedule.decrypt_private_message_with_keys(
    cs, sig_pub, gc, good_sd, content_key, content_nonce, pm,
  )
  for bad_gc in [gc_wrong_gid, gc_wrong_epoch] {
    let mut e_priv_ctx = false
    try {
      let _ = @schedule.decrypt_private_message_with_keys(
        cs, sig_pub, bad_gc, good_sd, content_key, content_nonce, pm,
      )
    } catch {
      @schedule.ScheduleError::GroupContextMismatch => e_priv_ctx = true
      _ =>
        fail(
          "expected ScheduleError::GroupContextMismatch in decrypt_private_message_with_keys",
        )
    }
    assert_true(e_priv_ctx)
  }

  // 7c. unprotect_public_message rejects group_id / epoch mismatch against GroupContext
  let prop_fc : @types.FramedContent = {
    group_id: gc.group_id,
    epoch: gc.epoch,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(1U)),
  }
  let pub_msg = @schedule.protect_public_message(
    cs,
    sig_priv,
    Some(membership_key),
    prop_fc,
    Some(gc),
    None,
  )
  let _ = @schedule.unprotect_public_message(
    cs,
    sig_pub,
    Some(membership_key),
    pub_msg,
    Some(gc),
  )
  for bad_gc in [gc_wrong_gid, gc_wrong_epoch] {
    let mut e_pub_ctx = false
    try {
      let _ = @schedule.unprotect_public_message(
        cs,
        sig_pub,
        Some(membership_key),
        pub_msg,
        Some(bad_gc),
      )
    } catch {
      @schedule.ScheduleError::GroupContextMismatch => e_pub_ctx = true
      _ =>
        fail(
          "expected ScheduleError::GroupContextMismatch in unprotect_public_message",
        )
    }
    assert_true(e_pub_ctx)
  }
}
