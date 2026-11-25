///|
/// Whitebox test verifying that a Commit with a tampered `confirmation_tag`
/// (even when AEAD-encrypted and validly signed under the current epoch!) is
/// rejected with `ConfirmationTagMismatch` and leaves the receiver's group
/// state 100% unpolluted so a legitimate Commit can immediately succeed.
test "tampered Commit confirmation_tag fails atomically without polluting state" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-conf-tag-tamper")
  let alice = MlsGroup::create(cs, b"tamper-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = MlsGroup::from_welcome(cs, w1, bob_kp, None)
  let bob_auth_before = bob.epoch_authenticator()
  let bob_th_before = bob.tree_hash()
  let alice_pub = match alice.tree.get_leaf(0U) {
    Some(l) => l.signature_key
    None => fail("missing alice leaf")
  }
  let verified_w1 = verify_and_decrypt_welcome(
    cs,
    w1,
    bob_kp.init_priv,
    bob_kp.key_package,
    alice_pub,
  )
  // Snapshot Alice's epoch-1 secrets/context before Alice commits
  let old_gc = alice.group_context
  let old_sd_secret = alice.secrets.sender_data_secret
  let old_enc_secret = verified_w1.secrets.encryption_secret
  let old_n_leaves = alice.tree.n_leaves()
  // Alice creates a valid Commit for epoch 1 -> 2
  let c2 = alice.commit([], rng)
  // Decrypt c2.commit_msg to flip a bit in confirmation_tag and re-encrypt validly
  let sd = @schedule.decrypt_sender_data(cs, old_sd_secret, c2.commit_msg)
  let tmp_st = @tree.SecretTree::new(cs, old_enc_secret, old_n_leaves)
  let (key, nonce) = tmp_st.handshake_key_nonce_for_generation(
    sd.leaf_index,
    sd.generation,
  )
  let ac = @schedule.decrypt_private_message_with_keys(
    cs,
    alice_pub,
    old_gc,
    sd,
    key,
    nonce,
    c2.commit_msg,
  )
  let orig_tag = match ac.auth.confirmation_tag {
    Some(t) => t
    None => fail("missing confirmation_tag")
  }
  let bad_tag = Bytes::makei(orig_tag.length(), fn(i) {
    if i == 0 {
      (orig_tag[i].to_int() ^ 0xFF).to_byte()
    } else {
      orig_tag[i]
    }
  })
  let bad_auth : @types.FramedContentAuthData = {
    signature: ac.auth.signature,
    confirmation_tag: Some(bad_tag),
  }
  let tampered_commit_msg = @schedule.encrypt_private_message_with_keys(
    cs,
    old_sd_secret,
    sd,
    key,
    nonce,
    ac.content,
    bad_auth,
    0,
  )
  // Bob rejects tampered Commit with ConfirmationTagMismatch
  let mut got_tag_mismatch = false
  try {
    let _ = bob.process_message(tampered_commit_msg)
  } catch {
    GroupError::ConfirmationTagMismatch => got_tag_mismatch = true
    _ => fail("expected ConfirmationTagMismatch")
  }
  assert_true(got_tag_mismatch)
  // Verify Bob's state is completely untouched
  assert_eq(bob.epoch(), 1UL)
  assert_eq(bob.epoch_authenticator(), bob_auth_before)
  assert_eq(bob.tree_hash(), bob_th_before)
  // Now deliver the legitimate Commit at the EXACT same generation -> must succeed!
  assert_eq(
    bob.process_message(c2.commit_msg),
    ProcessedMessage::Commit(0U, 2UL),
  )
  assert_eq(bob.epoch(), 2UL)
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
  assert_eq(bob.tree_hash(), alice.tree_hash())
}

///|
/// Whitebox test verifying MissingRatchetTree when GroupInfo omits EXT_RATCHET_TREE
/// and external_tree is None, and success when external_tree is provided.
test "from_welcome MissingRatchetTree and external_tree fallback" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-missing-rt")
  let alice = MlsGroup::create(cs, b"rt-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  // Decrypt GroupInfo, strip EXT_RATCHET_TREE, re-sign and re-encrypt Welcome
  let (gs, gi, psk_secret) = decrypt_welcome_payload(
    cs,
    w1,
    bob_kp.init_priv,
    bob_kp.key_package,
  )
  let stripped_unsigned : @types.GroupInfo = {
    group_context: gi.group_context,
    extensions: [],
    confirmation_tag: gi.confirmation_tag,
    signer: gi.signer,
    signature: b"",
  }
  let sig = cs.sign_with_label(
    alice.signature_priv,
    "GroupInfoTBS",
    stripped_unsigned.encode_tbs(),
  )
  let stripped_gi : @types.GroupInfo = {
    group_context: stripped_unsigned.group_context,
    extensions: stripped_unsigned.extensions,
    confirmation_tag: stripped_unsigned.confirmation_tag,
    signer: stripped_unsigned.signer,
    signature: sig,
  }
  let ws = @schedule.derive_welcome_secret(cs, gs.joiner_secret, psk_secret)
  let (wk, wn) = @schedule.derive_welcome_key_nonce(cs, ws)
  let enc_gi = cs.aead_seal(wk, wn, b"", stripped_gi.to_bytes())
  let kp_ref = cs.make_key_package_ref(bob_kp.key_package.to_bytes())
  let (kem_out, ct) = cs.encrypt_with_label(
    bob_kp.key_package.init_key,
    "Welcome",
    enc_gi,
    gs.to_bytes(),
    rng,
  )
  let stripped_welcome : @types.Welcome = {
    cipher_suite: cs.id(),
    secrets: [
      {
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output: kem_out, ciphertext: ct, },
      },
    ],
    encrypted_group_info: enc_gi,
  }
  // Without external_tree -> MissingRatchetTree
  let mut got_missing = false
  try {
    let _ = MlsGroup::from_welcome(cs, stripped_welcome, bob_kp, None)
  } catch {
    GroupError::MissingRatchetTree => got_missing = true
    _ => fail("expected MissingRatchetTree")
  }
  assert_true(got_missing)
  // With external_tree -> succeeds and matches Alice
  let bob = MlsGroup::from_welcome(
    cs,
    stripped_welcome,
    bob_kp,
    Some(alice.ratchet_tree_nodes()),
  )
  assert_eq(bob.epoch(), alice.epoch())
  assert_eq(bob.epoch_authenticator(), alice.epoch_authenticator())
  assert_eq(bob.tree_hash(), alice.tree_hash())
}

///|
test "C-3 self_removed Commit without UpdatePath or with corrupted UpdatePath must NOT deactivate member" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-c3-self-removed")
  let alice = MlsGroup::create(cs, b"c3-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = MlsGroup::from_welcome(cs, w1, bob_kp, None)
  // Alice crafts an illegal Commit removing Bob (leaf 1) with path = None
  let bad_commit_no_path : @types.Commit = {
    proposals: [@types.ProposalOrRef::Proposal(@types.Proposal::Remove(1U))],
    path: None,
  }
  let fc1 : @types.FramedContent = {
    group_id: alice.group_context.group_id,
    epoch: alice.group_context.epoch,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit(bad_commit_no_path),
  }
  let sig1 = @schedule.sign_framed_content(
    cs,
    alice.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc1,
    Some(alice.group_context),
  )
  let (g1, k1, n1) = alice.secret_tree.next_handshake_key_nonce(0U)
  let msg_no_path = @schedule.encrypt_private_message_with_keys(
    cs,
    alice.secrets.sender_data_secret,
    { leaf_index: 0U, generation: g1, reuse_guard: rng.next_bytes(4), },
    k1,
    n1,
    fc1,
    { signature: sig1, confirmation_tag: Some(Bytes::make(32, b'\x11')), },
    0,
  )
  let mut rejected_no_path = false
  try {
    let _ = bob.process_message(msg_no_path)
  } catch {
    GroupError::InvalidCommit(_) => rejected_no_path = true
    _ => fail("expected InvalidCommit when self-removing Commit omits path")
  }
  assert_true(rejected_no_path)
  assert_true(bob.is_active())
  assert_eq(bob.epoch(), 1UL)
  // Case 2: Self-removing Commit with corrupted UpdatePath (bad parent_hash)
  let alice_leaf0 = match alice.tree.get_leaf(0U) {
    Some(l) => l
    None => fail("missing leaf 0")
  }
  let bad_up : @types.UpdatePath = {
    leaf_node: {
      encryption_key: Bytes::make(32, b'\x77'),
      signature_key: alice_leaf0.signature_key,
      credential: alice_leaf0.credential,
      capabilities: alice_leaf0.capabilities,
      leaf_node_source: @types.LeafNodeSource::Commit,
      lifetime: None,
      parent_hash: Some(Bytes::make(32, b'\xFF')),
      extensions: [],
      signature: Bytes::make(64, b'\x00'),
    },
    nodes: [],
  }
  let bad_commit_corrupt_up : @types.Commit = {
    proposals: [@types.ProposalOrRef::Proposal(@types.Proposal::Remove(1U))],
    path: Some(bad_up),
  }
  let fc2 : @types.FramedContent = {
    group_id: alice.group_context.group_id,
    epoch: alice.group_context.epoch,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit(bad_commit_corrupt_up),
  }
  let sig2 = @schedule.sign_framed_content(
    cs,
    alice.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc2,
    Some(alice.group_context),
  )
  let (g2, k2, n2) = alice.secret_tree.next_handshake_key_nonce(0U)
  let msg_bad_up = @schedule.encrypt_private_message_with_keys(
    cs,
    alice.secrets.sender_data_secret,
    { leaf_index: 0U, generation: g2, reuse_guard: rng.next_bytes(4), },
    k2,
    n2,
    fc2,
    { signature: sig2, confirmation_tag: Some(Bytes::make(32, b'\x22')), },
    0,
  )
  let mut rejected_bad_up = false
  try {
    let _ = bob.process_message(msg_bad_up)
  } catch {
    GroupError::TreeError(_) => rejected_bad_up = true
    _ =>
      fail("expected TreeError on corrupted UpdatePath in self-removing Commit")
  }
  assert_true(rejected_bad_up)
  assert_true(bob.is_active())
  assert_eq(bob.epoch(), 1UL)
  // Honest application message still works for Bob
  let ok_app = alice.protect_application(b"still-in-group", b"", rng)
  assert_eq(
    bob.process_message(ok_app),
    ProcessedMessage::Application(0U, b"still-in-group", b""),
  )
}

///|
test "H-1 concurrent duplicate Removes, conflicting Update+Remove, and duplicate Adds are filtered cleanly in commit" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-h1-conflict-filter")
  let alice = MlsGroup::create(cs, b"h1-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let charlie_kp = KeyPackageBundle::generate(cs, b"charlie", rng)
  let dave_kp = KeyPackageBundle::generate(cs, b"dave", rng)
  let c1 = alice.commit(
    [
      @types.Proposal::Add(bob_kp.key_package),
      @types.Proposal::Add(charlie_kp.key_package),
    ],
    rng,
  )
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = MlsGroup::from_welcome(cs, w1, bob_kp, None)
  let charlie = MlsGroup::from_welcome(cs, w1, charlie_kp, None)
  // Concurrent proposals in epoch 1:
  // 1. Charlie proposes Update (will conflict with Remove(2))
  let p_charlie_upd = charlie.propose_update(rng)
  // 2. Alice AND Bob both propose Remove(2) (Charlie)
  let p_alice_rm_c = alice.propose_remove(2U, rng)
  let p_bob_rm_c = bob.propose_remove(2U, rng)
  // 3. Bob also proposes Remove(0) (removing Alice, the committer!)
  let p_bob_rm_a = bob.propose_remove(0U, rng)
  // 4. Both Alice and Bob propose Add(dave) (duplicate init_key/enc_key/sig_key)
  let p_alice_add_d = alice.propose_add(dave_kp.key_package, rng)
  let p_bob_add_d = bob.propose_add(dave_kp.key_package, rng)
  // 5. Bob proposes two consecutive Updates
  let p_bob_upd1 = bob.propose_update(rng)
  let p_bob_upd2 = bob.propose_update(rng)
  // Deliver all proposals to Alice and Bob
  let _ = alice.process_message(p_charlie_upd)
  let _ = alice.process_message(p_bob_rm_c)
  let _ = alice.process_message(p_bob_rm_a)
  let _ = alice.process_message(p_bob_add_d)
  let _ = alice.process_message(p_bob_upd1)
  let _ = alice.process_message(p_bob_upd2)
  let _ = bob.process_message(p_charlie_upd)
  let _ = bob.process_message(p_alice_rm_c)
  let _ = bob.process_message(p_alice_add_d)
  // Alice commits pending -> MUST filter all conflicts cleanly and advance to epoch 2!
  let c2 = alice.commit_pending(rng)
  assert_eq(c2.new_epoch, 2UL)
  assert_eq(
    bob.process_message(c2.commit_msg),
    ProcessedMessage::Commit(0U, 2UL),
  )
  let w2 = match c2.welcome {
    Some(w) => w
    None => fail("expected Welcome for Dave")
  }
  let dave = MlsGroup::from_welcome(cs, w2, dave_kp, None)
  assert_eq(alice.epoch(), 2UL)
  assert_eq(bob.epoch(), 2UL)
  assert_eq(dave.epoch(), 2UL)
  assert_eq(alice.epoch_authenticator(), bob.epoch_authenticator())
  assert_eq(alice.epoch_authenticator(), dave.epoch_authenticator())
  assert_eq(alice.members().length(), 3)
}

///|
test "H-3 KeyPackage capability/X25519/extension checks and Welcome trailing None / duplicate extensions / unmerged_leaves" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-h3-kp-welcome")
  let b1 = KeyPackageBundle::generate(cs, b"u1", rng)
  let kp = b1.key_package
  // 1. Low-order init_key in KeyPackage -> InvalidKeyPackage
  let low_init_kp : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: Bytes::make(32, b'\x00'),
    leaf_node: kp.leaf_node,
    extensions: kp.extensions,
    signature: kp.signature,
  }
  let mut err_low_init = false
  verify_key_package(cs, low_init_kp) catch {
    GroupError::InvalidKeyPackage(_) => err_low_init = true
    _ => fail("expected InvalidKeyPackage for low-order init_key")
  }
  assert_true(err_low_init)
  // 2. Capabilities missing cipher suite -> InvalidKeyPackage
  let bad_caps_leaf : @types.LeafNode = {
    encryption_key: kp.leaf_node.encryption_key,
    signature_key: kp.leaf_node.signature_key,
    credential: kp.leaf_node.credential,
    capabilities: {
      versions: [@types.PROTOCOL_VERSION_MLS10],
      cipher_suites: [
        @types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
      ],
      extensions: [],
      proposals: [],
      credentials: [@types.CREDENTIAL_TYPE_BASIC],
    },
    leaf_node_source: kp.leaf_node.leaf_node_source,
    lifetime: kp.leaf_node.lifetime,
    parent_hash: kp.leaf_node.parent_hash,
    extensions: [],
    signature: kp.leaf_node.signature,
  }
  let bad_caps_kp : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: bad_caps_leaf,
    extensions: [],
    signature: kp.signature,
  }
  let mut err_caps = false
  verify_key_package(cs, bad_caps_kp) catch {
    GroupError::InvalidKeyPackage(_) => err_caps = true
    _ =>
      fail(
        "expected InvalidKeyPackage for missing cipher suite in capabilities",
      )
  }
  assert_true(err_caps)
  // 3. Duplicate extension_type in KeyPackage -> InvalidKeyPackage
  let dup_ext_kp : @types.KeyPackage = {
    version: kp.version,
    cipher_suite: kp.cipher_suite,
    init_key: kp.init_key,
    leaf_node: kp.leaf_node,
    extensions: [
      { extension_type: 1U, extension_data: b"x", },
      { extension_type: 1U, extension_data: b"y", },
    ],
    signature: kp.signature,
  }
  let mut err_dup_ext = false
  verify_key_package(cs, dup_ext_kp) catch {
    GroupError::InvalidKeyPackage(_) => err_dup_ext = true
    _ => fail("expected InvalidKeyPackage for duplicate KeyPackage extension")
  }
  assert_true(err_dup_ext)
  // 4. Welcome with trailing None in external_tree -> InvalidCommit
  let alice = MlsGroup::create(cs, b"h3-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let (gs, gi, psk_secret) = decrypt_welcome_payload(
    cs,
    w1,
    bob_kp.init_priv,
    bob_kp.key_package,
  )
  // Rebuild Welcome with stripped ratchet_tree so external_tree is used, and test trailing None
  let stripped_unsigned : @types.GroupInfo = {
    group_context: gi.group_context,
    extensions: [],
    confirmation_tag: gi.confirmation_tag,
    signer: gi.signer,
    signature: b"",
  }
  let s_sig = cs.sign_with_label(
    alice.signature_priv,
    "GroupInfoTBS",
    stripped_unsigned.encode_tbs(),
  )
  let stripped_gi : @types.GroupInfo = {
    group_context: stripped_unsigned.group_context,
    extensions: [],
    confirmation_tag: stripped_unsigned.confirmation_tag,
    signer: stripped_unsigned.signer,
    signature: s_sig,
  }
  let ws = @schedule.derive_welcome_secret(cs, gs.joiner_secret, psk_secret)
  let (wk, wn) = @schedule.derive_welcome_key_nonce(cs, ws)
  let enc_gi = cs.aead_seal(wk, wn, b"", stripped_gi.to_bytes())
  let kp_ref = cs.make_key_package_ref(bob_kp.key_package.to_bytes())
  let (kem_out, ct) = cs.encrypt_with_label(
    bob_kp.key_package.init_key,
    "Welcome",
    enc_gi,
    gs.to_bytes(),
    rng,
  )
  let stripped_w : @types.Welcome = {
    cipher_suite: cs.id(),
    secrets: [
      {
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output: kem_out, ciphertext: ct, },
      },
    ],
    encrypted_group_info: enc_gi,
  }
  let trailing_none_rt = alice.ratchet_tree_nodes()
  trailing_none_rt.push(None)
  let mut err_trailing = false
  try {
    let _ = MlsGroup::from_welcome(
      cs,
      stripped_w,
      bob_kp,
      Some(trailing_none_rt),
    )
  } catch {
    GroupError::InvalidCommit(_) => err_trailing = true
    _ => fail("expected InvalidCommit for trailing None in ratchet_tree")
  }
  assert_true(err_trailing)
  // 5. Welcome with path_secret == None when my_leaf is NOT in ancestor's unmerged_leaves -> InvalidUnmergedLeaf
  let gs_no_ps : @types.GroupSecrets = {
    joiner_secret: gs.joiner_secret,
    path_secret: None,
    psks: [],
  }
  let (kem_out2, ct2) = cs.encrypt_with_label(
    bob_kp.key_package.init_key,
    "Welcome",
    enc_gi,
    gs_no_ps.to_bytes(),
    rng,
  )
  let no_ps_w : @types.Welcome = {
    cipher_suite: cs.id(),
    secrets: [
      {
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output: kem_out2, ciphertext: ct2, },
      },
    ],
    encrypted_group_info: enc_gi,
  }
  let mut err_no_ps_ul = false
  try {
    let _ = MlsGroup::from_welcome(
      cs,
      no_ps_w,
      bob_kp,
      Some(alice.ratchet_tree_nodes()),
    )
  } catch {
    GroupError::TreeError(@tree.TreeError::InvalidUnmergedLeaf) =>
      err_no_ps_ul = true
    _ =>
      fail(
        "expected InvalidUnmergedLeaf when path_secret is None and my_leaf not in unmerged_leaves",
      )
  }
  assert_true(err_no_ps_ul)
}

///|
test "M-1 epoch overflow protection in commit, process_message, and from_welcome" {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"wb-m1-epoch-overflow")
  let alice = MlsGroup::create(cs, b"m1-gid", b"alice", rng)
  let bob_kp = KeyPackageBundle::generate(cs, b"bob", rng)
  let c1 = alice.commit([@types.Proposal::Add(bob_kp.key_package)], rng)
  let w1 = match c1.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = MlsGroup::from_welcome(cs, w1, bob_kp, None)
  // Force both Alice and Bob to MAX_EPOCH (0xFFFFFFFFFFFFFFFFUL)
  let max_gc : @types.GroupContext = {
    version: alice.group_context.version,
    cipher_suite: alice.group_context.cipher_suite,
    group_id: alice.group_context.group_id,
    epoch: MAX_EPOCH,
    tree_hash: alice.group_context.tree_hash,
    confirmed_transcript_hash: alice.group_context.confirmed_transcript_hash,
    extensions: alice.group_context.extensions,
  }
  alice.group_context = max_gc
  bob.group_context = max_gc
  // 1. commit() at MAX_EPOCH must reject with InvalidCommit (never wrap to 0UL)
  let mut err_commit_ovf = false
  try {
    let _ = alice.commit([], rng)
  } catch {
    GroupError::InvalidCommit(_) => err_commit_ovf = true
    _ => fail("expected InvalidCommit on epoch overflow in commit()")
  }
  assert_true(err_commit_ovf)
  assert_eq(alice.epoch(), MAX_EPOCH)
  // 2. process_message() receiving a Commit at MAX_EPOCH must reject with InvalidCommit
  let dummy_commit : @types.Commit = { proposals: [], path: None, }
  let fc : @types.FramedContent = {
    group_id: max_gc.group_id,
    epoch: MAX_EPOCH,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit(dummy_commit),
  }
  let sig = @schedule.sign_framed_content(
    cs,
    alice.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    fc,
    Some(max_gc),
  )
  let (g, k, n) = alice.secret_tree.next_handshake_key_nonce(0U)
  let commit_at_max = @schedule.encrypt_private_message_with_keys(
    cs,
    alice.secrets.sender_data_secret,
    { leaf_index: 0U, generation: g, reuse_guard: rng.next_bytes(4), },
    k,
    n,
    fc,
    { signature: sig, confirmation_tag: Some(Bytes::make(32, b'\x00')), },
    0,
  )
  let mut err_proc_ovf = false
  try {
    let _ = bob.process_message(commit_at_max)
  } catch {
    GroupError::InvalidCommit(_) => err_proc_ovf = true
    _ => fail("expected InvalidCommit on epoch overflow in process_message()")
  }
  assert_true(err_proc_ovf)
  assert_eq(bob.epoch(), MAX_EPOCH)
  // 3. from_welcome() at MAX_EPOCH must reject with InvalidCommit
  let (gs, gi, psk_secret) = decrypt_welcome_payload(
    cs,
    w1,
    bob_kp.init_priv,
    bob_kp.key_package,
  )
  let max_gi : @types.GroupInfo = {
    group_context: {
      version: gi.group_context.version,
      cipher_suite: gi.group_context.cipher_suite,
      group_id: gi.group_context.group_id,
      epoch: MAX_EPOCH,
      tree_hash: gi.group_context.tree_hash,
      confirmed_transcript_hash: gi.group_context.confirmed_transcript_hash,
      extensions: gi.group_context.extensions,
    },
    extensions: gi.extensions,
    confirmation_tag: gi.confirmation_tag,
    signer: gi.signer,
    signature: gi.signature,
  }
  let ws = @schedule.derive_welcome_secret(cs, gs.joiner_secret, psk_secret)
  let (wk, wn) = @schedule.derive_welcome_key_nonce(cs, ws)
  let enc_gi = cs.aead_seal(wk, wn, b"", max_gi.to_bytes())
  let kp_ref = cs.make_key_package_ref(bob_kp.key_package.to_bytes())
  let (kem_out, ct) = cs.encrypt_with_label(
    bob_kp.key_package.init_key,
    "Welcome",
    enc_gi,
    gs.to_bytes(),
    rng,
  )
  let max_welcome : @types.Welcome = {
    cipher_suite: cs.id(),
    secrets: [
      {
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output: kem_out, ciphertext: ct, },
      },
    ],
    encrypted_group_info: enc_gi,
  }
  let mut err_welcome_ovf = false
  try {
    let _ = MlsGroup::from_welcome(cs, max_welcome, bob_kp, None)
  } catch {
    GroupError::InvalidCommit(_) => err_welcome_ovf = true
    _ => fail("expected InvalidCommit on epoch overflow in from_welcome()")
  }
  assert_true(err_welcome_ovf)
}
