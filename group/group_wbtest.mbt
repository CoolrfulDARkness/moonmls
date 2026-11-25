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
  // Snapshot Alice's epoch-1 secrets/context before Alice commits
  let old_gc = alice.group_context
  let old_sd_secret = alice.secrets.sender_data_secret
  let old_enc_secret = alice.secrets.encryption_secret
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
  let alice_pub = match alice.tree.get_leaf(0U) {
    Some(l) => l.signature_key
    None => fail("missing alice leaf")
  }
  let ac = @schedule.decrypt_private_message_with_keys(
    cs, alice_pub, old_gc, sd, key, nonce, c2.commit_msg,
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
    cs, old_sd_secret, sd, key, nonce, ac.content, bad_auth, 0,
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
  assert_eq(bob.process_message(c2.commit_msg), ProcessedMessage::Commit(0U, 2UL))
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
    secrets: [{ new_member: kp_ref, encrypted_group_secrets: { kem_output: kem_out, ciphertext: ct } }],
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
