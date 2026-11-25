///|
fn setup_5_member_group(
  cs : @cs.CipherSuite,
  seed : Bytes,
) -> (Array[@group.MlsGroup], @crypto.DeterministicRng) {
  let rng = @crypto.DeterministicRng::from_seed(seed)
  try {
    let alice = @group.MlsGroup::create(cs, b"bench-group-5", b"alice", rng)
    let bob_kp = @group.KeyPackageBundle::generate(cs, b"bob", rng)
    let charlie_kp = @group.KeyPackageBundle::generate(cs, b"charlie", rng)
    let dave_kp = @group.KeyPackageBundle::generate(cs, b"dave", rng)
    let eve_kp = @group.KeyPackageBundle::generate(cs, b"eve", rng)
    let c1 = alice.commit(
      [
        @types.Proposal::Add(bob_kp.key_package),
        @types.Proposal::Add(charlie_kp.key_package),
        @types.Proposal::Add(dave_kp.key_package),
        @types.Proposal::Add(eve_kp.key_package),
      ],
      rng,
    )
    let w1 = match c1.welcome {
      Some(w) => w
      None => abort("expected Welcome in bench setup")
    }
    let bob = @group.MlsGroup::from_welcome(cs, w1, bob_kp, None)
    let charlie = @group.MlsGroup::from_welcome(cs, w1, charlie_kp, None)
    let dave = @group.MlsGroup::from_welcome(cs, w1, dave_kp, None)
    let eve = @group.MlsGroup::from_welcome(cs, w1, eve_kp, None)
    ([alice, bob, charlie, dave, eve], rng)
  } catch {
    e => abort(Show::to_string(e))
  }
}

///|
test "group_5_members protect+unprotect (64B)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (members, rng) = setup_5_member_group(cs, b"bench-protect-unprotect-5")
  let alice = members[0]
  let bob = members[1]
  let payload = make_pattern_bytes(64, 51)
  let aad = b"bench-aad"
  b.bench(name="group_5_members protect+unprotect (64B)", fn() {
    let res = try {
      let msg = alice.protect_application(payload, aad, rng)
      bob.process_message(msg)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(res)
  })
}

///|
test "group_5_members update+commit+process" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let (members, rng) = setup_5_member_group(cs, b"bench-update-commit-5")
  let alice = members[0]
  let bob = members[1]
  let charlie = members[2]
  let dave = members[3]
  let eve = members[4]
  b.bench(name="group_5_members update+commit+process", fn() {
    let res = try {
      let upd = charlie.propose_update(rng)
      let _ = alice.process_message(upd)
      let _ = bob.process_message(upd)
      let _ = dave.process_message(upd)
      let _ = eve.process_message(upd)
      let out = alice.commit_pending(rng)
      let _ = bob.process_message(out.commit_msg)
      let _ = charlie.process_message(out.commit_msg)
      let _ = dave.process_message(out.commit_msg)
      eve.process_message(out.commit_msg)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(res)
  })
}

///|
test "key_package generate+verify" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"bench-kp-gen-verify")
  b.bench(name="key_package generate+verify", fn() {
    let bundle = try {
      let kp_bundle = @group.KeyPackageBundle::generate(cs, b"bench-user", rng)
      @group.verify_key_package(cs, kp_bundle.key_package)
      kp_bundle
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(bundle)
  })
}
