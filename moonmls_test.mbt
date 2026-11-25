///|
test "top-level moonmls facade smoke test" {
  let cs = @moonmls.cs_x25519_aes128gcm()
  let rng = @moonmls.rng_from_seed(b"moonmls-facade-smoke")
  let alice = @moonmls.create_group(cs, b"facade-group", b"alice", rng)
  let bob_kp = @moonmls.generate_key_package(cs, b"bob", rng)
  @moonmls.verify_key_package(cs, bob_kp.key_package)
  let prop = alice.propose_add(bob_kp.key_package, rng)
  ignore(prop)
  let out = alice.commit_pending(rng)
  let welcome = match out.welcome {
    Some(w) => w
    None => fail("expected Welcome")
  }
  let bob = @moonmls.join_group_from_welcome(cs, welcome, bob_kp, None)
  assert_eq(alice.epoch(), 1UL)
  assert_eq(bob.epoch(), 1UL)
  assert_eq(alice.epoch_authenticator(), bob.epoch_authenticator())
  assert_eq(
    alice.export_secret("demo", b"ctx", 32),
    bob.export_secret("demo", b"ctx", 32),
  )
  let msg = alice.protect_application(b"hello moonmls", b"aad", rng)
  let res = bob.process_message(msg)
  assert_true(
    res is Application(0U, b"hello moonmls", b"aad"),
  )
}
