///|
fn hex(s : String) -> Bytes raise {
  @tls.bytes_from_hex(s)
}

///|
fn flip_byte(data : Bytes, idx : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ 0x01).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn[T] assert_decryption_failed(
  f : () -> T raise @ciphersuite.CsError,
) -> Unit raise {
  try f() catch {
    @ciphersuite.DecryptionFailed => ()
    other => fail("expected DecryptionFailed, got \{other}")
  } noraise {
    _ => fail("expected DecryptionFailed, but succeeded")
  }
}

///|
test "CipherSuite metadata and from_id" {
  let cs1 = @ciphersuite.CipherSuite::from_id(1U)
  assert_eq(cs1, @ciphersuite.X25519Aes128GcmSha256Ed25519)
  assert_eq(cs1.id(), 1U)
  assert_eq(cs1.hash_len(), 32)
  assert_eq(cs1.aead_key_len(), 16)
  assert_eq(cs1.aead_nonce_len(), 12)
  assert_eq(cs1.aead_tag_len(), 16)
  assert_eq(cs1.secret_len(), 32)
  assert_eq(cs1.aead_id(), 1U)
  assert_eq(cs1.zero_secret(), Bytes::make(32, b'\x00'))

  let cs3 = @ciphersuite.CipherSuite::from_id(3U)
  assert_eq(cs3, @ciphersuite.X25519ChaCha20Poly1305Sha256Ed25519)
  assert_eq(cs3.id(), 3U)
  assert_eq(cs3.hash_len(), 32)
  assert_eq(cs3.aead_key_len(), 32)
  assert_eq(cs3.aead_nonce_len(), 12)
  assert_eq(cs3.aead_tag_len(), 16)
  assert_eq(cs3.secret_len(), 32)
  assert_eq(cs3.aead_id(), 3U)
  assert_eq(cs3.zero_secret(), Bytes::make(32, b'\x00'))

  try @ciphersuite.CipherSuite::from_id(2U) catch {
    @ciphersuite.UnsupportedCipherSuite(id) => assert_eq(id, 2U)
    other => fail("expected UnsupportedCipherSuite(2), got \{other}")
  } noraise {
    _ => fail("expected UnsupportedCipherSuite(2)")
  }
}

///|
test "RFC 9420 crypto-basics.json CS1 (0x0001) all 6 vectors" {
  let cs = @ciphersuite.CipherSuite::from_id(1U)

  // 1. ref_hash
  let rh_out = cs.ref_hash(
    "RefHash",
    hex("40312db83f651883c05ab26fa12c6af61930015c81947cfd0f129e6d99210bb2"),
  )
  assert_eq(
    @tls.bytes_to_hex(rh_out),
    "e8027fffc5f9bb469f29172538dc0f3a78f14f323495bbd2217eba7a77fb242a",
  )

  // 2. expand_with_label
  let ewl_out = cs.expand_with_label(
    hex("1499360a561335f4ef51d0a1b0d586900dc8007ae405b1ab79bf4207bb3d67e4"),
    "ExpandWithLabel",
    hex("2ff8c1f9d9c1248f82e372ddb5791c771695e01882abca6a64097bd2f04c971f"),
    16,
  )
  assert_eq(@tls.bytes_to_hex(ewl_out), "c1e8eb360391526c0c64039f13e0c5b1")

  // 3. derive_secret
  let ds_out = cs.derive_secret(
    hex("1a9ce178a53f8752d2513c27efe9c85133f6c0a97f7b35ac200695024a77228e"),
    "DeriveSecret",
  )
  assert_eq(
    @tls.bytes_to_hex(ds_out),
    "3b08c195a246c4ad469c1d11c10e62890d8fa6b684494ff925409efdb1ff0464",
  )

  // 4. derive_tree_secret
  let dts_out = cs.derive_tree_secret(
    hex("5133c6f8bad297f5d3beacdf477f0c45ec51b02de659d305220c5f9385c6eb43"),
    "DeriveTreeSecret",
    2694881440U,
    32,
  )
  assert_eq(
    @tls.bytes_to_hex(dts_out),
    "8461f3ccc603eae52149a23a4134d29c880a1ad1ba70441e5d586e3521ec7b25",
  )

  // 5. sign_with_label
  let sig_priv = hex(
    "a2f640dd5005fcad6adb8e9bd8b60d70946bb802e1e788307929fdac81e1ec74",
  )
  let sig_pub = hex(
    "85600e54e5c2919ccbd0742126e5d837cf7a2ba50d75a69b3f35dcfe4a50ffe2",
  )
  let sig_content = hex(
    "cd289cc7ba2869f64f3c32ffd133f500d17abace919a5ffe7faa974200d81932",
  )
  let sig_official = hex(
    "996bd223ddb4d55a2b57d85cb2944f21facc95696053ddf66d590060fdc719f4a26c6212ce605414e0d5e66a55921dd99d11122218c35bc23408b0076e8bc40b",
  )
  let (_, derived_pub) = cs.signature_keypair_from_seed(sig_priv)
  assert_eq(derived_pub, sig_pub)
  assert_true(
    cs.verify_with_label(sig_pub, "SignWithLabel", sig_content, sig_official),
  )
  let re_signed = cs.sign_with_label(sig_priv, "SignWithLabel", sig_content)
  assert_eq(re_signed, sig_official)
  assert_true(
    cs.verify_with_label(sig_pub, "SignWithLabel", sig_content, re_signed),
  )
  // Tampering content, label, or signature must fail verification
  assert_false(
    cs.verify_with_label(
      sig_pub,
      "SignWithLabel",
      flip_byte(sig_content, 0),
      sig_official,
    ),
  )
  assert_false(
    cs.verify_with_label(sig_pub, "WrongLabel", sig_content, sig_official),
  )
  assert_false(
    cs.verify_with_label(
      sig_pub,
      "SignWithLabel",
      sig_content,
      flip_byte(sig_official, 0),
    ),
  )

  // 6. encrypt_with_label
  let enc_priv = hex(
    "fb1ade7939987ff12a9d620772b1f9f7caeba26f8a3ecea9617d9402cd862444",
  )
  let enc_pub = hex(
    "ecea6564da58d6c6cff6c733bd4ae0815b1f60bb911b73e4ef1d06263ec4ce58",
  )
  let enc_context = hex(
    "26347dd7f218d1de8673d6a66646ce06ac5fd3aa8d5c33f65d86aeefdcf4a31e",
  )
  let enc_kem_output = hex(
    "0a144e8fbf2d6dcf6fe9d2e2b8aeca5461ff5b0ea9c0ede1040c3dc7ed1dfd1c",
  )
  let enc_ciphertext = hex(
    "15c80ea2bc37db221baa530ef5aea88650f0ce0f262803d6f78f3a1392f7ccd960eff94ca081ee54efa4c3acfa0eb591",
  )
  let enc_plaintext = hex(
    "8f55dd30f03d64335c22b53ea7670bb1becf49b04021f706368fe93eeb358f46",
  )
  assert_eq(@crypto.x25519_public_key(enc_priv), enc_pub)
  let decrypted = cs.decrypt_with_label(
    enc_priv, "EncryptWithLabel", enc_context, enc_kem_output, enc_ciphertext,
  )
  assert_eq(decrypted, enc_plaintext)

  // Re-encrypt and decrypt round-trip
  let rng = @crypto.DeterministicRng::from_seed(b"moonmls-cs1-test-seed")
  let (new_kem_out, new_ct) = cs.encrypt_with_label(
    enc_pub, "EncryptWithLabel", enc_context, enc_plaintext, rng,
  )
  let new_pt = cs.decrypt_with_label(
    enc_priv, "EncryptWithLabel", enc_context, new_kem_out, new_ct,
  )
  assert_eq(new_pt, enc_plaintext)

  // Tampering context, label, ciphertext, or kem_output must fail
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      flip_byte(enc_context, 0),
      enc_kem_output,
      enc_ciphertext,
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv, "WrongLabel", enc_context, enc_kem_output, enc_ciphertext,
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      enc_context,
      enc_kem_output,
      flip_byte(enc_ciphertext, 0),
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      enc_context,
      flip_byte(enc_kem_output, 0),
      enc_ciphertext,
    )
  })
}

///|
test "RFC 9420 crypto-basics.json CS3 (0x0003) all 6 vectors" {
  let cs = @ciphersuite.CipherSuite::from_id(3U)

  // 1. ref_hash
  let rh_out = cs.ref_hash(
    "RefHash",
    hex("4f0c86f9c82fba0a896bd7eecf79a29856e98a7e4f13b9f841ae285d70ed8b68"),
  )
  assert_eq(
    @tls.bytes_to_hex(rh_out),
    "f11019703c8b630060839b12a475fd39c6a30f8a866790ff46a35f9c65e1df3c",
  )

  // 2. expand_with_label
  let ewl_out = cs.expand_with_label(
    hex("55aa3ae5242564782567ce097beafe19510230660008b2cc064a78387fa16f36"),
    "ExpandWithLabel",
    hex("2e07148f4340c62a55e7608c20d73fddf1f3b8dafb2c7ef24eceb70e136c0d8c"),
    32,
  )
  assert_eq(
    @tls.bytes_to_hex(ewl_out),
    "1df5ba7996a34f75d717916a094a14083c03a75e80f0330a8095f5f11cfe1e1f",
  )

  // 3. derive_secret
  let ds_out = cs.derive_secret(
    hex("cae460c779ebaa3e81c061a371486dff1ed1ff273bea369cc0fc46550b83c407"),
    "DeriveSecret",
  )
  assert_eq(
    @tls.bytes_to_hex(ds_out),
    "aad859818ca5f2a9896d4d3ee2dccc0cefcd69b666bdb16b52f1de15fb1a5567",
  )

  // 4. derive_tree_secret
  let dts_out = cs.derive_tree_secret(
    hex("c994e257b53f726087ddd7121876f558f1fbd6f807e5ff010830d618d7bab6f2"),
    "DeriveTreeSecret",
    2694881440U,
    32,
  )
  assert_eq(
    @tls.bytes_to_hex(dts_out),
    "2095d6a81ab87095d1df26f6bdf012ec06f197e418381c1795a7b758603c936d",
  )

  // 5. sign_with_label
  let sig_priv = hex(
    "4e312160ee4981358db479aa877412847abc7f7054b5605511256c395404d054",
  )
  let sig_pub = hex(
    "18275f892ee0ca6f4687ff26c990776387502646ff658c3f572b324faecb05c5",
  )
  let sig_content = hex(
    "df308cf2dbf471edf2c29d30e3daf161b5b87d350ee3b2c715c298ec3d10d432",
  )
  let sig_official = hex(
    "4f56851c2c47f5115a61ff0ab6121b4a4732d4e94805fc7135a5132f87d5ca5f1dc7408816c1ea4f25887725cf5914b48c427a52cabcfeb746a2b8a12e821f08",
  )
  let (_, derived_pub) = cs.signature_keypair_from_seed(sig_priv)
  assert_eq(derived_pub, sig_pub)
  assert_true(
    cs.verify_with_label(sig_pub, "SignWithLabel", sig_content, sig_official),
  )
  let re_signed = cs.sign_with_label(sig_priv, "SignWithLabel", sig_content)
  assert_eq(re_signed, sig_official)
  assert_true(
    cs.verify_with_label(sig_pub, "SignWithLabel", sig_content, re_signed),
  )
  // Tampering content, label, or signature must fail verification
  assert_false(
    cs.verify_with_label(
      sig_pub,
      "SignWithLabel",
      flip_byte(sig_content, 5),
      sig_official,
    ),
  )
  assert_false(
    cs.verify_with_label(sig_pub, "WrongLabel", sig_content, sig_official),
  )
  assert_false(
    cs.verify_with_label(
      sig_pub,
      "SignWithLabel",
      sig_content,
      flip_byte(sig_official, 63),
    ),
  )

  // 6. encrypt_with_label
  let enc_priv = hex(
    "9d122ad4638fcb301b6eb5f4073414afb44bb34d37b4ddee9975b2941d700edb",
  )
  let enc_pub = hex(
    "7a5544b59f5940bf093c921469a00a170a7c92ba56c173d74db32713608d8a40",
  )
  let enc_context = hex(
    "0d6a5cf9ee88b1f8c79d8512477d9bfc5496c207c8173f8dcac0368b4dba7407",
  )
  let enc_kem_output = hex(
    "f26e9e5a94396a90f85a5f72eedf3dacfb1b7f4164e0573edeb9c6c912e1cb49",
  )
  let enc_ciphertext = hex(
    "40dd09ad4c5dc29d373f814bf054c9359cb75a468bc4d2c8bbcffb072a73105c4d9416ebd4fafeb62e59a9dea55da3cd",
  )
  let enc_plaintext = hex(
    "1dd4c1904996ce7d42cee7de68881459fa7a345da59a02040ade37103505baf6",
  )
  assert_eq(@crypto.x25519_public_key(enc_priv), enc_pub)
  let decrypted = cs.decrypt_with_label(
    enc_priv, "EncryptWithLabel", enc_context, enc_kem_output, enc_ciphertext,
  )
  assert_eq(decrypted, enc_plaintext)

  // Re-encrypt and decrypt round-trip
  let rng = @crypto.DeterministicRng::from_seed(b"moonmls-cs3-test-seed")
  let (new_kem_out, new_ct) = cs.encrypt_with_label(
    enc_pub, "EncryptWithLabel", enc_context, enc_plaintext, rng,
  )
  let new_pt = cs.decrypt_with_label(
    enc_priv, "EncryptWithLabel", enc_context, new_kem_out, new_ct,
  )
  assert_eq(new_pt, enc_plaintext)

  // Tampering context, label, ciphertext, or kem_output must fail
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      flip_byte(enc_context, 0),
      enc_kem_output,
      enc_ciphertext,
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv, "WrongLabel", enc_context, enc_kem_output, enc_ciphertext,
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      enc_context,
      enc_kem_output,
      flip_byte(enc_ciphertext, 0),
    )
  })
  assert_decryption_failed(() => {
    cs.decrypt_with_label(
      enc_priv,
      "EncryptWithLabel",
      enc_context,
      flip_byte(enc_kem_output, 0),
      enc_ciphertext,
    )
  })
}

///|
test "HPKE kem_derive_key_pair and Base mode round-trip for CS1 and CS3" {
  let ikm_r = hex(
    "b8302427646c449030250a4489056c243a77174c3c13d6c40147f5d24e8d29c0",
  )
  let ikm_e = hex(
    "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
  )
  let (sk_r, pk_r) = @ciphersuite.kem_derive_key_pair(ikm_r)
  let (sk_r2, pk_r2) = @ciphersuite.X25519Aes128GcmSha256Ed25519.kem_keypair_from_ikm(
    ikm_r,
  )
  assert_eq(sk_r, sk_r2)
  assert_eq(pk_r, pk_r2)
  assert_eq(sk_r.length(), 32)
  assert_eq(pk_r.length(), 32)
  assert_eq(@crypto.x25519_public_key(sk_r), pk_r)

  let (sk_e, pk_e) = @ciphersuite.kem_derive_key_pair(ikm_e)
  assert_true(sk_e != sk_r)
  assert_eq(@crypto.x25519_public_key(sk_e), pk_e)

  let info = b"Beauty is truth, truth beauty"
  let aad = b"Count-0"
  let pt = b"RFC 9180 HPKE Base mode test message for MoonMLS"

  let suites : Array[@ciphersuite.CipherSuite] = [
    @ciphersuite.X25519Aes128GcmSha256Ed25519,
    @ciphersuite.X25519ChaCha20Poly1305Sha256Ed25519,
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let cs = suites[i]
    // Deterministic ephemeral seal/open
    let (enc, ct) = @ciphersuite.hpke_seal_base_with_ephemeral(
      cs, pk_r, info, aad, pt, sk_e,
    )
    assert_eq(enc, pk_e)
    assert_eq(ct.length(), pt.length() + 16)
    let opened = @ciphersuite.hpke_open_base(cs, enc, sk_r, info, aad, ct)
    assert_eq(opened, pt)

    // Wrong AAD, wrong info, wrong ciphertext must fail
    assert_decryption_failed(() => {
      @ciphersuite.hpke_open_base(cs, enc, sk_r, info, b"Count-1", ct)
    })
    assert_decryption_failed(() => {
      @ciphersuite.hpke_open_base(cs, enc, sk_r, b"wrong info", aad, ct)
    })
    assert_decryption_failed(() => {
      @ciphersuite.hpke_open_base(
        cs,
        enc,
        sk_r,
        info,
        aad,
        flip_byte(ct, ct.length() - 1),
      )
    })

    // Deterministic encrypt_with_label_deterministic matches decryption
    let (enc2, ct2) = cs.encrypt_with_label_deterministic(
      pk_r, "TreeKEM", aad, pt, sk_e,
    )
    assert_eq(enc2, pk_e)
    assert_eq(cs.decrypt_with_label(sk_r, "TreeKEM", aad, enc2, ct2), pt)
  }
}

///|
test "MAC, RefHash helpers, and direct AEAD round-trip" {
  let suites : Array[@ciphersuite.CipherSuite] = [
    @ciphersuite.X25519Aes128GcmSha256Ed25519,
    @ciphersuite.X25519ChaCha20Poly1305Sha256Ed25519,
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let cs = suites[i]
    // MAC and verify_mac
    let mac_key = cs.extract(b"salt", b"ikm")
    let tag = cs.mac(mac_key, b"authenticated message")
    assert_eq(tag.length(), 32)
    assert_true(cs.verify_mac(mac_key, b"authenticated message", tag))
    assert_false(cs.verify_mac(mac_key, b"tampered message", tag))
    assert_false(
      cs.verify_mac(mac_key, b"authenticated message", flip_byte(tag, 0)),
    )

    // KeyPackageRef and ProposalRef match RefHash spec labels
    let payload = b"sample-mls-object"
    assert_eq(
      cs.make_key_package_ref(payload),
      cs.ref_hash("MLS 1.0 KeyPackage Reference", payload),
    )
    assert_eq(
      cs.make_proposal_ref(payload),
      cs.ref_hash("MLS 1.0 Proposal Reference", payload),
    )

    // Direct AEAD seal / open
    let key = Bytes::make(cs.aead_key_len(), b'\x42')
    let nonce = Bytes::make(cs.aead_nonce_len(), b'\x24')
    let aad = b"header"
    let pt = b"secret application payload"
    let ct = cs.aead_seal(key, nonce, aad, pt)
    assert_eq(ct.length(), pt.length() + cs.aead_tag_len())
    assert_eq(cs.aead_open(key, nonce, aad, ct), pt)
    assert_decryption_failed(() => cs.aead_open(key, nonce, b"wrong-header", ct))
    assert_decryption_failed(() => {
      cs.aead_open(key, nonce, aad, flip_byte(ct, 0))
    })
  }
}

///|
test "HPKE and CipherSuite error paths and empty payloads" {
  let cs1 = @ciphersuite.X25519Aes128GcmSha256Ed25519
  let cs3 = @ciphersuite.X25519ChaCha20Poly1305Sha256Ed25519
  let rng = @crypto.DeterministicRng::from_seed(b"hpke-edge-case-seed")

  // Empty plaintext, empty info, empty aad round-trip via hpke_seal_base (RNG)
  let (sk_r, pk_r) = @ciphersuite.kem_derive_key_pair(
    b"recipient-ikm-32-bytes-000000000",
  )
  let (enc1, ct1) = @ciphersuite.hpke_seal_base(cs1, pk_r, b"", b"", b"", rng)
  assert_eq(ct1.length(), 16)
  assert_eq(@ciphersuite.hpke_open_base(cs1, enc1, sk_r, b"", b"", ct1), b"")

  let (enc3, ct3) = @ciphersuite.hpke_seal_base(cs3, pk_r, b"", b"", b"", rng)
  assert_eq(ct3.length(), 16)
  assert_eq(@ciphersuite.hpke_open_base(cs3, enc3, sk_r, b"", b"", ct3), b"")

  // Invalid recipient key length
  try @ciphersuite.hpke_seal_base(cs1, b"short", b"", b"", b"hi", rng) catch {
    @ciphersuite.InvalidLength(_) => ()
    other => fail("expected InvalidLength, got \{other}")
  } noraise {
    _ => fail("expected InvalidLength")
  }

  // Invalid enc length on open
  try @ciphersuite.hpke_open_base(cs1, b"short", sk_r, b"", b"", ct1) catch {
    @ciphersuite.InvalidLength(_) => ()
    other => fail("expected InvalidLength, got \{other}")
  } noraise {
    _ => fail("expected InvalidLength")
  }

  // Low-order X25519 public key (all-zero) must be rejected with CryptoError(LowOrderPoint)
  let zero_pk = Bytes::make(32, b'\x00')
  try @ciphersuite.hpke_seal_base(cs1, zero_pk, b"", b"", b"hi", rng) catch {
    @ciphersuite.CryptoError(@crypto.LowOrderPoint) => ()
    other => fail("expected CryptoError(LowOrderPoint), got \{other}")
  } noraise {
    _ => fail("expected CryptoError(LowOrderPoint)")
  }

  // Invalid signature seed length
  try cs1.signature_keypair_from_seed(b"too-short") catch {
    @ciphersuite.InvalidLength(_) => ()
    other => fail("expected InvalidLength, got \{other}")
  } noraise {
    _ => fail("expected InvalidLength")
  }

  // Invalid expand_with_label length
  try cs1.expand_with_label(cs1.zero_secret(), "test", b"", -1) catch {
    @ciphersuite.InvalidLength(_) => ()
    other => fail("expected InvalidLength, got \{other}")
  } noraise {
    _ => fail("expected InvalidLength")
  }

  // Invalid AEAD key length for CS1 (needs 16, given 32) and CS3 (needs 32, given 16)
  try
    cs1.aead_seal(Bytes::make(32, b'\x01'), Bytes::make(12, b'\x00'), b"", b"a")
  catch {
    @ciphersuite.CryptoError(@crypto.InvalidKeyLength) => ()
    other => fail("expected CryptoError(InvalidKeyLength), got \{other}")
  } noraise {
    _ => fail("expected CryptoError(InvalidKeyLength)")
  }
  try
    cs3.aead_seal(Bytes::make(16, b'\x01'), Bytes::make(12, b'\x00'), b"", b"a")
  catch {
    @ciphersuite.CryptoError(@crypto.InvalidKeyLength) => ()
    other => fail("expected CryptoError(InvalidKeyLength), got \{other}")
  } noraise {
    _ => fail("expected CryptoError(InvalidKeyLength)")
  }
}
