///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    abort("invalid hex char")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { out[i] })
}

///|
fn flip_bit(data : Bytes, byte_idx : Int32, bit_mask : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == byte_idx {
      (data[i].to_int() ^ bit_mask).to_byte()
    } else {
      data[i]
    }
  })
}

///|
test "ct_equal and xor_bytes" {
  assert_true(@crypto.ct_equal(b"", b""))
  assert_true(@crypto.ct_equal(b"hello", b"hello"))
  assert_false(@crypto.ct_equal(b"hello", b"hellp"))
  assert_false(@crypto.ct_equal(b"hello", b"hell"))
  let x = @crypto.xor_bytes(from_hex("0f1e2d3c"), from_hex("f0e1d2c3"))
  assert_eq(x, from_hex("ffffffff"))
  let err : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.xor_bytes(b"abc", b"ab"),
  ) catch {
    e => Err(e)
  }
  assert_true(err is Err(@crypto.InvalidInputLength))
}

///|
test "sha256 NIST vectors" {
  // Empty string
  assert_eq(
    @crypto.sha256(b""),
    from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  )
  // "abc"
  assert_eq(
    @crypto.sha256(b"abc"),
    from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
  )
  // Two-block message (56 bytes)
  assert_eq(
    @crypto.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
  )
}

///|
test "sha512 NIST vectors" {
  // Empty string
  assert_eq(
    @crypto.sha512(b""),
    from_hex(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
  )
  // "abc"
  assert_eq(
    @crypto.sha512(b"abc"),
    from_hex(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
  )
}

///|
test "hmac_sha256 RFC 4231 vectors" {
  // Test Case 1
  let key1 = Bytes::make(20, b'\x0b')
  let data1 = b"Hi There"
  assert_eq(
    @crypto.hmac_sha256(key1, data1),
    from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
  )
  // Test Case 2
  let key2 = b"Jefe"
  let data2 = b"what do ya want for nothing?"
  assert_eq(
    @crypto.hmac_sha256(key2, data2),
    from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
  )
  // Test Case 6 (key > 64 bytes)
  let key6 = Bytes::make(131, b'\xaa')
  let data6 = b"Test Using Larger Than Block-Size Key - Hash Key First"
  assert_eq(
    @crypto.hmac_sha256(key6, data6),
    from_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
  )
}

///|
test "hkdf_sha256 RFC 5869 vectors" {
  // Test Case 1
  let ikm1 = Bytes::make(22, b'\x0b')
  let salt1 = from_hex("000102030405060708090a0b0c")
  let info1 = from_hex("f0f1f2f3f4f5f6f7f8f9")
  let prk1 = @crypto.hkdf_extract(salt1, ikm1)
  assert_eq(
    prk1,
    from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
  )
  let okm1 = @crypto.hkdf_expand(prk1, info1, 42)
  assert_eq(
    okm1,
    from_hex(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ),
  )
  // Test Case 3 (empty salt & info)
  let ikm3 = Bytes::make(22, b'\x0b')
  let prk3 = @crypto.hkdf_extract(b"", ikm3)
  assert_eq(
    prk3,
    from_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
  )
  let okm3 = @crypto.hkdf_expand(prk3, b"", 42)
  assert_eq(
    okm3,
    from_hex(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ),
  )
  // OutputTooLong
  let too_long : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.hkdf_expand(prk1, b"", 255 * 32 + 1),
  ) catch {
    e => Err(e)
  }
  assert_true(too_long is Err(@crypto.OutputTooLong))
}

///|
test "aes128_gcm NIST SP 800-38D Test Cases 1-4 and tamper detection" {
  // Test Case 1: empty PT, empty AAD
  let k0 = Bytes::make(16, b'\x00')
  let iv0 = Bytes::make(12, b'\x00')
  let ct1 = @crypto.aes128_gcm_seal(k0, iv0, b"", b"")
  assert_eq(ct1, from_hex("58e2fccefa7e3061367f1d57a4e7455a"))
  assert_eq(@crypto.aes128_gcm_open(k0, iv0, b"", ct1), b"")
  // Test Case 2: 16B zero PT, empty AAD
  let pt2 = Bytes::make(16, b'\x00')
  let ct2 = @crypto.aes128_gcm_seal(k0, iv0, b"", pt2)
  assert_eq(
    ct2,
    from_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
  )
  assert_eq(@crypto.aes128_gcm_open(k0, iv0, b"", ct2), pt2)
  // Test Case 3: 64B PT, empty AAD
  let k3 = from_hex("feffe9928665731c6d6a8f9467308308")
  let iv3 = from_hex("cafebabefacedbaddecaf888")
  let pt3 = from_hex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  )
  let expected3 = from_hex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4",
  )
  let ct3 = @crypto.aes128_gcm_seal(k3, iv3, b"", pt3)
  assert_eq(ct3, expected3)
  assert_eq(@crypto.aes128_gcm_open(k3, iv3, b"", ct3), pt3)
  // Test Case 4: 60B PT, 20B AAD
  let pt4 = from_hex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  )
  let aad4 = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let expected4 = from_hex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47",
  )
  let ct4 = @crypto.aes128_gcm_seal(k3, iv3, aad4, pt4)
  assert_eq(ct4, expected4)
  assert_eq(@crypto.aes128_gcm_open(k3, iv3, aad4, ct4), pt4)
  // Tamper 1 bit in ciphertext -> AuthFailed
  let bad_ct : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes128_gcm_open(k3, iv3, aad4, flip_bit(ct4, 0, 1)),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_ct is Err(@crypto.AuthFailed))
  // Tamper 1 bit in AAD -> AuthFailed
  let bad_aad : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes128_gcm_open(k3, iv3, flip_bit(aad4, 5, 0x80), ct4),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_aad is Err(@crypto.AuthFailed))
  // Tamper 1 bit in tag -> AuthFailed
  let bad_tag : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes128_gcm_open(k3, iv3, aad4, flip_bit(ct4, ct4.length() - 1, 1)),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_tag is Err(@crypto.AuthFailed))
  // Invalid key/nonce lengths
  let bad_key : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes128_gcm_seal(b"short", iv3, b"", b""),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_key is Err(@crypto.InvalidKeyLength))
  let bad_nonce : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.aes128_gcm_seal(k3, b"short", b"", b""),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_nonce is Err(@crypto.InvalidNonceLength))
}

///|
test "chacha20_poly1305 RFC 8439 section 2.8.2 and tamper detection" {
  let key = from_hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = from_hex("070000004041424344454647")
  let aad = from_hex("50515253c0c1c2c3c4c5c6c7")
  let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  let expected = from_hex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
  )
  let ct_tag = @crypto.chacha20_poly1305_seal(key, nonce, aad, pt)
  assert_eq(ct_tag, expected)
  let opened = @crypto.chacha20_poly1305_open(key, nonce, aad, ct_tag)
  assert_eq(opened, pt)
  // Tamper 1 bit in CT, AAD, tag
  let bad_ct : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.chacha20_poly1305_open(key, nonce, aad, flip_bit(ct_tag, 10, 0x04)),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_ct is Err(@crypto.AuthFailed))
  let bad_aad : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.chacha20_poly1305_open(key, nonce, flip_bit(aad, 0, 0x01), ct_tag),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_aad is Err(@crypto.AuthFailed))
  let bad_tag : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.chacha20_poly1305_open(
      key,
      nonce,
      aad,
      flip_bit(ct_tag, ct_tag.length() - 1, 0x01),
    ),
  ) catch {
    e => Err(e)
  }
  assert_true(bad_tag is Err(@crypto.AuthFailed))
}

///|
test "x25519 RFC 7748 section 5.2 and 6.1 vectors" {
  // Section 5.2 Test Vector 1
  let s1 = from_hex(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let u1 = from_hex(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  assert_eq(
    @crypto.x25519(s1, u1),
    from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
  )
  // Section 5.2 Test Vector 2 (bit 255 set in u_coord)
  let s2 = from_hex(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
  )
  let u2 = from_hex(
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
  )
  assert_eq(
    @crypto.x25519(s2, u2),
    from_hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
  )
  // Section 5.2 Iterated test (1 and 1,000 iterations)
  let mut k = from_hex(
    "0900000000000000000000000000000000000000000000000000000000000000",
  )
  let mut u = k
  for i = 1; i <= 1000; i = i + 1 {
    let next_k = @crypto.x25519(k, u)
    u = k
    k = next_k
    if i == 1 {
      assert_eq(
        k,
        from_hex(
          "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        ),
      )
    }
  }
  assert_eq(
    k,
    from_hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
  )
  // Section 6.1 Alice / Bob DH exchange
  let alice_priv = from_hex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let alice_pub = @crypto.x25519_public_key(alice_priv)
  assert_eq(
    alice_pub,
    from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  )
  let bob_priv = from_hex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let bob_pub = @crypto.x25519_public_key(bob_priv)
  assert_eq(
    bob_pub,
    from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  )
  let expected_shared = from_hex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_eq(@crypto.x25519_dh(alice_priv, bob_pub), expected_shared)
  assert_eq(@crypto.x25519_dh(bob_priv, alice_pub), expected_shared)
  // Low-order all-zero point must be rejected by x25519_dh
  let zero_pt = Bytes::make(32, b'\x00')
  let low_order : Result[Bytes, @crypto.CryptoError] = Ok(
    @crypto.x25519_dh(alice_priv, zero_pt),
  ) catch {
    e => Err(e)
  }
  assert_true(low_order is Err(@crypto.LowOrderPoint))
}

///|
test "ed25519 RFC 8032 section 7.1 vectors and malleability rejection" {
  // TEST 1: empty message
  let sk1 = from_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk1 = from_hex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let sig1_exp = from_hex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  assert_eq(@crypto.ed25519_public_key(sk1), pk1)
  let sig1 = @crypto.ed25519_sign(sk1, b"")
  assert_eq(sig1, sig1_exp)
  assert_true(@crypto.ed25519_verify(pk1, b"", sig1))
  // TEST 2: 0x72
  let sk2 = from_hex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let pk2 = from_hex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let msg2 = from_hex("72")
  let sig2_exp = from_hex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  assert_eq(@crypto.ed25519_public_key(sk2), pk2)
  let sig2 = @crypto.ed25519_sign(sk2, msg2)
  assert_eq(sig2, sig2_exp)
  assert_true(@crypto.ed25519_verify(pk2, msg2, sig2))
  // TEST 3: 0xaf82
  let sk3 = from_hex(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  )
  let pk3 = from_hex(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  )
  let msg3 = from_hex("af82")
  let sig3_exp = from_hex(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
  assert_eq(@crypto.ed25519_public_key(sk3), pk3)
  let sig3 = @crypto.ed25519_sign(sk3, msg3)
  assert_eq(sig3, sig3_exp)
  assert_true(@crypto.ed25519_verify(pk3, msg3, sig3))
  // TEST SHA(abc)
  let sk4 = from_hex(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
  )
  let pk4 = from_hex(
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
  )
  let msg4 = @crypto.sha512(b"abc")
  let sig4_exp = from_hex(
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  )
  assert_eq(@crypto.ed25519_public_key(sk4), pk4)
  let sig4 = @crypto.ed25519_sign(sk4, msg4)
  assert_eq(sig4, sig4_exp)
  assert_true(@crypto.ed25519_verify(pk4, msg4, sig4))
  // Tamper message, signature, public key
  assert_false(@crypto.ed25519_verify(pk1, b"x", sig1))
  assert_false(@crypto.ed25519_verify(pk1, b"", flip_bit(sig1, 0, 1)))
  assert_false(@crypto.ed25519_verify(pk1, b"", flip_bit(sig1, 63, 1)))
  assert_false(@crypto.ed25519_verify(flip_bit(pk1, 0, 1), b"", sig1))
  // Non-canonical S >= L (add L to S of valid sig1: mathematically [S+L]B == [S]B, must be rejected!)
  let l_bytes = from_hex(
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
  )
  let malleable_arr = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    malleable_arr[i] = sig1[i]
  }
  let mut carry = 0
  for i = 0; i < 32; i = i + 1 {
    let sum = sig1[32 + i].to_int() + l_bytes[i].to_int() + carry
    malleable_arr[32 + i] = (sum & 0xff).to_byte()
    carry = sum >> 8
  }
  let malleable_sig = Bytes::makei(64, fn(i) { malleable_arr[i] })
  assert_false(@crypto.ed25519_verify(pk1, b"", malleable_sig))
  // Wrong lengths
  assert_false(@crypto.ed25519_verify(b"short", b"", sig1))
  assert_false(@crypto.ed25519_verify(pk1, b"", b"short"))
  let sig_err : Result[Unit, @crypto.CryptoError] = Ok(
    @crypto.ed25519_verify_or_raise(pk1, b"tampered", sig1),
  ) catch {
    e => Err(e)
  }
  assert_true(sig_err is Err(@crypto.InvalidSignature))
}

///|
test "DeterministicRng reproducibility, independence, and non-repetition" {
  let r1 = @crypto.DeterministicRng::from_seed(b"moonmls-seed-1")
  let r2 = @crypto.DeterministicRng::from_seed(b"moonmls-seed-1")
  let r3 = @crypto.DeterministicRng::from_seed(b"moonmls-seed-2")
  let a1 = r1.next_bytes(32)
  let a2 = r2.next_bytes(32)
  let a3 = r3.next_bytes(32)
  assert_eq(a1, a2)
  assert_false(@crypto.ct_equal(a1, a3))
  let b1 = r1.next_bytes(32)
  let b2 = r2.next_bytes(32)
  assert_eq(b1, b2)
  assert_false(@crypto.ct_equal(a1, b1))
  // 32-byte seed direct path
  let seed32 = Bytes::make(32, b'\x42')
  let r4 = @crypto.DeterministicRng::from_seed(seed32)
  let r5 = @crypto.DeterministicRng::from_seed(seed32)
  assert_eq(r4.next_bytes(128), r5.next_bytes(128))
  // Long output has no repeating 32-byte blocks
  let long_out = r4.next_bytes(1024)
  assert_eq(long_out.length(), 1024)
  for i = 0; i < 32; i = i + 1 {
    let bi = Bytes::makei(32, fn(k) { long_out[i * 32 + k] })
    for j = i + 1; j < 32; j = j + 1 {
      let bj = Bytes::makei(32, fn(k) { long_out[j * 32 + k] })
      assert_false(@crypto.ct_equal(bi, bj))
    }
  }
}
