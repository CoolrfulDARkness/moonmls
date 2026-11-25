///|
fn vec_hex(s : String) -> Bytes raise {
  @tls.bytes_from_hex(s)
}

///|
fn vec_opt_uint(v : Int) -> UInt? {
  if v < 0 {
    None
  } else {
    Some(v.reinterpret_as_uint())
  }
}

///|
fn verify_message_protection_e2e(
  cs_id : UInt,
  group_id_hex : String,
  epoch : UInt64,
  tree_hash_hex : String,
  confirmed_transcript_hash_hex : String,
  sign_priv_hex : String,
  sign_pub_hex : String,
  encryption_secret_hex : String,
  sender_data_secret_hex : String,
  membership_key_hex : String,
  proposal_hex : String,
  proposal_pub_hex : String,
  proposal_priv_hex : String,
  commit_hex : String,
  commit_pub_hex : String,
  commit_priv_hex : String,
  application_hex : String,
  application_priv_hex : String,
) -> Unit raise {
  let cs = @cs.CipherSuite::from_id(cs_id)
  let group_id = vec_hex(group_id_hex)
  let gc : @types.GroupContext = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs_id,
    group_id,
    epoch,
    tree_hash: vec_hex(tree_hash_hex),
    confirmed_transcript_hash: vec_hex(confirmed_transcript_hash_hex),
    extensions: [],
  }
  let sign_priv = vec_hex(sign_priv_hex)
  let sign_pub = vec_hex(sign_pub_hex)
  let encryption_secret = vec_hex(encryption_secret_hex)
  let sender_data_secret = vec_hex(sender_data_secret_hex)
  let membership_key = vec_hex(membership_key_hex)
  let expected_proposal = @types.Proposal::from_bytes(vec_hex(proposal_hex))
  let expected_commit = @types.Commit::from_bytes(vec_hex(commit_hex))
  let expected_application = vec_hex(application_hex)

  // Verify signature keypair matches CS
  let (_sk, derived_pub) = cs.signature_keypair_from_seed(sign_priv)
  assert_eq(derived_pub, sign_pub)

  // 1. proposal_pub: unprotect + deterministic byte-for-byte re-protect
  let prop_pub_raw = vec_hex(proposal_pub_hex)
  let prop_pub_msg = match @types.MlsMessage::from_bytes(prop_pub_raw).body {
    PublicMessage(m) => m
    _ => fail("expected PublicMessage for proposal_pub")
  }
  let prop_pub_ac = @schedule.unprotect_public_message(
    cs, sign_pub, Some(membership_key), prop_pub_msg, Some(gc),
  )
  assert_eq(
    prop_pub_ac.content.content,
    @types.FramedContentBody::Proposal(expected_proposal),
  )
  let re_prop_pub = @schedule.protect_public_message(
    cs, sign_priv, Some(membership_key), prop_pub_ac.content, Some(gc), None,
  )
  assert_eq(
    @types.MlsMessage::public_message(re_prop_pub).to_bytes(),
    prop_pub_raw,
  )

  // 2. commit_pub: unprotect + deterministic byte-for-byte re-protect
  let commit_pub_raw = vec_hex(commit_pub_hex)
  let commit_pub_msg = match @types.MlsMessage::from_bytes(commit_pub_raw).body {
    PublicMessage(m) => m
    _ => fail("expected PublicMessage for commit_pub")
  }
  let commit_pub_ac = @schedule.unprotect_public_message(
    cs, sign_pub, Some(membership_key), commit_pub_msg, Some(gc),
  )
  assert_eq(
    commit_pub_ac.content.content,
    @types.FramedContentBody::Commit(expected_commit),
  )
  let re_commit_pub = @schedule.protect_public_message(
    cs,
    sign_priv,
    Some(membership_key),
    commit_pub_ac.content,
    Some(gc),
    commit_pub_ac.auth.confirmation_tag,
  )
  assert_eq(
    @types.MlsMessage::public_message(re_commit_pub).to_bytes(),
    commit_pub_raw,
  )

  // 3. proposal_priv: REAL @tree.SecretTree + @schedule full decryption & replay check
  let prop_priv_raw = vec_hex(proposal_priv_hex)
  let prop_priv_msg = match @types.MlsMessage::from_bytes(prop_priv_raw).body {
    PrivateMessage(m) => m
    _ => fail("expected PrivateMessage for proposal_priv")
  }
  // Cross-check @tree vs @schedule sender_data key/nonce derivation
  let (sch_sd_k, sch_sd_n) = @schedule.derive_sender_data_key_nonce(
    cs, sender_data_secret, prop_priv_msg.ciphertext,
  )
  assert_eq(
    @tree.derive_sender_data_key(
      cs, sender_data_secret, prop_priv_msg.ciphertext,
    ),
    sch_sd_k,
  )
  assert_eq(
    @tree.derive_sender_data_nonce(
      cs, sender_data_secret, prop_priv_msg.ciphertext,
    ),
    sch_sd_n,
  )
  let prop_sd = @schedule.decrypt_sender_data(
    cs, sender_data_secret, prop_priv_msg,
  )
  let prop_st = @tree.SecretTree::new(cs, encryption_secret, 2U)
  let (prop_k, prop_n) = prop_st.handshake_key_nonce_for_generation(
    prop_sd.leaf_index,
    prop_sd.generation,
  )
  let prop_priv_ac = @schedule.decrypt_private_message_with_keys(
    cs, sign_pub, gc, prop_sd, prop_k, prop_n, prop_priv_msg,
  )
  assert_eq(
    prop_priv_ac.content.content,
    @types.FramedContentBody::Proposal(expected_proposal),
  )
  // Replay on consumed SecretTree generation must fail with ReplayDetected
  let mut prop_replay = false
  try {
    let _ = prop_st.handshake_key_nonce_for_generation(
      prop_sd.leaf_index,
      prop_sd.generation,
    )
  } catch {
    @tree.TreeError::ReplayDetected(g) => prop_replay = g == prop_sd.generation
    _ => fail("expected ReplayDetected on proposal_priv SecretTree")
  }
  assert_true(prop_replay)
  // Round-trip re-encryption
  let re_prop_priv = @schedule.encrypt_private_message_with_keys(
    cs,
    sender_data_secret,
    prop_sd,
    prop_k,
    prop_n,
    prop_priv_ac.content,
    prop_priv_ac.auth,
    0,
  )
  let re_prop_sd = @schedule.decrypt_sender_data(
    cs, sender_data_secret, re_prop_priv,
  )
  let re_prop_ac = @schedule.decrypt_private_message_with_keys(
    cs, sign_pub, gc, re_prop_sd, prop_k, prop_n, re_prop_priv,
  )
  assert_eq(re_prop_ac, prop_priv_ac)

  // 4. commit_priv: REAL @tree.SecretTree + @schedule full decryption
  let commit_priv_raw = vec_hex(commit_priv_hex)
  let commit_priv_msg = match
    @types.MlsMessage::from_bytes(commit_priv_raw).body {
    PrivateMessage(m) => m
    _ => fail("expected PrivateMessage for commit_priv")
  }
  let commit_sd = @schedule.decrypt_sender_data(
    cs, sender_data_secret, commit_priv_msg,
  )
  let commit_st = @tree.SecretTree::new(cs, encryption_secret, 2U)
  let (commit_k, commit_n) = commit_st.handshake_key_nonce_for_generation(
    commit_sd.leaf_index,
    commit_sd.generation,
  )
  let commit_priv_ac = @schedule.decrypt_private_message_with_keys(
    cs, sign_pub, gc, commit_sd, commit_k, commit_n, commit_priv_msg,
  )
  assert_eq(
    commit_priv_ac.content.content,
    @types.FramedContentBody::Commit(expected_commit),
  )
  assert_true(commit_priv_ac.auth.confirmation_tag is Some(_))

  // 5. application_priv: REAL @tree.SecretTree + @schedule full decryption & replay check
  let app_priv_raw = vec_hex(application_priv_hex)
  let app_priv_msg = match @types.MlsMessage::from_bytes(app_priv_raw).body {
    PrivateMessage(m) => m
    _ => fail("expected PrivateMessage for application_priv")
  }
  let app_sd = @schedule.decrypt_sender_data(
    cs, sender_data_secret, app_priv_msg,
  )
  let app_st = @tree.SecretTree::new(cs, encryption_secret, 2U)
  let (app_k, app_n) = app_st.application_key_nonce_for_generation(
    app_sd.leaf_index,
    app_sd.generation,
  )
  let app_priv_ac = @schedule.decrypt_private_message_with_keys(
    cs, sign_pub, gc, app_sd, app_k, app_n, app_priv_msg,
  )
  assert_eq(
    app_priv_ac.content.content,
    @types.FramedContentBody::Application(expected_application),
  )
  let mut app_replay = false
  try {
    let _ = app_st.application_key_nonce_for_generation(
      app_sd.leaf_index,
      app_sd.generation,
    )
  } catch {
    @tree.TreeError::ReplayDetected(g) => app_replay = g == app_sd.generation
    _ => fail("expected ReplayDetected on application_priv SecretTree")
  }
  assert_true(app_replay)
}

///|
test "IETF message-protection.json CS1 full 5-of-5 with real SecretTree + schedule" {
  verify_message_protection_e2e(
    1U,
    "42e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780",
    1184274UL,
    "a257a326c7b632ce7ccdea8d3a3b5c3c2daa53a21029b3673ee05e9a3cea5934",
    "59b10f7a137e853c4ef7ce43d2fe0a481bb80652f648c5efab11c3141a1ba60c",
    "3091b9149866552f1bc8452aacd58b0a0b2ef87f2bb606d03ef6c06da0ca5cfc",
    "62087f5b047e5292d5d29ded0977442788633c196a607988238b8c4374b4b4be",
    "4db33574f514024e61e2a15e71527182f62561d84b4d8230501b623d848df998",
    "b21dfbbf69da2fec93299d8bd0795ad0aec22b42d83ff10a2e5e3f997672b8b3",
    "1f338b39337d019ab52c797bc836875998387e88fe711287df2258bc8f9967fb",
    "000300000002",
    "000100012042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa7800000000000121212010000000100020003000000024040932e43773e992f7b0c8ec9d82f72c9395ad62120f19a764e50ec150ca48ba94dbb139a1f9c6901aab353d67f97f68210027818f634ac9cf8a738fe35b7404906201be6bf2e5e22e38a6f908d534a04ae231c3f6de72750d74bbf626a2c0bfcf1ec",
    "000100022042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121202001cf8f3a79aa9f3cbc60ea1e886e46dd6dcbcde71e80f7e46a68b88edeb4058b7761be40499be70b7a0b5f4e2b151b20250153fe6af4599853b1b351ad6c68a7d7490cd58301a3ed08b2bfc254feee2f14f63df0bafa7994b6957dc449384b06b6cd24bd228d8870d5ba8a346fcca8dcaacadd95959443c",
    "404601000401205ff3e28b8183cba127d0b74459b5d8a81286c299ba02d68c7d62f6101c3782dc20e0fbf69e4e80c4b2b8d43ffac9c0863a25300d0a6880aa9287d3916c467ae3ab00",
    "000100012042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121201000000010003404601000401205ff3e28b8183cba127d0b74459b5d8a81286c299ba02d68c7d62f6101c3782dc20e0fbf69e4e80c4b2b8d43ffac9c0863a25300d0a6880aa9287d3916c467ae3ab0040403fe4fb435c134950173cf4244a899e3a3fedb6d77dde1279b8a1b03a507109661d82e6e08f9a476ebad8983ce83a1218dbf4df0b538e88d3d8ffb0cbc5fffb0120b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad2096f30e3de73f8f49037897e7e2ff6964857d7e662c6823cea2b5c4b78c3b03a2",
    "000100022042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121203001c97a2cc4f511ed694db9bd5ca4aeb06b5eb5fb92765f41feeece83a4040bc6c0e40ad742111fe68c17b0848c047f6909e0675dce492f4e2635fda105d20aac769b1b3916267a396235cbf955e1843072f62466f6c328f535bf7ecc326c224ae1b24c574ba543c0d1dc27328dfe10b221a43c29a0ea76e3e475980995e92cdf0c7b21bde1fcbb6bc5cc92b920b4b8bced424ccd518d2b7e738fe4c582040ef866cbe8afe72e76a8bae2e19e20a5c901d12baf43c2f01d98813a775ec5c6fdba27c8ccd1cc024dc95e4138bf8dd0135998c598240a0c87d5fe225b2",
    "a1ab266714fdb6d121f4c7f248271fb824a3e61dd3f91835e68fc8789f17f754a86233781fb59d23811b",
    "000100022042e4c3a73738d838cb4f9dc550cb81406206943f9e6870ee150f2000ae8aa780000000000012121201001cf18ad2e0ad4462390d72714d68b2a845ba336c3e8d398d21334f8d0f407dab47ce77c5fff3107b2f4e4bf99936c0ec680364333403663b7a955708a73d91e921a4fb3ffd50292a51ec31d4ec684231eb6f765cfbd5cca5b78fbe42bbf1b04dd1682fc87678b3a4f1599770839b171caff15e5e264957f3d16c31ba3ca16416f4665115244291536ddb438528cdb8502de654be9ca093915d36b1ab",
  )
}

///|
test "IETF message-protection.json CS3 full 5-of-5 with real SecretTree + schedule" {
  verify_message_protection_e2e(
    3U,
    "fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf",
    1184274UL,
    "5ae6ee5f282786b753d55f15938248f6212c69b2f677319e5fcdb2ce0bfbf48a",
    "0ba35f0d36007bc44df41db074b9d98a1314e3c690cb345ceeae152fbe5b6afe",
    "d48bc8fcb54ad6e48eb55e773577030224af3a68308cd4a2a2c3f939a774c1a0",
    "b1d7f2e45d6c94fa8bff3b63308bbba38024c5b70c22234834ee24294b6e0a28",
    "ce02c4dd80a8ed57503e3a50ec11b926a549d65e840417c0635427a838b3cf29",
    "85fc31fac878dbe2850e30a8fa88bdc63dacd890756aade03433791b50a510f5",
    "82f73c829938c5d1a19e19de2b2c109214455ee6671cf918af426f364162678e",
    "000300000002",
    "0001000120fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf00000000001212120100000001000200030000000240402aef68e55e2092800105a0a963c84afb2039093f5431f9c59fce19d3f2bca20689a617deb8fa59085f21b609649b0373e62c0c099e9bfc66f939e623a851d3022048451581d2796c68ca95ddbf06fe4cc69f5b1360f12dce5947e095ab26c259a3",
    "0001000220fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf000000000012121202001cc15e1b90a18448376191078a6b66567941ce2472f110def1215eb1114058f9bf6e2c2dd19ff11b450ce94d9990ca3dbaf94edf8873c0f7cbf8feeefd362ac674b32d4c1c6ca646b8282fec7aaa51dcdd402345792aa77d98eaa97da5bf13969e44845f33114c10e1edd765d1c738059757570366687b",
    "4046010004012017e89d9ff20be622654e2b82b1e55d5b51c9e01d3b02cf0fa179c14e8697c11620d3ad3e549ffe3fe157d4d2e6627b8d35be6b5b8f37ffb10ed358bfb47c6c829500",
    "0001000120fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf0000000000121212010000000100034046010004012017e89d9ff20be622654e2b82b1e55d5b51c9e01d3b02cf0fa179c14e8697c11620d3ad3e549ffe3fe157d4d2e6627b8d35be6b5b8f37ffb10ed358bfb47c6c82950040402ad9df6c6e068cfb07cd8a6e49455f256ca630341744128cdc2bd180c8dd76b8e2b3affc5e8c0b3a70d55e349e46adf95e2641299b6c1ac78336e69ec243860520b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad20aa0af8115702fcd155306e3f0091dbc40c772a97547ee9398157106ad10e9bf1",
    "0001000220fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf000000000012121203001c71db9299c28f6e4feec4ddd63660f8ee186769ba51f2721953c48b9440bc32b3c5b162267da077973a9966c1c1bf6406d4326d9b0649bffeceec9ebe4dcf8603aa291254ce1954471cb01670b8e8e2f111ed54f8c818b348bd0300eb174602b484899f2fa95bbebdae6807de23355e2a988cf30cdeb2327759b2274205f485ff15b668b00a4f36ead53e21091be1133c2dd9a635bd6a942509921e33647e864a26af80aa5e54e15e695d2156209c2da2a7b8fe1938632192fce5e75736249c2fb6a7c2af46b29bfb5a83699d568f6b5614bf4edca36dc290f71d",
    "725b6517ff1e5ed74224de23777a9b5f4a2dd74fe4a816d19ea71baa069d74c0975b7f10e61b7c3ef339",
    "0001000220fdbada2ddce02e7493673caab793308bdeb5cdb0558f151f647ab6e2ca0c63cf000000000012121201001c22d286c12043af1e8093bd213bf707b9b675ee98a171d0eeb206de91407d9d099e17b2aa1de37065098feb8efa598721128ec5bada3a6a07e06123eb61ced1dd265a0e7468f05f39b549ede80606f4795425de91acaee0b0bd840d0eabd284ae30adf04a5bf97027180836adee1203636c2cfd36f477747e9f0549dc99f5b3ef3a3db4f4def426625757365cf871061383a6dbd516127a11f83cc4",
  )
}

///|
test "IETF tree-math.json all 10 tree sizes cross-check" {
  let full_cases : Array[(UInt, UInt, UInt, Array[Int], Array[Int], Array[Int], Array[Int])] = [
    (1U, 1U, 0U, [-1], [-1], [-1], [-1]),
    (2U, 3U, 1U, [-1, 0, -1], [-1, 2, -1], [1, -1, 1], [2, -1, 0]),
    (4U, 7U, 3U, [-1, 0, -1, 1, -1, 4, -1], [-1, 2, -1, 5, -1, 6, -1], [1, 3, 1, -1, 5, 3, 5], [2, 5, 0, -1, 6, 1, 4]),
    (8U, 15U, 7U, [-1, 0, -1, 1, -1, 4, -1, 3, -1, 8, -1, 9, -1, 12, -1], [-1, 2, -1, 5, -1, 6, -1, 11, -1, 10, -1, 13, -1, 14, -1], [1, 3, 1, 7, 5, 3, 5, -1, 9, 11, 9, 7, 13, 11, 13], [2, 5, 0, 11, 6, 1, 4, -1, 10, 13, 8, 3, 14, 9, 12]),
    (16U, 31U, 15U, [-1, 0, -1, 1, -1, 4, -1, 3, -1, 8, -1, 9, -1, 12, -1, 7, -1, 16, -1, 17, -1, 20, -1, 19, -1, 24, -1, 25, -1, 28, -1], [-1, 2, -1, 5, -1, 6, -1, 11, -1, 10, -1, 13, -1, 14, -1, 23, -1, 18, -1, 21, -1, 22, -1, 27, -1, 26, -1, 29, -1, 30, -1], [1, 3, 1, 7, 5, 3, 5, 15, 9, 11, 9, 7, 13, 11, 13, -1, 17, 19, 17, 23, 21, 19, 21, 15, 25, 27, 25, 23, 29, 27, 29], [2, 5, 0, 11, 6, 1, 4, 23, 10, 13, 8, 3, 14, 9, 12, -1, 18, 21, 16, 27, 22, 17, 20, 7, 26, 29, 24, 19, 30, 25, 28]),
    (32U, 63U, 31U, [-1, 0, -1, 1, -1, 4, -1, 3, -1, 8, -1, 9, -1, 12, -1, 7, -1, 16, -1, 17, -1, 20, -1, 19, -1, 24, -1, 25, -1, 28, -1, 15, -1, 32, -1, 33, -1, 36, -1, 35, -1, 40, -1, 41, -1, 44, -1, 39, -1, 48, -1, 49, -1, 52, -1, 51, -1, 56, -1, 57, -1, 60, -1], [-1, 2, -1, 5, -1, 6, -1, 11, -1, 10, -1, 13, -1, 14, -1, 23, -1, 18, -1, 21, -1, 22, -1, 27, -1, 26, -1, 29, -1, 30, -1, 47, -1, 34, -1, 37, -1, 38, -1, 43, -1, 42, -1, 45, -1, 46, -1, 55, -1, 50, -1, 53, -1, 54, -1, 59, -1, 58, -1, 61, -1, 62, -1], [1, 3, 1, 7, 5, 3, 5, 15, 9, 11, 9, 7, 13, 11, 13, 31, 17, 19, 17, 23, 21, 19, 21, 15, 25, 27, 25, 23, 29, 27, 29, -1, 33, 35, 33, 39, 37, 35, 37, 47, 41, 43, 41, 39, 45, 43, 45, 31, 49, 51, 49, 55, 53, 51, 53, 47, 57, 59, 57, 55, 61, 59, 61], [2, 5, 0, 11, 6, 1, 4, 23, 10, 13, 8, 3, 14, 9, 12, 47, 18, 21, 16, 27, 22, 17, 20, 7, 26, 29, 24, 19, 30, 25, 28, -1, 34, 37, 32, 43, 38, 33, 36, 55, 42, 45, 40, 35, 46, 41, 44, 15, 50, 53, 48, 59, 54, 49, 52, 39, 58, 61, 56, 51, 62, 57, 60]),
  ]
  for c = 0; c < full_cases.length(); c = c + 1 {
    let (nl, nn, rt, lefts, rights, parents, siblings) = full_cases[c]
    assert_eq(@treemath.node_width(nl), nn)
    assert_eq(@treemath.leaf_count(nn), nl)
    assert_eq(@treemath.root(nl), rt)
    for x = 0; x < nn.reinterpret_as_int(); x = x + 1 {
      let xu = x.reinterpret_as_uint()
      assert_eq(@treemath.left(xu), vec_opt_uint(lefts[x]))
      assert_eq(@treemath.right(xu), vec_opt_uint(rights[x]))
      assert_eq(@treemath.parent(xu, nl), vec_opt_uint(parents[x]))
      assert_eq(@treemath.sibling(xu, nl), vec_opt_uint(siblings[x]))
    }
  }
  let large_cases : Array[(UInt, UInt, UInt, Array[(UInt, Int, Int, Int, Int)])] = [
    (64U, 127U, 63U, [(0U, -1, -1, 1, 2), (1U, 0, 2, 3, 5), (2U, -1, -1, 1, 0), (3U, 1, 5, 7, 11), (62U, -1, -1, 61, 60), (63U, 31, 95, -1, -1), (64U, -1, -1, 65, 66), (124U, -1, -1, 125, 126), (125U, 124, 126, 123, 121), (126U, -1, -1, 125, 124)]),
    (128U, 255U, 127U, [(0U, -1, -1, 1, 2), (1U, 0, 2, 3, 5), (2U, -1, -1, 1, 0), (3U, 1, 5, 7, 11), (126U, -1, -1, 125, 124), (127U, 63, 191, -1, -1), (128U, -1, -1, 129, 130), (252U, -1, -1, 253, 254), (253U, 252, 254, 251, 249), (254U, -1, -1, 253, 252)]),
    (256U, 511U, 255U, [(0U, -1, -1, 1, 2), (1U, 0, 2, 3, 5), (2U, -1, -1, 1, 0), (3U, 1, 5, 7, 11), (254U, -1, -1, 253, 252), (255U, 127, 383, -1, -1), (256U, -1, -1, 257, 258), (508U, -1, -1, 509, 510), (509U, 508, 510, 507, 505), (510U, -1, -1, 509, 508)]),
    (512U, 1023U, 511U, [(0U, -1, -1, 1, 2), (1U, 0, 2, 3, 5), (2U, -1, -1, 1, 0), (3U, 1, 5, 7, 11), (510U, -1, -1, 509, 508), (511U, 255, 767, -1, -1), (512U, -1, -1, 513, 514), (1020U, -1, -1, 1021, 1022), (1021U, 1020, 1022, 1019, 1017), (1022U, -1, -1, 1021, 1020)]),
  ]
  for c = 0; c < large_cases.length(); c = c + 1 {
    let (nl, nn, rt, checks) = large_cases[c]
    assert_eq(@treemath.node_width(nl), nn)
    assert_eq(@treemath.leaf_count(nn), nl)
    assert_eq(@treemath.root(nl), rt)
    for j = 0; j < checks.length(); j = j + 1 {
      let (x, l, r, p, s) = checks[j]
      assert_eq(@treemath.left(x), vec_opt_uint(l))
      assert_eq(@treemath.right(x), vec_opt_uint(r))
      assert_eq(@treemath.parent(x, nl), vec_opt_uint(p))
      assert_eq(@treemath.sibling(x, nl), vec_opt_uint(s))
    }
  }
}

///|
test "IETF crypto-basics.json CS1 & CS3 cross-package verification" {
  {
    let cs = @cs.CipherSuite::from_id(1U)
    assert_eq(cs.ref_hash("RefHash", vec_hex("40312db83f651883c05ab26fa12c6af61930015c81947cfd0f129e6d99210bb2")), vec_hex("e8027fffc5f9bb469f29172538dc0f3a78f14f323495bbd2217eba7a77fb242a"))
    assert_eq(cs.expand_with_label(vec_hex("1499360a561335f4ef51d0a1b0d586900dc8007ae405b1ab79bf4207bb3d67e4"), "ExpandWithLabel", vec_hex("2ff8c1f9d9c1248f82e372ddb5791c771695e01882abca6a64097bd2f04c971f"), 16), vec_hex("c1e8eb360391526c0c64039f13e0c5b1"))
    assert_eq(cs.derive_secret(vec_hex("1a9ce178a53f8752d2513c27efe9c85133f6c0a97f7b35ac200695024a77228e"), "DeriveSecret"), vec_hex("3b08c195a246c4ad469c1d11c10e62890d8fa6b684494ff925409efdb1ff0464"))
    assert_eq(cs.derive_tree_secret(vec_hex("5133c6f8bad297f5d3beacdf477f0c45ec51b02de659d305220c5f9385c6eb43"), "DeriveTreeSecret", 2694881440U, 32), vec_hex("8461f3ccc603eae52149a23a4134d29c880a1ad1ba70441e5d586e3521ec7b25"))
    assert_true(cs.verify_with_label(vec_hex("85600e54e5c2919ccbd0742126e5d837cf7a2ba50d75a69b3f35dcfe4a50ffe2"), "SignWithLabel", vec_hex("cd289cc7ba2869f64f3c32ffd133f500d17abace919a5ffe7faa974200d81932"), vec_hex("996bd223ddb4d55a2b57d85cb2944f21facc95696053ddf66d590060fdc719f4a26c6212ce605414e0d5e66a55921dd99d11122218c35bc23408b0076e8bc40b")))
    assert_eq(cs.sign_with_label(vec_hex("a2f640dd5005fcad6adb8e9bd8b60d70946bb802e1e788307929fdac81e1ec74"), "SignWithLabel", vec_hex("cd289cc7ba2869f64f3c32ffd133f500d17abace919a5ffe7faa974200d81932")), vec_hex("996bd223ddb4d55a2b57d85cb2944f21facc95696053ddf66d590060fdc719f4a26c6212ce605414e0d5e66a55921dd99d11122218c35bc23408b0076e8bc40b"))
    let pt = cs.decrypt_with_label(vec_hex("fb1ade7939987ff12a9d620772b1f9f7caeba26f8a3ecea9617d9402cd862444"), "EncryptWithLabel", vec_hex("26347dd7f218d1de8673d6a66646ce06ac5fd3aa8d5c33f65d86aeefdcf4a31e"), vec_hex("0a144e8fbf2d6dcf6fe9d2e2b8aeca5461ff5b0ea9c0ede1040c3dc7ed1dfd1c"), vec_hex("15c80ea2bc37db221baa530ef5aea88650f0ce0f262803d6f78f3a1392f7ccd960eff94ca081ee54efa4c3acfa0eb591"))
    assert_eq(pt, vec_hex("8f55dd30f03d64335c22b53ea7670bb1becf49b04021f706368fe93eeb358f46"))
    let rng = @crypto.DeterministicRng::from_seed(b"cb-rt-1")
    let (kem_out, ct) = cs.encrypt_with_label(vec_hex("ecea6564da58d6c6cff6c733bd4ae0815b1f60bb911b73e4ef1d06263ec4ce58"), "EncryptWithLabel", vec_hex("26347dd7f218d1de8673d6a66646ce06ac5fd3aa8d5c33f65d86aeefdcf4a31e"), pt, rng)
    assert_eq(cs.decrypt_with_label(vec_hex("fb1ade7939987ff12a9d620772b1f9f7caeba26f8a3ecea9617d9402cd862444"), "EncryptWithLabel", vec_hex("26347dd7f218d1de8673d6a66646ce06ac5fd3aa8d5c33f65d86aeefdcf4a31e"), kem_out, ct), pt)
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    assert_eq(cs.ref_hash("RefHash", vec_hex("4f0c86f9c82fba0a896bd7eecf79a29856e98a7e4f13b9f841ae285d70ed8b68")), vec_hex("f11019703c8b630060839b12a475fd39c6a30f8a866790ff46a35f9c65e1df3c"))
    assert_eq(cs.expand_with_label(vec_hex("55aa3ae5242564782567ce097beafe19510230660008b2cc064a78387fa16f36"), "ExpandWithLabel", vec_hex("2e07148f4340c62a55e7608c20d73fddf1f3b8dafb2c7ef24eceb70e136c0d8c"), 32), vec_hex("1df5ba7996a34f75d717916a094a14083c03a75e80f0330a8095f5f11cfe1e1f"))
    assert_eq(cs.derive_secret(vec_hex("cae460c779ebaa3e81c061a371486dff1ed1ff273bea369cc0fc46550b83c407"), "DeriveSecret"), vec_hex("aad859818ca5f2a9896d4d3ee2dccc0cefcd69b666bdb16b52f1de15fb1a5567"))
    assert_eq(cs.derive_tree_secret(vec_hex("c994e257b53f726087ddd7121876f558f1fbd6f807e5ff010830d618d7bab6f2"), "DeriveTreeSecret", 2694881440U, 32), vec_hex("2095d6a81ab87095d1df26f6bdf012ec06f197e418381c1795a7b758603c936d"))
    assert_true(cs.verify_with_label(vec_hex("18275f892ee0ca6f4687ff26c990776387502646ff658c3f572b324faecb05c5"), "SignWithLabel", vec_hex("df308cf2dbf471edf2c29d30e3daf161b5b87d350ee3b2c715c298ec3d10d432"), vec_hex("4f56851c2c47f5115a61ff0ab6121b4a4732d4e94805fc7135a5132f87d5ca5f1dc7408816c1ea4f25887725cf5914b48c427a52cabcfeb746a2b8a12e821f08")))
    assert_eq(cs.sign_with_label(vec_hex("4e312160ee4981358db479aa877412847abc7f7054b5605511256c395404d054"), "SignWithLabel", vec_hex("df308cf2dbf471edf2c29d30e3daf161b5b87d350ee3b2c715c298ec3d10d432")), vec_hex("4f56851c2c47f5115a61ff0ab6121b4a4732d4e94805fc7135a5132f87d5ca5f1dc7408816c1ea4f25887725cf5914b48c427a52cabcfeb746a2b8a12e821f08"))
    let pt = cs.decrypt_with_label(vec_hex("9d122ad4638fcb301b6eb5f4073414afb44bb34d37b4ddee9975b2941d700edb"), "EncryptWithLabel", vec_hex("0d6a5cf9ee88b1f8c79d8512477d9bfc5496c207c8173f8dcac0368b4dba7407"), vec_hex("f26e9e5a94396a90f85a5f72eedf3dacfb1b7f4164e0573edeb9c6c912e1cb49"), vec_hex("40dd09ad4c5dc29d373f814bf054c9359cb75a468bc4d2c8bbcffb072a73105c4d9416ebd4fafeb62e59a9dea55da3cd"))
    assert_eq(pt, vec_hex("1dd4c1904996ce7d42cee7de68881459fa7a345da59a02040ade37103505baf6"))
    let rng = @crypto.DeterministicRng::from_seed(b"cb-rt-3")
    let (kem_out, ct) = cs.encrypt_with_label(vec_hex("7a5544b59f5940bf093c921469a00a170a7c92ba56c173d74db32713608d8a40"), "EncryptWithLabel", vec_hex("0d6a5cf9ee88b1f8c79d8512477d9bfc5496c207c8173f8dcac0368b4dba7407"), pt, rng)
    assert_eq(cs.decrypt_with_label(vec_hex("9d122ad4638fcb301b6eb5f4073414afb44bb34d37b4ddee9975b2941d700edb"), "EncryptWithLabel", vec_hex("0d6a5cf9ee88b1f8c79d8512477d9bfc5496c207c8173f8dcac0368b4dba7407"), kem_out, ct), pt)
  }
}

///|
test "IETF key-schedule.json CS1 & CS3 all 5 epochs + exporter + SecretTree bridge" {
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let group_id = vec_hex("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
    let mut cur_init = vec_hex("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
    let epochs : Array[(UInt64, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, Int, String)] = [
      (0UL, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818", "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f", "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00", "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509", "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b", "4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d", "ddcd9ced2d264798f876cbd00a200cdc4d77311dfef96975257efb66b0ef2c4d", "505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9", "9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4", "01588615c93d02c83bda0b587473303b1637a92bf80783206d963f9197c40a13", "5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea", "7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643", "b5cb5666cfb9c501ed76715c6ed1cafbed5061cd6b86898ae5d3fd4cb05abb26", "feabd690de3b4ce985a3dfad86a4c4e6a0be9b84e7cc764842784f2a6b938b75", "970744ba7edd21700a3e106cb4e2b4c657cef6b41a1fe5b5a1418f86e76e037e", "d78ca815e192823f5c7c94b0156bdc7af4791cfb3f240fff613c0c03c01dabd5", "640117516be304ac1160933c894a6df9290231f1843f3685c124fc42c785c02c", "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4", "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785", 32, "dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb"),
      (1UL, "826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5d", "14a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e", "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000120826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5d2014a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e00", "7b3027aa5d2224aab7e2a18660bbf57930e2e21d95e02b849c704d970e3e28c5", "ca7a68f2a8a52147d70f1eb7195de968d2e182b93596bc5a61393861e91180e4", "7ba2c5eed466d6fa8de0b0f33553c7b336a2580c03820e79f22e9416efc5b9f9", "161b3d492aed45f9d9cde3ad8c4e6c936ca1c104977b7668727a014374afe489", "88586b2252f06838106a97f5ad1f3357d99d718be8f44f61ab103be653fc608a", "64035464638ac7cf16583644e8117a84ca3c101eaa34a86ad4ead9524f8fb9bc", "c607312fab6423cd728a25fd91e9905e058518d1bf171984ed5f4e4e057fa3be", "047d983048b132b79ea4e2e578afd02a0f4717d166cefe46e43e2e965b5c9f4e", "4bdbe62402b3caaadaf5c6fafd89db4db5ac7c7532f3e47d35c82b3998570361", "19a4869847b2637e3700599304be769023c729334462919c395481f6ef174010", "04ab9a788afe377d34b0fac1dc26085c85ac55a63e44b88da39fb4e58a898979", "1eb0202e445ebc744c00eb42951ad67638c51cc9a468d9035be06612ff5cd89a", "3b83961159a16b5d7c5f9a52344edfeea5ea92cf7b2fb069a53eedb90fe51de6", "4ad487e0aa90522dd81f9561695fd800569f313d33c42d1b2d785df734e96126", "ed66d7f1da52171ac9448f0f902edcfefa4ebbda843a43bd3d173cb7c5b4331e", "02dc18fc5bc4d9093cf41fa0053521653775b123784d40ac7d46cc5a72ef4d46", 32, "a702c3e70a89c06eae51aec3675918a4ee7698ae88c596dfb7abd1ed3a9ecf5e"),
      (2UL, "661ce3bd9ebec8608fa97bf5413a4588f50a8f9face225ec67a6d29c862b2516", "b5d7ec8c9d8b6a28c9467fe4918844be6acc08e98c1e10c71122e95f9a5e78c5", "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000220661ce3bd9ebec8608fa97bf5413a4588f50a8f9face225ec67a6d29c862b251620b5d7ec8c9d8b6a28c9467fe4918844be6acc08e98c1e10c71122e95f9a5e78c500", "d2825785628f1ea7404d6761f27272af5f99416ea28cc9d335df47ed2b0097d4", "599aa672406270914c60d30b7a31d2f2e217c3b5298b279b79e34c65a60e5f24", "5af09c405a0354e09b03714d5dd5d512cc93aff33979917b00bcf8ff364239f3", "89d13b67d2b4f36eaca621454ea345c3a67a76ee2ffb78e153a5243f2677a0a2", "ca13f80a46a3dff48551759bdeb081fcbf0a0be6fc74e33fc56209b377922a83", "e86474fdaaef42f5bd0913e06dab01ce63ae6c1f7a177e7acf100265b692466d", "e5ebb4f0b362e5ecb1753785d79802c2eb30b89033068a46c022fb9591be8c05", "69cb23d2ff46b36c466ad48911fd56ee108ab8d4ec1c91028622e9a93c067710", "408990a9228b3303b8cf89979d8698836fed7a4092220f91ec1753d56be14df6", "fc55b63c93d9c8b5596e5c314c7a04f684ae51f45d18571f52c0f3f3c0b3488b", "1a1c0cdbc1d8545116cf181c08467f1e8de1c6a4d7d865c73628b3c989625b8f", "8838cc5d52d7828fd87dcc3ca98a45e9169426e71545f4068726679d15d195c7", "69ca921c0bc0796ea4d476219ff929413f0936dba5474c76adf4fc466714f84f", "40d7a031830cc70d7fd71d2e5792f0a7850f012068d417d24803c4545e7f5d0e", "06f549e9bf966d7b7135b6ef6d4e3032a1c720adf0281c3ef1c0beac0da88621", "b0fa7e3f0f2199278a55267d551d43946bbfc6d847632867dd86abd1217982a5", 32, "07dd60ff9acb0278f80cae4c6f4ee69c745481f5bf967b21d237c18e48d78b4b"),
      (3UL, "08225ed7f3b0b8aa9f03b24395ed8ee7002d38209fddd7d941dd8ac629ac8a62", "dab8c2f8ec97a0e5a137c55a5b9ac1ccdf5ae8329810e98e0bc3930aae0b4be1", "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e00000000000000032008225ed7f3b0b8aa9f03b24395ed8ee7002d38209fddd7d941dd8ac629ac8a6220dab8c2f8ec97a0e5a137c55a5b9ac1ccdf5ae8329810e98e0bc3930aae0b4be100", "f652baa9151c9719ecb2716240a2a5ed9aeede1df19de0de862ded166a724783", "4106e07ffe8f0bfdbfd317d92e37a1fc6c4d1fba53ee054b7acf8587013d533b", "65ee9fa09f2d0da5022b9de54fb3753b58471d03106e9d479cd53030a6f58165", "e8eefa28cfb25ab8a05dd40ba81f4fac84852b4b56f79dbf55c7da0af08ebfae", "1a034b1838c873d3c536a5f007c2ecb34b6f44ce5fa716902755d6ab64398aad", "c3a28048c5b6d04872be40bff1f8e3d469250e2b9482fde4684cc40120e1bbc9", "735539658afe3bf936f091f430e4a85962c7b48b138e7b3b9a70f1290e5d6ffd", "9f2a260a99b352c9c9c90f081050380c9e8b5f400b41461f4e40690a2f111b03", "4705894cbf2a35f793bdc25045ddad0281dee5fd1836b3ed836c74ae6b23e7fd", "c6b645ebd6b263616fbf872d9d43b3a51338d4509164d8a3fe4f52c10ac45cea", "6345bb395af7657232ebab23196a690e16a90a51d87eeac7789c81935b8c2a30", "99372e5b9b27f332d9f1b1c669619c156eee9d6bb1908d4a7ed89eb5fb511f29", "b3ffe5ef8de8e569879d48cd5b64bcaef7127eafc052da4eb25e64e2b951af52", "c35219e0a19625baef97a90c7adfd1c0d566b3536fa8d980d8491248d6d57353", "b76193af29eadc6e16c66493e2a4ef8219aad79986b6d4911493741ec1e666cc", "941db06073e76050679d33cf1f0ec33de3e5a2cd00cb738b54c0dd90de251cdd", 32, "d379ee776bbaadb55b2bf74ffb4e53b96307611a115b6a67f165192b6c481bce"),
      (4UL, "918e07d9bfd965f880f860830b24427d9200fcac485e973b4943e67d322c1682", "5e88437e7e8e91582bc440a375e93280417c94c5e38db8537963dd3750dd3e16", "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000420918e07d9bfd965f880f860830b24427d9200fcac485e973b4943e67d322c1682205e88437e7e8e91582bc440a375e93280417c94c5e38db8537963dd3750dd3e1600", "50fb68cdd31ff76b8d86b88b80124534d845cf2a835411b002b40b7b08d28278", "c7e0f52b886962b1edde9e75b9ecafa0d8efeffb474732a3da298c470f1d1445", "4ace52a8c9dd70e8a71ec54d84a5aa64a5f7229d97f110849e49be6d93b6c65a", "d015f8f6ef8b89bf9555a3796d8759ffc500e63b3f1fd7a5b55c319646388109", "005eec47d467da14e21f9bf1e8f79b8ca64c27ce762f94fd0da253749d150384", "981607260c472cc61770cadee57fae7f02b5433246fa57ba64e712d6ed320845", "98e6bbb22b1d33ccc8d964da54abb79a6105af028c04799de6103320b42b9717", "7e6f8cedec75018d137c1d08444c8695e52fe73efe0650f928007dcbcfa48b2b", "c60fd8cebae30f72724eee59569c0a364a7c12e617f91bced41d5615886cc9cf", "ce214e92ce56cc0ef199984cf563f00e63114933acc529e12525ba72e07fd845", "7c46de2314426dfa41f137627860ed9601d13427556bc197f1ae029b17a22ed2", "eeba13b78014db447abd409b1fbbecfbfccd9ccb76ed4a43b47ca2d36b3a32ec", "cf1b198338aee226353358a7778c72e6785743516e3b5eff11378357c2db118b", "bed767d42b739546d6936035a4c59322f5228e444e06a31bb9ed3194da0fa523", "cc9c4b25b0bd69250b6e4f9908d1b170bf62fe8cc11ad36d33e602324ac0662a", "a0f762fc82d5e421d8fdf8a317b2fd463008c625bf19db7fbfa4ac778b5106a2", 32, "f4698636cc032717011a186a14a42cc49e95aeeb4d9bc8ab82295fc1543735ac"),
    ]
    for i = 0; i < epochs.length(); i = i + 1 {
      let (ep_num, th_h, cth_h, gc_h, cs_h, psk_h, js_h, ws_h, is_h, sds_h, es_h, exs_h, ea_h, ext_h, ck_h, mk_h, rpsk_h, ext_pub_h, exp_lbl, exp_ctx_h, exp_len, exp_out_h) = epochs[i]
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch: ep_num,
        tree_hash: vec_hex(th_h),
        confirmed_transcript_hash: vec_hex(cth_h),
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      assert_eq(gc_bytes, vec_hex(gc_h))
      let sec = @schedule.derive_epoch_secrets(cs, cur_init, vec_hex(cs_h), vec_hex(psk_h), gc_bytes)
      assert_eq(sec.joiner_secret, vec_hex(js_h))
      assert_eq(sec.welcome_secret, vec_hex(ws_h))
      assert_eq(sec.init_secret, vec_hex(is_h))
      assert_eq(sec.sender_data_secret, vec_hex(sds_h))
      assert_eq(sec.encryption_secret, vec_hex(es_h))
      assert_eq(sec.exporter_secret, vec_hex(exs_h))
      assert_eq(sec.epoch_authenticator, vec_hex(ea_h))
      assert_eq(sec.external_secret, vec_hex(ext_h))
      assert_eq(sec.confirmation_key, vec_hex(ck_h))
      assert_eq(sec.membership_key, vec_hex(mk_h))
      assert_eq(sec.resumption_psk, vec_hex(rpsk_h))
      assert_eq(sec.external_pub, vec_hex(ext_pub_h))
      let exp_val = @schedule.mls_exporter(cs, sec.exporter_secret, exp_lbl, vec_hex(exp_ctx_h), exp_len)
      assert_eq(exp_val, vec_hex(exp_out_h))
      let sec_j = @schedule.derive_epoch_secrets_from_joiner(cs, sec.joiner_secret, vec_hex(psk_h), gc_bytes)
      assert_eq(sec_j, sec)
      let st = @tree.SecretTree::new(cs, sec.encryption_secret, 4U)
      let (k0, n0) = st.application_key_nonce_for_generation(0U, 0U)
      assert_eq(k0.length(), cs.aead_key_len())
      assert_eq(n0.length(), cs.aead_nonce_len())
      cur_init = sec.init_secret
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let group_id = vec_hex("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
    let mut cur_init = vec_hex("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e")
    let epochs : Array[(UInt64, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, String, Int, String)] = [
      (0UL, "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818", "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f", "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00", "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509", "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b", "3e28da76edc09fb9ad59fae258839c7dc46e3c092a125499959c7413a60250b2", "b0defbdd2232224b0c0427e8efa80f011f7813291dca783433f2da1431620bbc", "418b197eafd925ebbf4bfd94d650aa83b1a11d6d02f33c2cc81631c6734f69d9", "de1df3a74bbcfc7fcc631213a20c1b1842860eab8e6f0c864dcfb541cd42cf24", "ffcc3d4a757224eaf62c124f8e7def12c0db74740cf494c9f56fa7dd07214947", "27518b380b39834affecb08780ee9709627859d5f6f37994e8783791004485cb", "f68f6735aeeb97331d674ef4f580e11352beff543b3b6688a01a1bab97d42f26", "46f51f54ce4c3457ee5681925b9d1a282de166f04e28a4a316404bd14dda3138", "e8bdff522e2675c7e0582321fbeb7e61763b1f88e7ded3c57ea78c691e1d0b93", "6839abba79aaeb82385397612fb90cbea3bf8d427806cb3f0bfe5793c1a42fc9", "244b05004ced1a7d1dc3da6a7541e9b180b6ffe41cc6e24d63c5c9c0742b4870", "8206ea1eb4d8d5730a2737f7470718b9d00c2276d24a98ac4e6d7ef52cba0631", "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4", "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785", 32, "623c858acd2728c5b860a77ae0cde77fa8aef14e9ac124464cab06bbc3cf3635"),
      (1UL, "826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5d", "14a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e", "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000120826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5d2014a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e00", "7b3027aa5d2224aab7e2a18660bbf57930e2e21d95e02b849c704d970e3e28c5", "ca7a68f2a8a52147d70f1eb7195de968d2e182b93596bc5a61393861e91180e4", "f589c7bc9de6fac35e546bbf4ac89632980158e40336cdf89165b526a482f228", "f577c28c938b9f57224e5f208ee8a64f65a4fb734bf8f74f44f0020f55e22a20", "6947180097f92f021d5d0739568d9e41647ebe26d754f679f0a883013165b6c9", "c6b20eeb67246447456fe4d4dd9ee8e6e88e710cf766f862440e9a7b4789be81", "bd364a14dbe3e9d14f6573d2df1ee014cb0bfcadd948f257d35091fba8735d3a", "eac27705796cb8ff5867d5883f111f8a9990de3e69befc5d69bf2d02f539b863", "acd66baee8206cca6b60a71c9db4f1ae97718db857e267c352d495f29ff0776b", "e7b78eda3dc2d13c3aee74426a6aa6e8a90fb95992be66b5eeb8cdc0b08c6f1a", "839d6621c61a40a14d30a5042aa9a530e267f825734d485ac9e415f19e35d9dd", "d835002d8367b0c81e7d0159527b12a24870dbb8efc8fb299ad16b72b2199a6c", "e2cc0c5444b77af2d15a8d5adf2ce9fd051429758ab80bd247d80f6c44982a64", "e2daac515f8378d164bf51746f4143b54d7a8d574f4ae1081b5d1d0ba88fe615", "ed66d7f1da52171ac9448f0f902edcfefa4ebbda843a43bd3d173cb7c5b4331e", "02dc18fc5bc4d9093cf41fa0053521653775b123784d40ac7d46cc5a72ef4d46", 32, "f6ae0abce67ed43e7cda3c04774278930c96bb1abfa77707cb7ac3351a9ded5f"),
      (2UL, "661ce3bd9ebec8608fa97bf5413a4588f50a8f9face225ec67a6d29c862b2516", "b5d7ec8c9d8b6a28c9467fe4918844be6acc08e98c1e10c71122e95f9a5e78c5", "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000220661ce3bd9ebec8608fa97bf5413a4588f50a8f9face225ec67a6d29c862b251620b5d7ec8c9d8b6a28c9467fe4918844be6acc08e98c1e10c71122e95f9a5e78c500", "d2825785628f1ea7404d6761f27272af5f99416ea28cc9d335df47ed2b0097d4", "599aa672406270914c60d30b7a31d2f2e217c3b5298b279b79e34c65a60e5f24", "2895d244e83e8f29025bc990bedff61ce114281e4ff22362c4ddd1646e0fd052", "58a7d5da2ab6a8cbebb89c34741c52ce3f4aab1b0ca3fe53f47c25f77de9576c", "300b71ecfff9459934b4ede696bc0ee9858aa70a89c0e934fadad97383347e4c", "498d6f93ac48b8a8d3ba1321b4baf760fe59d486be53208ad0c2f57a34ce6263", "a61b4a90c66febc563f95e7af4417e1be5e33181605b2b9f8725ea30b184928e", "fdac6dcb3929509f612106168550370afd92beeaf838bc09bad0a4db09c03b4e", "1b9bbd13d92e2b4d600af772e340c8130b5704ad81cf17766ff5649603d058b3", "072b9f6d87abb70c908e0808fb4f60e0680426d12c64d4aa8389bf6c423b6cc3", "3cdd1841fe689fad3c4afca9d78e20506cbc377c34e67245721448d944e63ace", "08caa1215ef79aab5fb229c286b82c2a5702932aeb68190496b18cf537c86e5c", "887ca27b1d9f00bb88d60a6ecb86df34bf500bf0f755e7d02b6fd14457fff9d9", "c32e86b676cdcf9daf07823faad7bf0d650ea5b1593bf816573236a0bc744571", "06f549e9bf966d7b7135b6ef6d4e3032a1c720adf0281c3ef1c0beac0da88621", "b0fa7e3f0f2199278a55267d551d43946bbfc6d847632867dd86abd1217982a5", 32, "58560324e8b45296b31c44f250df77194b977cd4f9b1c0fd55b15cd260a3d582"),
      (3UL, "08225ed7f3b0b8aa9f03b24395ed8ee7002d38209fddd7d941dd8ac629ac8a62", "dab8c2f8ec97a0e5a137c55a5b9ac1ccdf5ae8329810e98e0bc3930aae0b4be1", "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e00000000000000032008225ed7f3b0b8aa9f03b24395ed8ee7002d38209fddd7d941dd8ac629ac8a6220dab8c2f8ec97a0e5a137c55a5b9ac1ccdf5ae8329810e98e0bc3930aae0b4be100", "f652baa9151c9719ecb2716240a2a5ed9aeede1df19de0de862ded166a724783", "4106e07ffe8f0bfdbfd317d92e37a1fc6c4d1fba53ee054b7acf8587013d533b", "02a17a6d0995432062b8825fa071fabefb0aecadbe9864d229e82ea73abaf71d", "c935f0face4e94e6f7e886a9df715bfcdcdc3d3a546601fc4ffa7f46b10904f6", "561d5fe3f86642d8b9782d6227bb4b0dae805e6930432ed1b45334e14ff5225a", "785fd9a3bbe87178b2b26aa494851d0528a1f39430c1b787c4d48ccacb1012ce", "72842779a3f83949693f20efb2a64c60a43a8e5b12981d92b43660508869d9d9", "db2749738091f49e479a570001f2daa7dc4aeeca2e1cfbb60f7d983b3dfd427c", "5c811e1b167d6ccbbd1ddafe4df66f833e418cadd562e23e6ff7d8c8103f8ca3", "75edc2d917753b5238d08a8549150672d8730731fddcd1aac9ac4dcdffab1fe6", "b531f478b39a21ff975491f292bd971764b1c99ec5bec5ba5e12f2922fa13c9d", "d68c57291ad3a57f20ace9386e52187581a3de9820938bd0424696287df64622", "89b4a85bf900b6ba890a89eae531bb58c5b3b48f406918846a2d7195088edf04", "1e8f03db3e2f5d6fa885455904f726f426354a441c5317a271417360ef7b9d2e", "b76193af29eadc6e16c66493e2a4ef8219aad79986b6d4911493741ec1e666cc", "941db06073e76050679d33cf1f0ec33de3e5a2cd00cb738b54c0dd90de251cdd", 32, "4e2dd79d84c728b7503cee9acbe1e057523d0ff973d81e011905b5b581d2adb3"),
      (4UL, "918e07d9bfd965f880f860830b24427d9200fcac485e973b4943e67d322c1682", "5e88437e7e8e91582bc440a375e93280417c94c5e38db8537963dd3750dd3e16", "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000420918e07d9bfd965f880f860830b24427d9200fcac485e973b4943e67d322c1682205e88437e7e8e91582bc440a375e93280417c94c5e38db8537963dd3750dd3e1600", "50fb68cdd31ff76b8d86b88b80124534d845cf2a835411b002b40b7b08d28278", "c7e0f52b886962b1edde9e75b9ecafa0d8efeffb474732a3da298c470f1d1445", "e3e8700db2c43917c6e36dae28732b21c285f9af371f66a5a9f5f9a70c65e1b2", "6f6494718441537ce4cea94ad29fb66d3048c711e61f7f8aefccf4f6d61fcd86", "20315bc816babd2c11b78bbcac01baa787136a26baf80adc0753d163c9b09d89", "1535616e267425ab17e48a8607d9edc196601579303592885db62c71efbbdcbf", "7e893a0ef9b0b4b1708213996b2ae8c8382a50fbce6caa4496e07093c36de351", "7cd91ce426cada365fc15f9fb060c360ad81bc350096b404bc3d66a7d64a00cc", "d59f86014e0c306be049bd9f2dbae06a3d225486e74042dba30238e4d72ab89e", "b3f67ce4547ae1e886e2275aa3760146d55cc9a1746bd36b0291c127368c7c38", "9a34f258b8c3a3733d734a3c84ebf3683f34fa67760eeabf1e9a9b329a733d56", "3dadf8dbb09c5c1e25c565dc7cffc494055e517b0129e0bc83fcbb7280e9ae7f", "e914d45c8c1b06670b926ae56a7908c93d2721cc562f82778044e9888dc9e2d1", "8236c9f14f1d5bc27635be4da2795b5367660879f5afe3951b7f1eb7b69fd769", "cc9c4b25b0bd69250b6e4f9908d1b170bf62fe8cc11ad36d33e602324ac0662a", "a0f762fc82d5e421d8fdf8a317b2fd463008c625bf19db7fbfa4ac778b5106a2", 32, "b07890e33ce8c281d07c7228c186c48f882a70967f30958a1cc0d9d3f547d551"),
    ]
    for i = 0; i < epochs.length(); i = i + 1 {
      let (ep_num, th_h, cth_h, gc_h, cs_h, psk_h, js_h, ws_h, is_h, sds_h, es_h, exs_h, ea_h, ext_h, ck_h, mk_h, rpsk_h, ext_pub_h, exp_lbl, exp_ctx_h, exp_len, exp_out_h) = epochs[i]
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch: ep_num,
        tree_hash: vec_hex(th_h),
        confirmed_transcript_hash: vec_hex(cth_h),
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      assert_eq(gc_bytes, vec_hex(gc_h))
      let sec = @schedule.derive_epoch_secrets(cs, cur_init, vec_hex(cs_h), vec_hex(psk_h), gc_bytes)
      assert_eq(sec.joiner_secret, vec_hex(js_h))
      assert_eq(sec.welcome_secret, vec_hex(ws_h))
      assert_eq(sec.init_secret, vec_hex(is_h))
      assert_eq(sec.sender_data_secret, vec_hex(sds_h))
      assert_eq(sec.encryption_secret, vec_hex(es_h))
      assert_eq(sec.exporter_secret, vec_hex(exs_h))
      assert_eq(sec.epoch_authenticator, vec_hex(ea_h))
      assert_eq(sec.external_secret, vec_hex(ext_h))
      assert_eq(sec.confirmation_key, vec_hex(ck_h))
      assert_eq(sec.membership_key, vec_hex(mk_h))
      assert_eq(sec.resumption_psk, vec_hex(rpsk_h))
      assert_eq(sec.external_pub, vec_hex(ext_pub_h))
      let exp_val = @schedule.mls_exporter(cs, sec.exporter_secret, exp_lbl, vec_hex(exp_ctx_h), exp_len)
      assert_eq(exp_val, vec_hex(exp_out_h))
      let sec_j = @schedule.derive_epoch_secrets_from_joiner(cs, sec.joiner_secret, vec_hex(psk_h), gc_bytes)
      assert_eq(sec_j, sec)
      let st = @tree.SecretTree::new(cs, sec.encryption_secret, 4U)
      let (k0, n0) = st.application_key_nonce_for_generation(0U, 0U)
      assert_eq(k0.length(), cs.aead_key_len())
      assert_eq(n0.length(), cs.aead_nonce_len())
      cur_init = sec.init_secret
    }
  }
}

///|
test "IETF secret-tree.json CS1 & CS3 all 6 vectors (1/8/32 leaves) + schedule sender_data bridge" {
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let sds = vec_hex("95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573")
    let ct = vec_hex("156f2eb3fa482cff20e3a090c267ce6481d4a0976aee2adb921d70ae8a04a6494339462ac049f185e7184d8245270e54e68b72bd5df66800367c50e423cafec0260ac4dc743c24cabfc6060fc5")
    let exp_sd_k = vec_hex("92667d9c889a6b768c157538c0a79fed")
    let exp_sd_n = vec_hex("362785b1cc8bc775fcc216e7")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab"), 1U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "a2d6b8a9255478e9b79a076872ae3563", "8e8fc08a4eb5189b7b558527", "442e691710646617a21e41482d868a4e", "c76e37884536a9ce33fb3070"),
      (0U, 15U, "6121c93d8e92e76320087e5d646a3bf2", "961e5b73d62b72743b900c88", "0f2d1b9e1d5c09abefb0edabd8349e9f", "a08d3a0243b6216cc92671ec"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let sds = vec_hex("c1d2716789d55bd41e85316b455b7da70433898816e62b15216368d713d1d4fb")
    let ct = vec_hex("c32247575cc61ec993efcb78704012929d0569283f7ab1f85f048791f1170e2639cacf787be9a58e31a3a21f3f12523d32f8089eeaa0756f69a1488a4e87356ab50b700bf2222ff8b0b258f22d")
    let exp_sd_k = vec_hex("ce20a37761e1152c56e0a6743aaeb520")
    let exp_sd_n = vec_hex("70f55f0f05fdd2d7459a50bc")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("9d4ecb550dc4fbcbaae66d120a2215cbeca20d45d66791df5b4349eace30fd3f"), 8U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "199d6d2b8810a8f6e81e80e49e6a29ce", "18f6c449223678070da1a24b", "dd3fbd3f880af22368f4232e7518d93b", "969933769978098b3eb6324a"),
      (0U, 15U, "e6c01a531c31e31faa37eaa6ec405cbd", "579ee05a5d60db32f9c8aef0", "3eddbdfcea44bf06aab8145c90e4e699", "4a12f22d9328a723cec85b8c"),
      (1U, 0U, "3ba4098e67e27b848add03b50787a469", "77a7bc800797e68deb99b455", "a7114a7437fcfc7366d0757ebfe197ac", "ebec678992aa507a8110e024"),
      (1U, 15U, "c9628ce8a46f656f771a23a17c1bd910", "a6aa633b2d2bfd3e236d34b4", "c26726299ba30ef1c63257d4237e9485", "39faaaef13f59f8239795db0"),
      (2U, 0U, "75232364cf70f1c85eec1d36781aead1", "433be05a051b3ffc379978e1", "7c4e45ee27c0a54b258d305b4142f184", "884893a47ca825277657f930"),
      (2U, 15U, "aa1ddde2d4d554345dae6408a1a2d3c7", "4a0b38edabea511ff426bdac", "0e2ca072b7ed7857648768eab436c946", "d07d781202aee086795fb367"),
      (3U, 0U, "37bdb128c0ea29a04137c820661a38d4", "0ecb584481c3790dc4f1ad2f", "95378beae4bc6b75e117e54153540f73", "e2c2eef354f4c8721a92310a"),
      (3U, 15U, "bb14adbf47b685521aede7ec58c08a32", "15e43e424202aa29ab7f1d65", "fd92f2214b1e1db1c27c07eb6345acd4", "afbfc19ed33f8fd702cf09cc"),
      (4U, 0U, "0971784c1c8c69cd458ea7fd57a43dc3", "631844f53290807e6c498c51", "b961b5a5f95a23c184dfc9f15f30f685", "4757753807e632c175b0eb5b"),
      (4U, 15U, "f0af40200372af1d8bab6c3affa98407", "236f56e83c3694b8e87548bd", "f2faa1d398e50f480ad5728dcf593cb7", "82d73299b49f795a773b3ba6"),
      (5U, 0U, "579d500a6e78803ffd6187c1e4a3448d", "8bdceebc9e6f8838c93ebe06", "87dd6efd2ac7e13e0e477a72cfea0c85", "c3f031d03cd30def2b14ac8d"),
      (5U, 15U, "9a494c83e2d9dfab6008d8df9ba63aab", "95edab0a7777e09c30514561", "66992f2f134e10095469e656dd7117e0", "a5efd9b2edf31ce95eab1e18"),
      (6U, 0U, "402fbfd02e8156706b60e50c87dbe128", "7e6c65f08a34e70c7db0ed5a", "af900eee2d95aeb65bd2cb54a99615ea", "239fac22f69377e0fd75e1bf"),
      (6U, 15U, "d82109a3968088cbcc6a6bd977019767", "6d4f9ba103e6591747d74d25", "81f4c511da8a36971bcfa288d42070f8", "ac33d3833b76a1ff5827f8e9"),
      (7U, 0U, "e13891d83b76131ca2bd86dca69514c0", "b4e72b31cc0e2fe85fb645ed", "a5c06098e8f8fac7156d4be34299db2d", "6b7fd4094473892fd5e9cfa5"),
      (7U, 15U, "034a340c0511b2e7884a221d99f4e5c4", "45ead0267ed84a5d88553c3b", "d82803947511bab6cff6549f4d377ab4", "fb687de03bdbbc6221009fd7"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let sds = vec_hex("19f0c3a677af19e7ff785e4d132ca5ab344ea1836ea35a7670e5e9d3c1e8b79a")
    let ct = vec_hex("6194b140888cd594e6cb67b1c04af09766e171df0a53bd304c07b2979dfc760a15421f02409ea53fdb3658cb6e4132eebb99c6a579779b6e15129b34d92d71887b4c39c9be0c7404ee80d3b7d4")
    let exp_sd_k = vec_hex("679b2c8764e7170a0d68a91372c61d97")
    let exp_sd_n = vec_hex("da8e189fab4382d696834aba")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("4b11aa4f1660dde37e4851cb5e2336709e3cdd792147cd65fc99be6cb2e53ed4"), 32U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "d14ec0ba69d2f9d6c2c558fb39f54c42", "06a7fa107d0cee4af174f5b1", "1b007d5ba2f1fe46838f47aa4cbf1129", "6d744109ba5bf02829efc6a5"),
      (0U, 15U, "9677255c3ff2ba87b7ad62b94c9f9fb6", "d8b3cf5f053f9a053e72218e", "6951a5f30d2e6d32a788691a1884cc8a", "a43641cc5a8a4e1651501bf1"),
      (1U, 0U, "1f32e3ef74cc21e537072c9122d60155", "f6efbe393eb614949625ea35", "367af56897ff8e84e2802fad357a42df", "4b633ad7f526fbba54b3efcb"),
      (1U, 15U, "1b45cf1dce80cd94a8d195cf037ed47c", "e8ae89e8aa649a7f607f9c7e", "ed40f75e536421fa00d269313932cf08", "25268aee34a45c90ea45cb4a"),
      (2U, 0U, "908d5f56cb172524f37aab84558ad40a", "f350902335544a2587d78a13", "06568785b2e70604e563e47897bfd220", "604f5ba2893c1cc390968bc7"),
      (2U, 15U, "e7b47f95fd15e2ec075252a31691b3e9", "84ac18e28ccec5c15385fef6", "11eb30c8358d7c29d77d3de9190f0e5f", "621c16fffcd13114db14e2f9"),
      (3U, 0U, "1066a77bf72a71b2d546b82b8fc21ffb", "e6576f6ce7a9c816ceed34a6", "0b7c791b6eff7322b800ab580820be76", "583e763af33ae247948d4a5f"),
      (3U, 15U, "659f54f8c0fb891b0ac245bdf3ad3029", "f6f71202f813863c3941c77c", "e277683f6b90baf9761bb1bbabb7797d", "3211e571701247946ab63527"),
      (4U, 0U, "8d9af2a829fa35f8eb0ad02f948f11cb", "b0c4f56650ddab2e9b32e376", "4401f29e16eca8b9b1fcbe3d57dfe675", "dd5e8a0cecde3169210503c5"),
      (4U, 15U, "2f6d8d2ff11134d34804acb6ad9e93e4", "b9d5458ab3ae191f977cdc00", "b600f1d641df2e74833137e75a9005dd", "5bda40f8200758d6553d4d86"),
      (5U, 0U, "5996e9e132f664553b668487ec60ac2f", "e9476814e66302e621f048cb", "c3732f712402d71b04be7498a51adb09", "1796b95fa4850cd952cefefe"),
      (5U, 15U, "f8ad32a76fe00456867567d30c0869d2", "c92de54e4fff77973e607e9c", "4cf335ebccbf3e222b4148d111a58614", "e1b1e82853e3621c6d595771"),
      (6U, 0U, "b1c2b0da7ae963478cd5d1ba9b49e401", "b92b88178447417b5aa27e66", "1ba25a1dae8e5ab05c4b2cbd00dcbb72", "ab7a3eac4b08982bd0de570f"),
      (6U, 15U, "c92b65c9ba613f60bf660d638876756d", "fec19b63363ce518711cf266", "07757af6d992d8cc5bc0db07753820b0", "8ea2133a7fabcebf53f95b37"),
      (7U, 0U, "654c3513dcf2f5b53c89f41be267b5dd", "46454b13c4026b20d49d2f04", "5d30f2a3dbdc42260b724dc1152d9bb8", "c4bed63baf7a514674f726a1"),
      (7U, 15U, "f95f4c588a61efa509a3d08c1826fecd", "3202a493fb78c7a2618de7d7", "de87e9aa9a40b77a6957c12808a013e0", "34ee9c751b15a83bce9da172"),
      (8U, 0U, "31f10146c3433ff22261a4c284bf538c", "7693c37375b4e4387e8ecb29", "35769652a9a8be4e5de63b3596f912d6", "252f5d646a8bc1fc75d49ae5"),
      (8U, 15U, "6d2f0790cf376703caae36be4ff7465d", "acd2660bfc3e17d01ac4c6ad", "2fb3fbc08fa67a32be5d3cb2f2488ea0", "a2d376a419d15e1d6b0f04ce"),
      (9U, 0U, "7bf9c4b206bfcddd04cd849df5c3271f", "1cdec53e31beaac188c85e1b", "9de33053917fbcf2af02f377eb33d6eb", "00c40647d2571c790de5e119"),
      (9U, 15U, "fedabb05f5362ff2f82aef2a66a77492", "70e066747a8a28bc7325add2", "008d21f22deeda47dd8b60acf3249ac3", "d6ffd8a2cbe4e0706ab4ea7a"),
      (10U, 0U, "ae48c504337ad62b84ef47c425bcb4a1", "1b487aead70b506939edc6e1", "0e521a7662b79bd44c6e19fc0e9f0ea8", "2d4e81e8670c512d3be9ad88"),
      (10U, 15U, "20f3cc33e664efdc6dc30a40bec3403e", "4cc3487d18655cc6a58e56ae", "c126552f6fb4084920f9b3f158932f72", "9b43fa6d11328578ef378223"),
      (11U, 0U, "83ef9bcfd91cf032e6df6124b5ba503f", "f3e3189b9a8efd0c9498e77f", "3006e1ab88e681ec164af3cef6ce88b9", "09af81e1d6b6ed0d905f5b47"),
      (11U, 15U, "0b73104e026459ad6be345d522133192", "a793dbc1c7f13d43d46f52b5", "a21f29059562f331c6f6549618593eb3", "3e915b9944fcc10d9c14cb41"),
      (12U, 0U, "e9dc193999ebe35dd2a87ba0b68bd794", "837b386aa08df35082d35e7a", "843dd3aded2f340d5ee5f9bd8f997097", "8ba2133dea8c6a2db34b3f4a"),
      (12U, 15U, "09e1c7045b2f500f6079d85c5afe1ebb", "02a9944ef4f8f9e3da963174", "26df53eb9680cf5018174031c50dde1c", "59e02851c73011fe2c0d5113"),
      (13U, 0U, "eba4668d5ea7f62528f74b2b319ffef9", "aba941a4a893c821005daf83", "385e0abe84d5e40c90c7371794744a94", "3e6fe39e04dde980ff63fed5"),
      (13U, 15U, "131aa5c77c267e1b22fa4f7652d6cf84", "10d19f524a4ed7a139d8acdc", "e928390209435ce550b89f154719c6c5", "03038d4eb6b2a07ab6471836"),
      (14U, 0U, "6e4b7e023b60ab01845dbccd9536b666", "d1356b7693d3379d005d58f1", "897c90c3b516f3ecac8c75435c65dfc8", "fa7e927c16bb1bfaa563e087"),
      (14U, 15U, "fc3746a21efa6756ae619e04fa26aa0e", "edf5b75f54aef6db3946024c", "bb98da592d0adfdad31786f036218725", "be05e2b4a78dba85398ef32e"),
      (15U, 0U, "ea64a4706a25e70e069c2bda32dc4f19", "a46654c07e18b1b4f79d353d", "b924fc1778ca7784fdba21dad73f0f6f", "083e96725b404b79323f4b2d"),
      (15U, 15U, "21b31782596a6e12ceb4bd796f187da2", "aa5ac38aa27f7959d8f187cd", "a9a13053745632bd695c11d2bee642b4", "a75627b255398bd4d6f2994b"),
      (16U, 0U, "8e063fa6311b287fbeb7cdf7cc3b0d6e", "12313471f4598bee96bf05ef", "2564f4e73eae8185dde0fabfef009bed", "5b68c36a65b0701cd97f5059"),
      (16U, 15U, "00ac5bfd57d3005c4c87f58c5c70364f", "c422b0056eff1c83a7a37193", "82c167d9f7369c688a80b0313f473c73", "ec8942ed93bd910a8716c34e"),
      (17U, 0U, "f73a70f6f809d36bfa8d810aae72d75a", "59bb7590ac0ff65f1652d9ff", "57fee1ed861667fe84689ff8898758cd", "6766766669720f5ba2f76f8e"),
      (17U, 15U, "31c2ca36c94dff35470587b239c6e9a7", "a88821a972f154a9f778f810", "873b4e0f9c309dddcab08d001b30a222", "1bafdb6d7328268cf551b91b"),
      (18U, 0U, "9a2091ff4799a72cf33751e56368d7ec", "9a3edcf4b4118d0e4c062c23", "8cfa058230570393e81e9155d6bd6bf7", "04d248b54237fb89f137434f"),
      (18U, 15U, "7f3901480be23699f87a6422f64d2c88", "ada240ab742c10931e5238c6", "bc97687744346832ef66b670852404c6", "ea8f21975e91d5f95785e474"),
      (19U, 0U, "dd433447c7d99658d388fab2c92eb5c4", "99237624b6a3d06a11a21643", "123da5defe150647e397e36b24491936", "cbc12c44510777fe02fefb40"),
      (19U, 15U, "71517455d93ed2a617ced51fef9ef01e", "dfb3d1174bc5d01c29bef551", "7a801caa4b28e6556e4a1810890efa54", "33fc23a2168739e36774c03e"),
      (20U, 0U, "003ec0b06273d9c596304565bd917193", "4fc83789d6f3cd6e44ecbb34", "416c377903f855637f96ec448af9a907", "8afe7c0dfca58b92af266e0e"),
      (20U, 15U, "8aa3b67cc6d4d7871bb5f0b373889866", "a54eb7ae18d56914b1d86695", "1401fb17f2100c18226ded5bf26067cb", "2314b2dd850bf350e3e2c28f"),
      (21U, 0U, "0300b5842fbfa463929e7616deb18a3d", "dc6f8d3dc04a7db7f02998cc", "1f6ca52185d3b3ac33bb38b05c9b7e37", "4f54e2d31f8f5603ea18c1f8"),
      (21U, 15U, "503c540925307d812e2d395d89b5f438", "26543203e104439228869c51", "ee115ab48d7478a296e7cdafe99aead6", "f5473402ea304af8f2e339db"),
      (22U, 0U, "38f6209f1df53ecd653af892b4f463a2", "d9d0185006093c4d035666c3", "6f8a0789848328da7e8b9d15cdb8b161", "9964c01626a1ebb9834fcca8"),
      (22U, 15U, "9b12f2cd18b8f6061edbc6323d6652a5", "87bed8c51d66e7f8a7a95aea", "7f0244f8237eb29959c9ae08255d6ead", "667bc5ea6a5c3f1e77deda07"),
      (23U, 0U, "afe7bd3375352c4536749012db962c7f", "a4a8094628a73e7798a9aeb5", "88a19b037eab3b136a9cad41f82bf77f", "ec5be30181abd4f5a395d66c"),
      (23U, 15U, "0802c1c8dbb782ae45ac01f8bf9599b6", "c59f08009f7482676ab82a35", "efb18132e919cab8b0cc386b4e1b9a2a", "c34b5df7f6ea42b793f2ee97"),
      (24U, 0U, "a91059ce8a07597744fb0986071621b6", "0085a2b035201fc4cefe94fe", "e39d2267c4d8390114925a3497cecd79", "f56204ce092a313c8d95c4b6"),
      (24U, 15U, "96c6a8ab141b9786299a2c7ee6513f3e", "0975b829647a8c5f6965f764", "a200b37ae4da61b63bf798fa3e8215d1", "eb8cefb0d71d0e3998b1a547"),
      (25U, 0U, "59709c3a0474e34aed7bad204a09559b", "2dd7da3659b76939bdf4a67e", "d80aaa0ce79a9830aebdddb642929743", "d3bdfa587c42a1f51ea9070e"),
      (25U, 15U, "e3e136a0843dbf0410384d84a28c13f4", "7f10e7924e97f4e1ea1daad4", "f931107b2bfb93721ff3aa6311bbb721", "a0c956bf9ecf60fe920c8dfa"),
      (26U, 0U, "b416ff49b7eb442040ca945d5562082b", "7a19aafc6e92c92561d13193", "836b5570c8e545327c54d8c8702c5619", "18d57e3246cf40aa542e2929"),
      (26U, 15U, "824fea25452276d7a7dcd188424cde1e", "9051905fdcced49d7ea9dbed", "6478a29e35244be834daf159aea7900b", "f9238731d30b20779e3aea1e"),
      (27U, 0U, "4fb3f52b78c4138e2a563c75eb1591ab", "1b8679e70d992c43523220da", "a68e003280585214c7d5054b1906fb9a", "5efae23c9e08a11cfdc1d474"),
      (27U, 15U, "1bcf23da3114ed3478d3cf4b6cca4379", "e0e818626eb306b069015535", "16cae08934ef65bfb9680cc85c022374", "f99e0ce710ddc17925f87bbc"),
      (28U, 0U, "a694e09a6e452504e2d8758cc62ad1c2", "b8fde945f6c27733f690cfe0", "b285b20eee6dc2841fe102a77597a0f8", "d4cf984d7e681bcc8741bc00"),
      (28U, 15U, "7e124eee2b8a8d08ce7b6fd7e35434ce", "9a322fb06f1a71d7f7e3eac3", "d25a9714d9722d67e8644baf3510e3c4", "9a0920f31b82096727dfa4b8"),
      (29U, 0U, "ccf2c08c3867285dfd6ef72d86dadb2b", "e030c2bc82975105dff93c14", "16b5209eec3e06f1d41da98a80ebc473", "23bb6b9f87cba13952a8d207"),
      (29U, 15U, "c449ee7cf3ed9db117ed6b0e55c12a00", "d844e2cdd97a5b93a547baae", "d62d38b59833d0082e2a36c87ec52765", "9857b4aa1017ab308301f914"),
      (30U, 0U, "203361871a0b031f7cfa98052996e11c", "af9bcd243db9c4722964f9e3", "a355b731eb98c4dda9d592c7e9f8ca8b", "e8f638ba8c0b4a997514283b"),
      (30U, 15U, "8ed88ad385e78fa9925fa376ffa509f4", "9b7ebfd0ea67dd7a097de05a", "32076c347049609f652cb47edf4a0a0e", "68759a4ffb03a00941e40f73"),
      (31U, 0U, "4f4239ba4c0a5cf5e0d329f105dbb615", "acdb956c6d300b38036cdf47", "f7b8f6506d49b3522fccabca19616801", "5af92f7ea5c258e154230439"),
      (31U, 15U, "a988bb75b0d95c2d059fc6e750fc5098", "689b51728d4702dc2037f0a9", "1f843d1bd0fdf3f956b8fa4dd5246a5b", "063c5d83171615c2986fc27d"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let sds = vec_hex("d61204c27f29de53d30ff54a6ebb53e9908d044f55b9e726fa5736d4246b7b36")
    let ct = vec_hex("d0f75d5b691dbff35cafe226adad83aa5076c85035fef7d7fac489ad63f10828266b44ea366961509e8c9c24474abb6066c5a350aeb2b05415facb7ac2aa1b1efcf75a0c700bfdc93c705e352c")
    let exp_sd_k = vec_hex("674a0c3e1500d068aae5d50f57a14648a63de2c246f8178382a150df8031f4cf")
    let exp_sd_n = vec_hex("56b73cca00eac6cc5080be8d")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("59227ed552e4a6db0779d43aea694fd1b2c2540e605a099b95cf852b41e8ea66"), 1U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "2ef3c21ad150b59cc78b21bd96e5dc0bd2579e19c7a46b7581fb1969103389d2", "5794013a45e0563de4d35ce0", "3f57aae38cbe6eaf31e4c05bd4a6aeba50c6878fa6fc2443bb8f3e57870fe712", "4b2599c99b38c18775c85008"),
      (0U, 15U, "488400e9d1a4a1d48e94da89dbc6c306d6479004e26aaade4101dd2fd86f2c21", "424c2809d87242ecbb1da91f", "bd44b39e16d4d59750469719cd330e4a52ecf5a1c9060254fac3e8ef73f4cf9b", "82f8881240b93d1611b34e8c"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let sds = vec_hex("3c61a6ebf1f32a9f20dc375039459ba7afa95600ee0736bd91fbd7cd6f0f324e")
    let ct = vec_hex("e80d2f8e7283ce19fc07afe30277b9b5f5684fa8b3b858d51b3bc04e3d0cca2bec15d67d58063206b4df0b88a8a31e8bdfc1e4a1aacdf7d0b2df2cfb43fc85c9d53da8c05a3ced7c056e6f147f")
    let exp_sd_k = vec_hex("989649a440be9cffdc2d4afeef55e15b667d2f0b145c406a5aae11405f4cc6d3")
    let exp_sd_n = vec_hex("b111bc5303860211b9d1b95d")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("d57a3e97f5db1387fd29e6111fd12cd15f55082164438e983f588e490d4be3c9"), 8U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "55c0916e2c0d115e3ab35c70b2f16ded3051c79399fcffc2859e699f938e75c9", "1d96560be0297c2a7df1988d", "79032092cdead1eb02385b174abec5722b474486c299636cf3c18b0cafa49267", "ef49061a0037b0f1eb6cfdb1"),
      (0U, 15U, "f0037a7de2797df1ff036009dc6750d8cc7901c434d19561c42b8e9adc83acf0", "c3b1dab20c6d1cf996c22471", "d3660e4b2e2014fb6eba6db191cb41912bdbf75f48dc1cbc284a8dd26d05715b", "eb69d4f656abaffa736363cc"),
      (1U, 0U, "2da73ee4f45f6993330be8bd345d55e2e20e0676fddc1cfe4905ffc96e12e850", "da15885d28be5a9992acbdda", "f3a3e0bc8954deb8888974325a604347c8a37cac40a0ff973ba6c269d8c300ee", "dfdf7c21ece020b34591c7e6"),
      (1U, 15U, "1b3b385763a2192c4f5166376719c78e7b32cc218d5ed83194d90e97f90865de", "2af2483f73b8da6a5d59dfd3", "5f0ee220bbd25c3333c1d03fced661972e00249503d47a43e6023f6f77c69f6d", "ec3b8f23a06e5949e2561ae4"),
      (2U, 0U, "32fd4ccd71b9495e7faae476bc6030de01ab18d7468c360d3fc3b63dc90012a8", "ebcd40f83950051a4a46270c", "50702c3e200b9292b7c26b5f906ce9abf57044767523f06bb40eea5ab56403a3", "2027bed41530e08aa53f6fb3"),
      (2U, 15U, "0b5e1e68ae79e61b53f629ba9515e564f829cc06c544283940344bcb86aec193", "b8c72c1921a44dfdc85710bb", "e68fb3a6802a0723db3438f477c48a902458b1c0490838f2eda0fbd8b7b195fa", "ee63416b0de9f578a8097a42"),
      (3U, 0U, "71918cd048f1e1a69429bed587c9828223634a4e35f019a9a640265841803593", "a082534ae9126a732050acf7", "a598c5fed9cb918b29d000403e7c5bfae6119cacf0ec5ea17084b4ef4607f380", "25e1db42bbf3f6faa70ce0a6"),
      (3U, 15U, "3b65ca68be982ced788ead218df556acd5fb7be76589f2cdc06bd5ca76f84e24", "d06444a6079a25b6363e1e2e", "2d68bf10fcb74f21e98cb537bb51e49bfad9633c8f158e8295c80a20bba5f564", "4000c00939f8e48a8626c94f"),
      (4U, 0U, "dc32974d57f431297470cc8af57533d113e9db7b52fd850f6af2f61940ff2473", "a4c9cc6b474e902de86ba656", "dcef1450bf62d0b2204b8e517824d03c21e7e13049854cdc3600becf356de422", "cb474c0a5c28821f0c567b0d"),
      (4U, 15U, "3212a4167a024bdb4d72dbfe1c02984698e70a0dcb215165c8a576fa88ef3c0b", "8bc3825e05162cc3220bf787", "389c94af36aa817a380fd4fdda932385579ba9f2d3a72349fe704efd2901396e", "a047a51fd99c36e1aaa86695"),
      (5U, 0U, "0a6538d0472fbdd15c912bf67b84de562c9d27afd44a69cb5d28026bb6e93851", "59376149e274000b31ffff72", "5cbc6e9b705e19032afe6e22f44eaaa0b488c57cd441e37c7bb1224be1026f38", "ee50d01dd78de80239309c5d"),
      (5U, 15U, "0ae63f1aefef7deec797082de74d07020b4fc491012da9a297a7f85f8f3313d7", "138293ae1dd09af823dc600b", "5fef1992203713ffb91bc67965402b6345f691bcc4c656e4cffd0853a4ac6474", "c9862f345543c351e0b81412"),
      (6U, 0U, "52b795f243c6812f0e8921473463c76d581e15aef8602df2747bd06f6de1d592", "fb677efc646c93883452211b", "8a88a31e26cbdf93485abb16c14f552d40d15021c4a37c56e3b35b8c1cfe6c0b", "8fac76e85c7195e73d06858a"),
      (6U, 15U, "95d7c164d4f9f93aa52c830f5b578cee3fdaf1d90aaf173ccb59c56a598ed4ae", "1d59d4a38b0ad2321b2949f0", "75092d7b88678ae5f14073fea16d6328465b009f6d45b72068e55976d1e65d48", "29c9fbcbff4baeeca874a5ff"),
      (7U, 0U, "28c09a2d5275cba5e14787f61f8ba210b77e0f790bb1eea19ee6208055d5311c", "c5312900774af942a8499e4f", "39d155f1b517eb74ea4dd217faf3c8a0d5ee225c3a09a9e0260766405c1a30d1", "e7d1e967163d2eee48bbcd2f"),
      (7U, 15U, "ebb1df28bf07a18cd4a1aa216ff96d8fc61afa7b2d98cb4b37a6a3a791813e37", "73b9a10947dd9dfadb6d7995", "acf22181714e05aa45f0c9e179d0319cd4693b94c0aacfd60d33da3eee44cc64", "343807a851dc834515f0eff0"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let sds = vec_hex("09c466b58b772325fc28959b4adc2c8af8ec2e094e0d1a3d5f40dd8a6e0d59cc")
    let ct = vec_hex("aaff203bc0df0c63f4b0db2ebcec25379cac0d185753d2dc19de67dff0b5d11559789edc102488d4fd7b602871079095b78ea8799ac2d22055076424ffc9925a837cbbe859c05bc407af0946ca")
    let exp_sd_k = vec_hex("49f35b2ce57617cc7e57cc1e0d10891a6d8de533c1a732d12896a895335fcb01")
    let exp_sd_n = vec_hex("ece5b65f163e2e2df0e94f9f")
    assert_eq(@tree.derive_sender_data_key(cs, sds, ct), exp_sd_k)
    assert_eq(@tree.derive_sender_data_nonce(cs, sds, ct), exp_sd_n)
    let (sch_k, sch_n) = @schedule.derive_sender_data_key_nonce(cs, sds, ct)
    assert_eq(sch_k, exp_sd_k)
    assert_eq(sch_n, exp_sd_n)
    let st = @tree.SecretTree::new(cs, vec_hex("49859949b3e26371713cfb1f753ae543ce1b7632710242628571b798953187c6"), 32U)
    let leaf_checks : Array[(UInt, UInt, String, String, String, String)] = [
      (0U, 0U, "5102b1705ef5a1f9390bd52a1e648a480e8bc806e9380899f8ce55ae8bd713bf", "7aa4342c298b754aa3c4523c", "0a24d577a06af2fa3ab9b6d5144046267b63ce0b19dfa454bc35a4d0f52b2e69", "58f972b0bb12404226e643e5"),
      (0U, 15U, "513d91cb32642de7eac35e6ec7102483bfc37a9470b34931c0f90c1a354032a4", "c1c2b869ca47b5705b242673", "87c441cacbc46d63ef710d8f5d9dc6d7219c75af004f0672beec69ac757b94ed", "49afcd1b5644251d1559714b"),
      (1U, 0U, "2d04368cd82e130ce4a1fe5c5fdb7c793e87c6c038e0731fb2c2b1d9e81fcf5d", "a9bc5a0ad7f41f04e4f87698", "836c1e8982cd314c836ae8ad791428f653087760ba1c8ed78d7ccc5c5ce07673", "89cb851cd3eb80da3af04775"),
      (1U, 15U, "81c5b2a8e535ea5b9f47c168fe7b04ad9b61a576a3bf8742c89f1f7303d245d2", "a3f00fc9758f339947659296", "43a0dc853e4d7e3893c6bde5e34aa2001e1a4601380514f944c2c1615cfa8794", "8fca3ba94f338b88dbdc21db"),
      (2U, 0U, "cb16363a4ece4ecc568d8eefda4baa0d13f10e72cf61e940d34cddf877c7990c", "3d37209aeab33188767fa07f", "b6dfcc1b4833389bfe986779337003c15c7e392c31c6f58023647760de5acfd4", "80bffc48f52d0859b0c45e0b"),
      (2U, 15U, "060a338a48885f3699474ed88c24c60748eb2654db313b703b3dc508561ea13a", "be3600be0c4b6dc2d64df06d", "9d2031b0e6ea40222c6e4772334a0cb16b7a70e04590ee0318490d370eed6a21", "e0f61964a025620ec2a3cc22"),
      (3U, 0U, "cefdbc6e3b85e3a53783e4967a3ba5a9a1a6b8c486145936bce6b2afce014b0e", "68a9de9fdee52f149b01657d", "37dac5153a4902b794641e7897b66908ec192d90d18919e2c793a76a165491e8", "360e27a3a4a64005750c501f"),
      (3U, 15U, "5d7615bba20dc520562a302d7588ec7ff070a5e8a4f8d0e2f1bed78984c12b98", "b3cc4d3cb96e14ccadb941dd", "36de04038c0e394ab0913f7a7dc37b3a6551ebeb7ce82b095854b9dd1eab7fca", "adc247314fcae51d97992a4b"),
      (4U, 0U, "a5c7a6fce1c71b466f29b0e503e96bb92203f850286b3ff3f1bf92f821cd9e1e", "2fbd7adab80304636dbee443", "21e99db9b0556a32143eb02acbf93e5d3532a4a385e397b40781ce19fb27f045", "4ddc53e79de147f1c0b62d56"),
      (4U, 15U, "4f294af9f7f65aa7c552043b9db99f444a5a4cb7782589237126e975bf417993", "52f4aa7cc59d39d579824722", "48d959f383a77af5722a0d464f1777c205b0af41c5433459b4b0c53476f3481b", "6d849dfd50e660589f4b913b"),
      (5U, 0U, "e1d6282b67e64d6d4c7ba17215396b5c44ccec55911f303e091dcd28636a70c8", "effa5afe7ebe9ab8eca40c98", "d6aa79436fb4f0cc3e968289865d23ace504fbe69d55a7a204e58a7fc9cbf470", "2378e12cab1aa0f0758d4c49"),
      (5U, 15U, "4452bf9ac965e4b3058285d258251884a49d461f2c21f6b3525f81cfdee4fd7d", "615096dcc80673c6c6344ee3", "536b48f86ebc7dc6ea1bbf26a99e56c805b91e9a215f6be366929e65ffb3beed", "30914fe30e299c1a2aa0cb19"),
      (6U, 0U, "578e75d1ba2a9e05b887b068404c0baf4b5d2fcf4e15560c7b383c7a5833b3a2", "3373345bc67ed124c5974235", "3bda8030d665dd7ae2a509e9c8e7eb868b23a641b0cd00abb5281bdc5fbca1d0", "77d821c894eb259ff5504630"),
      (6U, 15U, "1110a03ea8909d3ebf25bd2d49ee9d1ff86b61f30531ce557982e664777a9e64", "73f11cdfd2675be09cefbf6a", "b83b50610f9aae7ba7115d04b014808f51e08ef3350a565679190489f5f76864", "26c768228f22a3c189e84774"),
      (7U, 0U, "9ef95b2adfc9d7fae9094e85a83f0d38c6748176428e1260c183ef632a7de5f5", "c5e95e061432035490718fcc", "2aa73eaa7fa9b4b0a2321ac80841e59f5763daee345673e55094cd391c397656", "49a648a61488633518a1e63e"),
      (7U, 15U, "e3ba556729a0eff06b05b2cee1de9e2e72234fe0cabb9f99ee30e988ac29c2fd", "1af51b8fb2b3c8c332fc2857", "bab2d149eeabf591918edc284b4b40f8e69bcfb2655e279dcc14604b497706dd", "e0a5161e008e874cc080748e"),
      (8U, 0U, "7c1be24e6240b358ad2f4b3c6ac7394c5d9d3778f95669bdc615a27406a21f9f", "0ab1fed43992665b209fb29a", "7d98494f3a1b0b0332b6a829eb6ce68fa8309ebad0807683235af6abcb028006", "d6cb542191f84d060a30af3a"),
      (8U, 15U, "ff79265cc9cd1bdc84dbdb45b376ac69c94aec066b61cee086b0e7d69ea0aa56", "8f78668bade3f8f7e2ad2ffa", "a42a21f9acbf8312d329d1df121473d21f47b481017d252b81f18f79ba799152", "ecd82ba6f4b2e2e9de7bb646"),
      (9U, 0U, "1ee4f9fdbf5339898bf5a333d24610abe701d0da886e9a65932d0cd9ee0f7248", "5812b568f82270a5c60b3f5d", "f9866e6c9d9541a94fd3d5c61a872cb036819760b33693909fc4c3067afb883b", "b64a5df86df749e32f623623"),
      (9U, 15U, "a8e268e0f3da0d4f64f91c1107c8a5b5c8fb0ccb7dfdb88ff50d4e5eca5ac62e", "e02d504d5c77524b3bf33395", "77b45129def7153bc547ad435f8311fd509cdbec3cce2a5ca3d6855311c8b56a", "6b0af3b1fabd8e9339b1d975"),
      (10U, 0U, "bbebc7ddecc105f337ab2ef600e80ddd7b21874a74c1866a63c2844b76217cf6", "ba43d3cfba9f4d270e8ac184", "2ad3059620a000ee5f2503765f94785c84c5cc25c742f39224ee0e2d4b395ac0", "27654be31f596fa3ec5be8bd"),
      (10U, 15U, "b7c3dd23db7b1eb7a160efbfa39ed9aceb783dc6998998f3cb8e7f8875134e46", "68fc5a37e990d6da66440f10", "a6384de54114b6e5da9df6ed5e183f4cc4073f9d1599ed1987c4079a68e889a8", "2f52e1c1f9adda1be687ee59"),
      (11U, 0U, "1f5a75c691636a498f19e691e4b845b347a439546a08c33d7b35e3debffccb47", "5ea407637ecf27faa5f9e3a6", "6bce419b8b2d4ea687b7f51511a61301b5de925547827b3155cf09a7659e9cee", "8584190731a81e3b9a9a7fce"),
      (11U, 15U, "c4b9544ebcb58d2d5a242d2329b5d8e7c2ec1ae7032fe3929c07621f26890330", "11659686215a9f10704aa473", "9fd5ea50dceb64aadd20a1b32a962f73ebce9db54b6e92a84569538bc09b5806", "72249adce1cdf3ef8a476799"),
      (12U, 0U, "68471caf1594b04a6937ccd9c8f9a844609c122556d893beec5d0e5abb1b9abb", "385566a667bd877048adc1f8", "a7b54230d99f73ef078ef9b50e31d63e6a209dbb687e2dc995fff5a08012f0b6", "4cd735cbd9e3ca2a63d07b0a"),
      (12U, 15U, "f9402caf45f66ee9e43692ea66251092756863890f3a81bba26950e95d6f62c0", "4533bf845b1c527c7e15593f", "08c12fe31dc56d47cd474e0bec58dd2f2e5d94afa9f09e08d5b1899fbc319b4c", "9e4f30439151f2267b983d24"),
      (13U, 0U, "0ead0f9dd582e03f253fd4231500f6243898b188dc5c14270651e4bd907f544a", "7777ffe6f1b631e945455d86", "bc4787428fdee2fa793cb81b0088720e4bd48434476e741f4fa49498b9c40b87", "e45d3c38e4b2f1a346ee6bb0"),
      (13U, 15U, "5b9df9f343f947e1c2d19917e5e4eb38b3230fb13037753fc70ba185699d887b", "1b66a9653db0e7e1263159e2", "ed63da82b94971fc087138fdc24d300fc04184b7fd1faa9476509247dc4360b5", "670c5d609ecdcd179024be88"),
      (14U, 0U, "a6af30003d6a0ebc1165f6a409d26bbc9e130826ec3de2d5b9efd98b90863290", "45c5bca88132b3b019497191", "1dd991c61ea8b2a15ddb997cd73d147f130282975add3edab265c80113994c4c", "252cf987be000faa9395e374"),
      (14U, 15U, "7b5c6ce8984d99f66580da728668b45e3de0123b204e1570588305ea2b23b16a", "80ff5aaeda7f3c393cf47948", "a883c2ba5bc15b6f62303d2a077195f5a41b54dcfa56cc208b730a651faf9b8e", "e1f00aec3118ef894e8ef857"),
      (15U, 0U, "74528d0685d43dcdb5f6570da71b8c0885e5d7ed1a24045e2a7a975689170990", "3761799305f9061f065404bd", "b664d4492582843ba0f571ac4e97e4203a49c1ce7643401eb97a8674e557e4b6", "3670a16a75f8c3ccf3534214"),
      (15U, 15U, "93fd884a5ef67ffea4fa9e423cb806efb132f60a888a0e398c621ac6643b9e05", "4de1d7c4144280931b77e463", "577bac50ea300acac89c821a7a72e66d6222ab61b99859533fecaf13316e968b", "59deb0f69cc9208213e01c17"),
      (16U, 0U, "a637c514b7c829cab2a9629a8ff25271243615bf4859564a612fa1c4558a4712", "4af4d19d36f35331b94b2266", "b2e26e5a1c4c6da6868f9cd065e1b0ecb44a28ebb9c2b3cb424034dfc3995317", "9eebf0915efb97b858f7b768"),
      (16U, 15U, "14370e699dd51f7b5d20e7de7902d08063b59f919617d174d62afe7087e93986", "bad0c7cc1627aa98fa92ead0", "ce8f0371058f53aa3acf4247d3e5ad4406fbc34133da172ee02f07390a24c7ef", "6f8daf39512d316ed125f780"),
      (17U, 0U, "4c01b96ba7b96dac8fa88fdeda453f6784e5223a03447191dc1588cc95ca9673", "1da27b4eda1116016cbdb387", "6d0dea98855b5c994e218ba2f0976bbf62967be1158cd59c331fbeb11a2d561c", "35f162ec922c7ea06807f8f9"),
      (17U, 15U, "641fa6c1261e6e30609adf7806fd98a0d8311cc1997da2c2996cee7a4c367dfb", "ef7478c8589fa2839b8159d7", "5ea43052a92e9c24d54023c98fc9b986ca0348dfba60bef879174e2fc694f9ae", "7eb562ee1b95d4ea6ff23ada"),
      (18U, 0U, "1f6de251bbf2b13cb520e67df4b33e24637cf31c3702782d29a6f8f839afd208", "7beec37adaa7410d847a2144", "60f42b93db6b678ca6aa1404de43e25dd91903b66fa27806b94f7b9875408848", "2c9d0dbbc1a2c81e3c443e19"),
      (18U, 15U, "63751909275974233fefcf4176e3aabdb634a9b4a362fa06e840f27754349ef1", "6bc125402f08559ce072eb7d", "80b4c8c0e00c3ad0508b9e96edcfb3a892872ccdec48095b546997c55d26ce4f", "f3e486464fafed0ca31cd440"),
      (19U, 0U, "1daf5540dab095fd914501033872bf7c86274db51fa0acbef6a9ac4ffb550244", "9d98bfe879c91a3055ef0e83", "552aabba30e419de851fb2c6c4e3eb7c43a5bfe12d846b9ac7f53fa1d4f01090", "99842f50b3484f21124680da"),
      (19U, 15U, "f51a272bee65bf5e5021f8d244c294bcfe22ebd9fcef68d6503ac28d2067a515", "33b2c5f398482892898dda32", "58ad351fd3f97c9cd1f6d2db7e90bc22db89a4e1a5bdea4ca595b1b51b3b4af9", "0d066d818b4bfd670c37fa2f"),
      (20U, 0U, "235ca988cd3fa54a987e8c6696150b8e10f32cd54bf0920961d3fcfea0bb1750", "56b0c544d20aba38b39fb3ab", "b9f48c4910c280fb5a5caa59d6ccae2d13fb699a70eeaf5dfdedaa591d7ae60b", "fc1c013946ce4e2f718a8194"),
      (20U, 15U, "cc308ee4cefa2403a172210a7f452f08c5811bf62743c857e997766d4856d781", "7a654742529da576490049b0", "9513d72e097d59945ef55fdeebcf78e2fa764a7005c2142f3ff60202732f72f7", "8830961dd3996ecea1fc04e4"),
      (21U, 0U, "6eef12f40735cf41e3ed956616ffed807bc17eb0d1a3a4ddb4d8a2c191ad7227", "c335f7d3b01689f54dd0de73", "00ee6bff7a38d1af3f02fc33427dce21df57be6431e3d3debf9403f4061b1677", "18931c5c8ed5968ac7e34b16"),
      (21U, 15U, "c5cd9f2c0fc5556eb1b72cd5347e3bd2b3f32e1573e52d99327b593d026bb935", "83822100c66ab081058c4e98", "e5c864190765a8c4bf618fabdcbaf17082903bf16f1ba1f43202c581056b0680", "58cf28bbc5913c5425ecc6f3"),
      (22U, 0U, "c0e2b786481eb9216d26cb84c8ae65fa631512b30a28320350eb80fc3190a3a6", "7b5b181ed1c2bb1d486ab0c7", "bd1b0e751ad168d77167373c9f35d03ebcb2d6ac61c8bf8080967955d5f130c6", "69402b8abf6d591b94b2b789"),
      (22U, 15U, "01bd4236b9a221a77ccb2c0acab295db45bbe22e465c6cce5092f0677468d8db", "b7a6d94f134416410be01722", "778ae0a3a44e33ab4e70587a372df8f21895727f2a9f07fc869b12839bf64898", "251bc1775d3c2d0dee7b8cc5"),
      (23U, 0U, "857980041516d9860405ff2b4660a99200e1645d1b14d62aa5236423d77ccadb", "6815d9632523b349b3b56d65", "45f51d01477d3a1b56095dba92686d045a199f2475aa85e00f80b5714ab9294c", "1917c353ae0ef9f04a92b4da"),
      (23U, 15U, "ef2aa858c74f20f3b6072e7d324d778db0c4ee7afe95014b18e746416444be90", "d044c981303e0a9e95cf4e12", "52f5f473c85cf7d6489eabd5e12a9938f8f2ded347ec4feb8f26b3340cca78cc", "c02f4e2ac8d69a8a49cd2ce9"),
      (24U, 0U, "9964ffdde50cb0341ca28f526e049e9b27b61018b6ac2899e7c1c962a0a36fb0", "193c9a8ded86d031599ca201", "f4b713b3f8c3302406b0324fbe7fd976e4bbe4e020f36cefe16584b81203ac9d", "a16129d408260754c517ab74"),
      (24U, 15U, "88f10067fa213a57da7b15a9fe216e17edef6d4c6919427bb3269e9b02769e6f", "bb4c1ed548d344cab95fbf76", "9684a7dbae4a961c9cd3a1e6909552d8d67328f8315d3cd7480b9951d7326a56", "b3ab89f9344ea903bae44991"),
      (25U, 0U, "73d8d6e350d6f711db01363a4dfccce55bfb819adc4a8eb0f1cb142b920bd95a", "d86c67f005581d813fe6211a", "9666d72fd981bfa6866c984fd2bc290c16f8f69c129fbab05006610f748bf82b", "a90d5e735298f60449e1fba4"),
      (25U, 15U, "9be0769ec171eb5f6a34a5e9b7f6c57662847d3127273c862305d4ed2eb6d476", "c53146c3f42d45b9e7d6118b", "8a11a2332a979b6a0a6913b067855af1a2bf02481985212990c1ac02b3d425ae", "3eb2629a7b3a84e38731446f"),
      (26U, 0U, "8612f11958ccfdec9e21b4becedc9c831a0eadee0bd19611bccfa4c095a34f10", "a232d33b2ee057c174eee366", "de9f89f8af5e21978766bae0cb3815bad4e507ea84eb54c91caad51ea238dde7", "52694b3920c04ef6f46e9a79"),
      (26U, 15U, "dfefa089b41cd4562453b709d43f7968d7c27abb1394554d5fa0a604527f2780", "5c17aa7253a308d84ab43ba2", "74eb21d8f60f0a64b09632e97a5b4839b176d78fea13e2ba96cc7545e5f62885", "bb4f7abf1d0860c1ac553908"),
      (27U, 0U, "cb869bde1eb5b70ff35739f9cb06c8272bad1b4c3bb234de7ffa135b2ed136e4", "f45e26ebfca815b4b821ee2d", "39d564c496b0ee7ee90cb6853d4938eff97a6a7e7396f566fde2aecce1d4a7d3", "d8cccccc1c53976c76f18466"),
      (27U, 15U, "5062fd8386cba1d40c9277d48ed146eabb8206fd370ea682c4af0b0767db19dc", "f1807a88fe30c9424630038c", "351164206bf6b171d9367e232cf82daf5e7f1ca2397238633c4799d8a476a9b9", "bbedbbab0d79fad3854452ab"),
      (28U, 0U, "7c4c2e51e314430775554cb1ff8940bbb4c94a6210b449769be796c98b2424e3", "360535c001817287e0982106", "8c5874902fcf0e6d82a347c766262576dbcb3a9ba1fba79a00becd6acba868c9", "5f89bc378212799802de6be4"),
      (28U, 15U, "59b396e69961833f648e05e8c0a065dcd271e81afc35b785645d1fba64aa5bca", "a4c6cb7e4fa8a290dea9a0f7", "a4dcdd02a47ababc9d29f2b718801e23c6b91002789aa227c63edd596e8dcce5", "90179202d31c7deb9f073297"),
      (29U, 0U, "3972dfe31100f7f7230bf47848d83b8c26e4f86d47216992319cf6626bca20e4", "ac47c72e2cacf39bccaa3902", "eb403c9e50781670a89e7890cec34deca93834185b12386d354cfd7b3eb4a20c", "a4b5342f92c21f024b226dca"),
      (29U, 15U, "92f28b1df9f9badac4d2504f97a0f8f06227e2eecc376cbc4e6230cc762f4eb8", "d7da6ad009d4617721fd8db9", "afdcb9be5d122e16abc7c3763f12a0f1009707cffa4965d1f2de34e2f8c63f42", "eb96cfea64f6ee0181d29583"),
      (30U, 0U, "508acb31ab4786832c997eed47ecb08b4e84ae54ec8a306caea2f3263ed32b4c", "e08c95f0c5d655c89c5cb9ab", "53759a62b8bfb13cece035ea5c6b93d9423b9490357b315e3953f91ff874305a", "ebca2ba3c6f41973ba3ccc67"),
      (30U, 15U, "c1d567cdb00b7cf868e572b9be2ee6f966411d18ee0f9675bb2c362ae0d2bf0c", "7d97be13602668670d73f64c", "3efd96fa798ad71f27f9704558d61af1fdc59a98fce954859310a58a61e5c758", "560ca28b329ba0b13134970f"),
      (31U, 0U, "7995eb14bc7b2d2de2f8327c2713d3fd67072171afcd340047e16cc9c0723206", "13c16545ca583976b85edc71", "07230e423965dc46903e9b7f9299bd7d494337e81ae456fde012e1d20da03ab3", "71ea257ff165a0c8b13bb427"),
      (31U, 15U, "e88bf2205086e437ccc2c2da260d88bcf060b6a73ce5431af21a4f4c569638b9", "089f74bf51d0e3b3473b8cfd", "4ccf1caa96504c21a17e6d06388b46aa70dfe22aedcc786f2ad3ff0709e9d949", "9d979b762eac328e6f29f749"),
    ]
    for i = 0; i < leaf_checks.length(); i = i + 1 {
      let (leaf, gen, hk, hn, ak, an) = leaf_checks[i]
      let (got_hk, got_hn) = st.handshake_key_nonce_for_generation(leaf, gen)
      assert_eq(got_hk, vec_hex(hk))
      assert_eq(got_hn, vec_hex(hn))
      let (got_ak, got_an) = st.application_key_nonce_for_generation(leaf, gen)
      assert_eq(got_ak, vec_hex(ak))
      assert_eq(got_an, vec_hex(an))
    }
  }
}

///|
test "IETF tree-operations.json all 5 vectors (Add/Update/Remove) + tree structure validation" {
  let ops : Array[(UInt, String, UInt, String, String, String, String)] = [
    (1U, "496d01012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f8340002000110dada00010002000300041a1a00050006042a2a1a1a023a3a06000100020a0a0320c2b83383ba0da6216cdc2da0ae2491d729ff4809624eb59752d697f08329927a091a1a06836d3c07c4eb4040cfb18b65de7bcab7a3171fad239479ad37567ab729ce1d37262dac8a71f5d6b06e276a100878e1c4cbde51114b2b69da66ef7860b940403e1c8d8a0cb9033e0f0102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e801320b9193e2cd747f422787a758fe5637886798c6a138162a3a6c4824d1d3e20012b000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf020001106a6a00010002caca0003000400050006047a7a6a6a026a6a06000100029a9a0320df19c8262bd3dd5a2721494e8e67af63026ea92c0067ed6f8dbb8d6a704579760b6a6a088834a98e43c5d12640403378b9aa589426a6e5e6045150307fd8b7d72fcb64202c114f3013bec247e4fb2ee7402fcdb9b4fb14efa31a39916c28291296b049d30a0cd358a1693cdd91070102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f192024d4099ace2e6f0c7bdf0a8e0ca6501a885d707bc4f7c84beb8945437503241c00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200010e000100020003000400050006caca047a7a5a5a02caca06000100025a5a0320747f788d2b133f65993e8ad959e3c331885c9d063d892552c69be9f030c1f782125a5a0f601ae01242bd00f0cfb0e81ac56d2d4040b28ff7be2f05d60c75cbf36702a0b4fdc9208e9aa97e7665874f3cbebd243b12c7fa507f17eb50e2f56357892f23fe4c290d74a50a75ca57e3c9294610c19e08010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e20f698cc6f93a503e12283170fec181bc29011e19d7c8433f6303e3f4154a325c700010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e02000110000100029a9a0003aaaa000400050006042a2a9a9a024a4a068a8a00010002032022979d017063b0199f461d64bf24baf4525a232098c101f46acb95147883e500049a9a014f40404eceb2b13c82897a0f46d883255f00ee7965f34054e5c337f0ae30d62ce57e0f4c0460c5a1f4dc9b2a72460a2e196c047d19e5039028aa74841ad2502e699a0b01022087d51d50760e8dbdd369fe80ff9e1066ec7bda1c10abe0cd94986c444d50b34700000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca020001120001aaaa00020a0a4a4a0003000400050006045a5a6a6a023a3a069a9a000100020320448a4e2ff9cdcca91eb36fb387a9775b4cc2b811e2f2bacf5de42c5240d7bc66046a6a01694040a07544f53fd7dcae0728c27b64fd9e1ecd1c4da0ee4519f70cbfaed36dc352c7c1b277d0f31165a65283db211fb1fc6def75b100baca380ba533138a6c4903060102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a20826a372dcf3307aff3c9db57a5678d3850cfdde25f548e00247fe003b6edaf8a00010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001100001000200034a4a0004dada0005000604eaea9a9a021a1a068a8a000100020320c4240c1003d152be08a5fbcffc6d4a93c5922adb2c5a8bd0d195ac558eee9fa303eaea004040abf1f13b4bab1ba999cec337119586ba5ce9962083ea8459a6e36088f25a3ae9c67b2c74c4487fcd2c0b1266fd1b32e307c580474c7a4e33bb0831d64656490601022090cc51841275222982eacfa7175064aabbdf1e9fc0d3b8caa1254fb669cf045f205b498efee622ede79a9f8d98e04faaf1a748e87bde4a50305d6c72fa69aad962000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200010e4a4a000100020003000400050006041a1aeaea02caca0600010002eaea032075c4a6212e7b382dbea04ea3ebcdb1b574d4504ef5088ad1fc4cac48044d50b1031a1a004040780fb6cc84b60872260c67fa4f13da154ebeda6e3d110db443fa120625077942f60cddfb1423e88eb961b05b89d3d6313ca4eda5ca5dd02d9b28f8305e9393090102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a32752207819f0e3c65835dff2b408ae58ef1c3a2e8ca3916134ef1345b8badc0afcb41f00010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e0001eaea0002000300040005000604dada5a5a02baba0600010002baba010000000000000000ffffffffffffffff135a5a10d80f9be639358e17feb4f3633f47107140402dd8873ac2d400e4372e7ff0763c55b1856074b2358fd4ed7143435b733d1e6112c92e201cd157946e39bee277d80921e38625eb4047b815f2fa749a5a26ba0c", 0U, "00010001000120256ab4a172a65e0e34bea3a8ad211a88f633b47aaa5c775d837cf4404d0f4c3c209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e000100023a3a000300040005000604eaea4a4a02eaea065a5a00010002010000000000000000ffffffffffffffff09eaea06fae05f00e9ac404064ac7afed038c6ee946e4f39e80edf8f2ff7d510f9dfd57ca123ba02f4ebbb36083edd0d6b2282ffc0d42f8341061e42e769842dc66f79d23ebf20730e43ba050c6a6a092315520e5649f2449f404086bdced443d954b20b230e50da7125d7b9615610208a5e2dadd4a4b74349c505ea8f2a1cd7c5262b9698aedd5024065883808343ee700d4d4c4a1261eb000802", "cf16040ad8680a387d870c26b5688a9f353c665320666aa1a55625f3f9b36224", "4a5301012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f8340002000110dada00010002000300041a1a00050006042a2a1a1a023a3a06000100020a0a0320c2b83383ba0da6216cdc2da0ae2491d729ff4809624eb59752d697f08329927a091a1a06836d3c07c4eb4040cfb18b65de7bcab7a3171fad239479ad37567ab729ce1d37262dac8a71f5d6b06e276a100878e1c4cbde51114b2b69da66ef7860b940403e1c8d8a0cb9033e0f0102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e801320b9193e2cd747f422787a758fe5637886798c6a138162a3a6c4824d1d3e20012b000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf020001106a6a00010002caca0003000400050006047a7a6a6a026a6a06000100029a9a0320df19c8262bd3dd5a2721494e8e67af63026ea92c0067ed6f8dbb8d6a704579760b6a6a088834a98e43c5d12640403378b9aa589426a6e5e6045150307fd8b7d72fcb64202c114f3013bec247e4fb2ee7402fcdb9b4fb14efa31a39916c28291296b049d30a0cd358a1693cdd91070102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f192024d4099ace2e6f0c7bdf0a8e0ca6501a885d707bc4f7c84beb8945437503241c00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200010e000100020003000400050006caca047a7a5a5a02caca06000100025a5a0320747f788d2b133f65993e8ad959e3c331885c9d063d892552c69be9f030c1f782125a5a0f601ae01242bd00f0cfb0e81ac56d2d4040b28ff7be2f05d60c75cbf36702a0b4fdc9208e9aa97e7665874f3cbebd243b12c7fa507f17eb50e2f56357892f23fe4c290d74a50a75ca57e3c9294610c19e08010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e20f698cc6f93a503e12283170fec181bc29011e19d7c8433f6303e3f4154a325c700010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e02000110000100029a9a0003aaaa000400050006042a2a9a9a024a4a068a8a00010002032022979d017063b0199f461d64bf24baf4525a232098c101f46acb95147883e500049a9a014f40404eceb2b13c82897a0f46d883255f00ee7965f34054e5c337f0ae30d62ce57e0f4c0460c5a1f4dc9b2a72460a2e196c047d19e5039028aa74841ad2502e699a0b01022087d51d50760e8dbdd369fe80ff9e1066ec7bda1c10abe0cd94986c444d50b34700000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca020001120001aaaa00020a0a4a4a0003000400050006045a5a6a6a023a3a069a9a000100020320448a4e2ff9cdcca91eb36fb387a9775b4cc2b811e2f2bacf5de42c5240d7bc66046a6a01694040a07544f53fd7dcae0728c27b64fd9e1ecd1c4da0ee4519f70cbfaed36dc352c7c1b277d0f31165a65283db211fb1fc6def75b100baca380ba533138a6c4903060102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a20826a372dcf3307aff3c9db57a5678d3850cfdde25f548e00247fe003b6edaf8a00010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001100001000200034a4a0004dada0005000604eaea9a9a021a1a068a8a000100020320c4240c1003d152be08a5fbcffc6d4a93c5922adb2c5a8bd0d195ac558eee9fa303eaea004040abf1f13b4bab1ba999cec337119586ba5ce9962083ea8459a6e36088f25a3ae9c67b2c74c4487fcd2c0b1266fd1b32e307c580474c7a4e33bb0831d64656490601022090cc51841275222982eacfa7175064aabbdf1e9fc0d3b8caa1254fb669cf045f205b498efee622ede79a9f8d98e04faaf1a748e87bde4a50305d6c72fa69aad962000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200010e4a4a000100020003000400050006041a1aeaea02caca0600010002eaea032075c4a6212e7b382dbea04ea3ebcdb1b574d4504ef5088ad1fc4cac48044d50b1031a1a004040780fb6cc84b60872260c67fa4f13da154ebeda6e3d110db443fa120625077942f60cddfb1423e88eb961b05b89d3d6313ca4eda5ca5dd02d9b28f8305e9393090102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a32752207819f0e3c65835dff2b408ae58ef1c3a2e8ca3916134ef1345b8badc0afcb41f00010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e0001eaea0002000300040005000604dada5a5a02baba0600010002baba010000000000000000ffffffffffffffff135a5a10d80f9be639358e17feb4f3633f47107140402dd8873ac2d400e4372e7ff0763c55b1856074b2358fd4ed7143435b733d1e6112c92e201cd157946e39bee277d80921e38625eb4047b815f2fa749a5a26ba0c000101209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e000100023a3a000300040005000604eaea4a4a02eaea065a5a00010002010000000000000000ffffffffffffffff09eaea06fae05f00e9ac404064ac7afed038c6ee946e4f39e80edf8f2ff7d510f9dfd57ca123ba02f4ebbb36083edd0d6b2282ffc0d42f8341061e42e769842dc66f79d23ebf20730e43ba05", "af8003e98d618669d2563f46607beb4536467bea9938e826ed8b11b0316ab680"),
    (1U, "47d901012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00018a8a00020003000400050006042a2a7a7a023a3a060001dada00020320047c08366436e1804fe6203236dff188c8404958bc279b2e666eb6b6420a68500a7a7a0710ef6c19e5d0854040e73fe349402cb8215f754a18c769815309c05b0fe8be1da0c3584319309953989b528774a243e7c88c3e7661cd4fdbe956216574ba5b34f81b445650167330010102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132036f1f42566569ae80dc85bdc4c3f1d7905699902b4de10cb6e143b10a5f3b6d2000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf020001120001000200036a6a00042a2a00051a1a0006041a1a2a2a025a5a060001baba00020320466bec4546020b5c31fe17a0e22567e5da8c116940846e0e81b7cd4408932227052a2a027e3e4040d3844c1355e3f5fe752d6d1ac66522b8f9cfeeed972004a0b8e5b71a8f2837193d63ba9e0c9b90d69fc81a043088a28e5eb24bc11fb96c4606ee01681726fd070102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920d7583cfece9ec7d1aaa8cbd781849a7142f86144fc1056ab2719e19593c1144a00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200011000010002eaea0003000400055a5a000604dada5a5a023a3a067a7a0001000203200a6d811b5eabcb3f02e1264079c59db047a835874f30ce38d21b11a58cda892910dada0df95cfb073a2fb295f9fb726415404068500e6ad5eadacda09a513d9d12ca35d15af9e20f2f5b24b114251a362fc7dd2748201efcf06d6ecf53c0f746d788803a09e059be543abf92d55893407b340c010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e2030ba33553783d045904286705a634fb04744ae4ec1c2281047a02a4485fa17c100010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e020001120001000200031a1a000400058a8a2a2a0006045a5a0a0a02baba0600015a5a00020320cc3c9cfd19a1169ea030b061448544ddb5861296163f15bc498b3f5553c1787e0f5a5a0c25f9a0f022b45cffea4dcd0040401a326d23c7e3115f539c15a47907080cde7bffb0958af41f1147e88d583c68798f860785f383b5a7534a7c1e8f663bfc4c5f4d893e571681522fd0cd432a040a000000010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001102a2a000100020003000400058a8a000604aaaa6a6a02aaaa0600017a7a00020320f98200f1bbaafee7b9f590e61813979270f79ebe5912268cb206fc57273f4d9e0caaaa09cbcdbba44b1acf6a9140409899a5a01d0fb551905f84507e9ffc0f29efd4c0309d05bbd75a2323a9fbe05e6b239a4bac1a30c0bf4ee188af8568a1baf682d17123580a343a10b76a306806000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200010e000100020003eaea000400050006040a0a2a2a022a2a0600011a1a0002032086632d6236c60fadb3ba6e83847a9f14a6fc3d763250a0aa4731ab60d686f660092a2a062bb314ab7b87404048589055296a7a88d95db692bddee5a517175b4f45f9fab9b3120b1edc2249e9b5ed22cfbe273aa75b143fe906c0730d7eaac08c8e2bfe244e912a7cfdaeae080102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a32752202c25471a5fde4a61d39d66a2e4f2277ad26dc542f387beecf21c172170ff484000010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e0001000200030004000500062a2a04eaeadada022a2a06000100029a9a010000000000000000ffffffffffffffff08dada0545eca30f1f404062e0834bf3e5dc78e94d3d3c3c92f0dee73b983b2e48643e7325e9c9da4374a95832b68e19c7aa1a11de2dbf99fcde18ff9c22efa5ab0bbe9554cf02a394f708", 0U, "00010001000120256ab4a172a65e0e34bea3a8ad211a88f633b47aaa5c775d837cf4404d0f4c3c209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e0001baba00020003000400050006043a3aaaaa021a1a0600019a9a0002010000000000000000ffffffffffffffff073a3a04c442c85b4040758f3ba7a2c531a0a856116b75d39943ee1608cff6671721113ed1f074099c1e89a1e375d194d1920e57ecfb8014fa2fd987a73d85c1c62a6d579f0837a53201124a4a0f4f2d8837806b26aa1f527e87a86fce4040ddcbfab6144910abdcf0bfdf7c24e859a0e0f3ce2f970ab435c6d73f05d58dbe916ee9d01d9afcf0143bc0c1e5a96cd57ce84d06b76e277aa1790b53bab3b50b", "e784f949fc040860c7a5648e6cecb2c7d2249e8f746f55f542d91ad7c3a6adf8", "48bb01012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00018a8a00020003000400050006042a2a7a7a023a3a060001dada00020320047c08366436e1804fe6203236dff188c8404958bc279b2e666eb6b6420a68500a7a7a0710ef6c19e5d0854040e73fe349402cb8215f754a18c769815309c05b0fe8be1da0c3584319309953989b528774a243e7c88c3e7661cd4fdbe956216574ba5b34f81b445650167330010102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132036f1f42566569ae80dc85bdc4c3f1d7905699902b4de10cb6e143b10a5f3b6d2000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf020001120001000200036a6a00042a2a00051a1a0006041a1a2a2a025a5a060001baba00020320466bec4546020b5c31fe17a0e22567e5da8c116940846e0e81b7cd4408932227052a2a027e3e4040d3844c1355e3f5fe752d6d1ac66522b8f9cfeeed972004a0b8e5b71a8f2837193d63ba9e0c9b90d69fc81a043088a28e5eb24bc11fb96c4606ee01681726fd070102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920d7583cfece9ec7d1aaa8cbd781849a7142f86144fc1056ab2719e19593c1144a00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200011000010002eaea0003000400055a5a000604dada5a5a023a3a067a7a0001000203200a6d811b5eabcb3f02e1264079c59db047a835874f30ce38d21b11a58cda892910dada0df95cfb073a2fb295f9fb726415404068500e6ad5eadacda09a513d9d12ca35d15af9e20f2f5b24b114251a362fc7dd2748201efcf06d6ecf53c0f746d788803a09e059be543abf92d55893407b340c010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e2030ba33553783d045904286705a634fb04744ae4ec1c2281047a02a4485fa17c100010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e020001120001000200031a1a000400058a8a2a2a0006045a5a0a0a02baba0600015a5a00020320cc3c9cfd19a1169ea030b061448544ddb5861296163f15bc498b3f5553c1787e0f5a5a0c25f9a0f022b45cffea4dcd0040401a326d23c7e3115f539c15a47907080cde7bffb0958af41f1147e88d583c68798f860785f383b5a7534a7c1e8f663bfc4c5f4d893e571681522fd0cd432a040a000101209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e0001baba00020003000400050006043a3aaaaa021a1a0600019a9a0002010000000000000000ffffffffffffffff073a3a04c442c85b4040758f3ba7a2c531a0a856116b75d39943ee1608cff6671721113ed1f074099c1e89a1e375d194d1920e57ecfb8014fa2fd987a73d85c1c62a6d579f0837a5320100010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001102a2a000100020003000400058a8a000604aaaa6a6a02aaaa0600017a7a00020320f98200f1bbaafee7b9f590e61813979270f79ebe5912268cb206fc57273f4d9e0caaaa09cbcdbba44b1acf6a9140409899a5a01d0fb551905f84507e9ffc0f29efd4c0309d05bbd75a2323a9fbe05e6b239a4bac1a30c0bf4ee188af8568a1baf682d17123580a343a10b76a306806000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200010e000100020003eaea000400050006040a0a2a2a022a2a0600011a1a0002032086632d6236c60fadb3ba6e83847a9f14a6fc3d763250a0aa4731ab60d686f660092a2a062bb314ab7b87404048589055296a7a88d95db692bddee5a517175b4f45f9fab9b3120b1edc2249e9b5ed22cfbe273aa75b143fe906c0730d7eaac08c8e2bfe244e912a7cfdaeae080102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a32752202c25471a5fde4a61d39d66a2e4f2277ad26dc542f387beecf21c172170ff484000010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e0001000200030004000500062a2a04eaeadada022a2a06000100029a9a010000000000000000ffffffffffffffff08dada0545eca30f1f404062e0834bf3e5dc78e94d3d3c3c92f0dee73b983b2e48643e7325e9c9da4374a95832b68e19c7aa1a11de2dbf99fcde18ff9c22efa5ab0bbe9554cf02a394f708", "35401ab19294389951a3858988952aa4c0baa3f29cc66a9207e9485d7def5a85"),
    (1U, "497d01012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00010002000300040a0a0005000604aaaa6a6a021a1a06000100027a7a0320157106897bd1560cbd236af2c409c87e4ca9fa796939d701ee8d964cb8dd1b4413aaaa10a6d93107eda0bc3a696a4a44db84a7494040d8153c58e3363e6e8446a0f0cfadb65c9cb8d7c4ca4c396a478239e06fcf106f3993dc0a54de3d7b6a90d19bae11174ffe395ba7ab453acb35169da42a3f58030102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e801320e9b93a32cf8b48a5e251d81e3b29d39738003d828cdee9b312eb8d8699ba333c000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200010e0001000200030004000500064a4a043a3adada027a7a0600019a9a00020320843475d3940352d948f4068a64a9423eb6e5edec1c246ca9cb905ace6e40001f063a3a03929ec5404073a15ded92aa00433fbe69ce0aea3d7e48de602715bd53e522430271543e8325e59fa80d9f1d639449f246142e78d2693b8769aef3e18af94547a398bd4865070102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920ffaeab3901fd882d1d64b9a9bbfcf9b3984fcac0d3c4b3edab39004dd3b3ef8e00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c02000112000100020003dada7a7a000400058a8a0006047a7a2a2a02baba065a5a0001000203209a6cdbedd8beb12cbdf926928012d452f04424995bd23358583d87d8ea345fb8037a7a004040f1ac458a058dfddf606dcda4b6c508873eac2a20662b1dc6ac29fd1703d586327b9bdd91a3114a12c8bb09b794caa009d45918836dfd0901376390407bbbc900010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e20a66949e84494ef9accc672fc2b56a94a7a56ba2c150ecdae756efac5c3c66d6300010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e0200010e00010002000300046a6a0005000604caca5a5a026a6a0600010002aaaa0320aeb88ec925dc27703eadcd0a3093c76739385c09916e40c359ae141917f53ad30acaca075dc921a7d1542a4040f3ac9d087563f7776e289f2cb7356ec10f68b1afd901fdd81df8987dc0f34d46c1f2e5f2e53f541432337e6d5e164b7799f56e72e59c4051d02045cb465d900901022087d51d50760e8dbdd369fe80ff9e1066ec7bda1c10abe0cd94986c444d50b34700000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca0200010e000100025a5a0003000400050006045a5aaaaa02aaaa0600010002aaaa03208b439b3bdb60edb91557328f2f3e0fca4d53ca1bb2efbf9ca7e3a38e1d62e1cb0b5a5a08521e845c561c1fa44040e6cf203a0cbdfecf21b5153a10d38d7f06cc0ef1bb58d8ed9da4642786ae4295d3c3478fbe99aa043b9b36f70919dfd54a04f667f77488e55fecea8b3c6c14020102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a202bf6e99711949a0d4ab7ec964e92a1ebc7f546613d8ba88083da931506ad764300010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c90200011200016a6a0002eaea000300049a9a00050006024a4a020a0a0600010002eaea0320c02bd05afa197b0f8f8b631cce6310ba8aaf016d9a157af76c3bc6ff819fd5dc074a4a0461ba6195404039ecc9ce7d340de80da0017baeca01c7cef1e8811063974b411d4f1888b3c4fdfb2f4faf199fd5ab3ec6d9293d7335b6375d5b3471c61b3cc0471b7307b5b30801022090cc51841275222982eacfa7175064aabbdf1e9fc0d3b8caa1254fb669cf045f20eb35dbf46480c96ad0a60ace5fb8a77ec07b63601225791090d4694e28806043000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef020001129a9a0001aaaa00020003000400052a2a0006040a0a9a9a02aaaa065a5a000100020320e103c8fb46aa817c6e71c4095c67a639804968605b6d376f92a56454e882faef129a9a0f8f0a9637e4708ecae4e5d5bebd9309404024ede41bcb6ee5bddfe0e55cc2461a915cd323bca7be13b37d8fa6d5bfa3cbc2e6d039d473c88a674e9878bd5c87750c57e44a5ba95f1d01f192deaf68a1340c0102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a3275220b5502b8866b1fa1cb0fb71801bdc387a0d380c39d4e957dd8cfa8039aaf0440200010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003eaea000400050006047a7a5a5a027a7a062a2a00010002010000000000000000ffffffffffffffff0f7a7a0c6d6e6fbaa59b24b94ea612134040653e7bb232c8918bd045dcbe999aa635edd5758945c80ecf3c0977a08869a5c1ceb2dde48a47186ba88b579e8cd5f4f6cbccfa45297c9fd794188b7d7e07220f", 3U, "0002209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e0001000200030004eaea0005000604caca1a1a02aaaa0600013a3a000202081a1a058c8a717cc440401c216d950b5fb7eb768d66c011cb6433a0df46e32f5d54f803318ece6b33255264e0a127781167e7837400258c457415d98b73c262baa99ea6ae53d318a50e06", "c6a17498a4632bbab8606da2af5216103fc76a516923e816334a57a8633f47fa", "48ae01012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00010002000300040a0a0005000604aaaa6a6a021a1a06000100027a7a0320157106897bd1560cbd236af2c409c87e4ca9fa796939d701ee8d964cb8dd1b4413aaaa10a6d93107eda0bc3a696a4a44db84a7494040d8153c58e3363e6e8446a0f0cfadb65c9cb8d7c4ca4c396a478239e06fcf106f3993dc0a54de3d7b6a90d19bae11174ffe395ba7ab453acb35169da42a3f58030102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e801320e9b93a32cf8b48a5e251d81e3b29d39738003d828cdee9b312eb8d8699ba333c000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200010e0001000200030004000500064a4a043a3adada027a7a0600019a9a00020320843475d3940352d948f4068a64a9423eb6e5edec1c246ca9cb905ace6e40001f063a3a03929ec5404073a15ded92aa00433fbe69ce0aea3d7e48de602715bd53e522430271543e8325e59fa80d9f1d639449f246142e78d2693b8769aef3e18af94547a398bd48650700010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c02000112000100020003dada7a7a000400058a8a0006047a7a2a2a02baba065a5a0001000203209a6cdbedd8beb12cbdf926928012d452f04424995bd23358583d87d8ea345fb8037a7a004040f1ac458a058dfddf606dcda4b6c508873eac2a20662b1dc6ac29fd1703d586327b9bdd91a3114a12c8bb09b794caa009d45918836dfd0901376390407bbbc900000101209be6295faf0814054cdef6a80c75a32ea834e634b41da42f5701a6d1f2f0e530205f002e8ef08a200f648ee70fb1c74c3d67b49affd5474607e228bf3e8d5de05e00012028fb5ae1c23e40d0ac1bc2af7239efb36d81265a3bf00ab1b345f010bfdcf0f70200010e0001000200030004eaea0005000604caca1a1a02aaaa0600013a3a000202081a1a058c8a717cc440401c216d950b5fb7eb768d66c011cb6433a0df46e32f5d54f803318ece6b33255264e0a127781167e7837400258c457415d98b73c262baa99ea6ae53d318a50e06000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca0200010e000100025a5a0003000400050006045a5aaaaa02aaaa0600010002aaaa03208b439b3bdb60edb91557328f2f3e0fca4d53ca1bb2efbf9ca7e3a38e1d62e1cb0b5a5a08521e845c561c1fa44040e6cf203a0cbdfecf21b5153a10d38d7f06cc0ef1bb58d8ed9da4642786ae4295d3c3478fbe99aa043b9b36f70919dfd54a04f667f77488e55fecea8b3c6c14020102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a202bf6e99711949a0d4ab7ec964e92a1ebc7f546613d8ba88083da931506ad764300010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c90200011200016a6a0002eaea000300049a9a00050006024a4a020a0a0600010002eaea0320c02bd05afa197b0f8f8b631cce6310ba8aaf016d9a157af76c3bc6ff819fd5dc074a4a0461ba6195404039ecc9ce7d340de80da0017baeca01c7cef1e8811063974b411d4f1888b3c4fdfb2f4faf199fd5ab3ec6d9293d7335b6375d5b3471c61b3cc0471b7307b5b30801022090cc51841275222982eacfa7175064aabbdf1e9fc0d3b8caa1254fb669cf045f20eb35dbf46480c96ad0a60ace5fb8a77ec07b63601225791090d4694e28806043000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef020001129a9a0001aaaa00020003000400052a2a0006040a0a9a9a02aaaa065a5a000100020320e103c8fb46aa817c6e71c4095c67a639804968605b6d376f92a56454e882faef129a9a0f8f0a9637e4708ecae4e5d5bebd9309404024ede41bcb6ee5bddfe0e55cc2461a915cd323bca7be13b37d8fa6d5bfa3cbc2e6d039d473c88a674e9878bd5c87750c57e44a5ba95f1d01f192deaf68a1340c0102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a3275220b5502b8866b1fa1cb0fb71801bdc387a0d380c39d4e957dd8cfa8039aaf0440200010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003eaea000400050006047a7a5a5a027a7a062a2a00010002010000000000000000ffffffffffffffff0f7a7a0c6d6e6fbaa59b24b94ea612134040653e7bb232c8918bd045dcbe999aa635edd5758945c80ecf3c0977a08869a5c1ceb2dde48a47186ba88b579e8cd5f4f6cbccfa45297c9fd794188b7d7e07220f", "76b3dc5edee2a0ae88bb1f5934b9ab8bc67eec912d92520f61381fb1dfb51adb"),
    (1U, "4abd01012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00010002000300040005aaaa000604eaea0a0a020a0a060001eaea000203203c99a4ab966ad4fdd0eb18238c0a713ecaada7ff9dfa4e1170b40f002fae4cc7110a0a0e9b5f3d804bafc37ae4fc1798172040404deea6d8760e47456b4fae788fe93c00ad664d1e200ee9f3f43f163ee60a4ed4787b37b2dadf31615249082c3754943cd397a0d59c2569b75f3ea751f6e56e010102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132038dc9aec856e8b8a76b3234bd4a9acb02f41a31ad8ae5ff06ac7344abf4298a4000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200010e00010002000300040a0a00050006042a2a9a9a028a8a0600013a3a00020320a75280c287fe03fdf72f64e3d691fb668f9d55ee75eea76f7eba01fd076de22a119a9a0ebdefa4a74d028e321df7a7635c9c404044e9c9ca65fecd898398d138d5584bed92b2fad1c1aa329306465e33b733ffccb4b9a79260e7ba91519ac12ae0f80482ac07c12f07dbaee5d0cd9676acc132060102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920e272175b2870222e4aaebde24d8134e897b88dea2b4303a66fe1784f4379781a00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200011200010002000300040a0aeaea0005caca000604aaaababa028a8a0600010002caca032075ea3ab9af63bd21444553f102986904dd4e9bff409ab5138011231deed72b270eaaaa0b0453ad16c1362772f529764040c1a20c712cac30589ce0b8830e88f4c97b73596448afc055176dcef4c58632dd2b16de38f7bac5a67edbfdf84a2c4f9efb24a3b94be88cc665e9052aeaa2ed09010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e20dc25996eba86c9ff08bd876e346a13928721a339ec1f5109a259f5feb69f5fea00010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e02000110000100020003000400052a2a3a3a0006049a9a4a4a028a8a0600013a3a00020320b403f087b2c6e65b49d7c165006aa2403707724d73eb1615e652a1968258b49b0f4a4a0ce7500e969a93eaa8a7968f6240406abb414b942d5465279b7dc4d4f487cabe658a62f28afa7459e09e55665fda8205c104725665b07a84020a32d101becf88f61cd3bd0e75178656d07b37d2160f0102206956bd798af452712be6cd409ce49fcffc65394ce82c92d14eda871f0f6e3d1620cfe62ef1b967aae8987ea24a63c42fdda64deb6498bcc7b1253cc35961bf6472000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca0200011200018a8a0002000300042a2a00059a9a000604caca0a0a02baba0600010002aaaa0320128354e427e8be9c4ed8bf16d15fc8659f15833f48df8fc850d4a71b823ae6cd05caca02df6140400971075ae4954a956b73da18500cc67f179d6aa553fdc1644680ee113e8e6ff6a90622d6c055a511ae805212087c30ae35616d91bd36dbf9da65d84d461d03010102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a205bb2f7939b26b01029d0ccc1400e106600de9ec9bd57563641864cd3e9b2256200010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c902000110000100020003baba00044a4a00050006049a9acaca02baba06000100023a3a0320cfd1049e149506ff8806d07e60690b7c4a5f7b687f29ed2cab0e9d9798bb611b0acaca07f1e49e95e5b8fa40403ba46254f2de24132cd66076b30afdac92717fbd275cb8a9c7a5de2ea9a96de41df72f0d10c6f7bce94050fed42636864d26570f2afa15b2f0f2f2bd0c5e6509010220f9af9bd0bd552a0d446840073f881982aa9a8481a8b45177a5df81003660724020e93b66b534d4c031422526220007841955fc8f03a025a86520ae8882c6367674000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef020001102a2a000100024a4a0003000400050006048a8ababa020a0a064a4a000100020320fe2856e64fc82bc186ba7778c0e2bb8b6baaf3219751ea559bef1abb53a42a1605baba02ca084040026856e86868aa43dc03e16383e201ae689b6580acc4624df488041425ec493d87a52e508e488b724619561cba152e2f22593d26708344adaa4c5412b95f10040102209c88408732a0b8b0256a8f1681a52f25b5c7bbf80218c292658b713a83c80315201ddd556e85d4b8d79071cd41bfc8166497218fe2af9a219186e1007ce077a76200010120bfe7b2e7263af7ddb2a96f533104031d61dc44567ad16f78dfd5eade18099a4520eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003000400050006dada023a3a020a0a0600012a2a00020320fc8756100bd9df738f707b1d7e0827c916259b96415ab72b6d5058723542428e0b3a3a08228e940012ffaf5440402cd1c9b25635dd02310fc4ad8310a65e924b18ec3c21452a13b76e7469435f592bbf72ccd339be4585fc7281dbbb260d535d0be2ec7598fbdb5b34951502b40401022003d56f6bedb3da90c417fc82fe92915c382f02125df807cfeb2beabfd0a529710000010120e06d6b8539f2477d45602da3ceceae590c69b5189d56fdbf1fbfa6050a268d5e2011e901c7b2a7ec501b634139009a92e7e60248f73be2ef9c2513d3749f4cf28b000120b3c4da3503446a86d0b727172070f322a5f7d359d786998b68f76a8d16164a0e02000110caca00018a8a0002000300040005000604aaaa4a4a023a3a0600010002aaaa010000000000000000ffffffffffffffff05aaaa02b584404064872a4ee10a195acb6525aac27b2f133e6bca149833e4e48ff1472d4bf556eaa0e7039e9e8b463ad8aa311336a0e9729f67e473e008b0333b4f438cadbae50e", 0U, "000300000008", "c22cab9734182a792fb3f942469a326028280b9bd9a963a69ad1bc15b54cccce", "49b501012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00010002000300040005aaaa000604eaea0a0a020a0a060001eaea000203203c99a4ab966ad4fdd0eb18238c0a713ecaada7ff9dfa4e1170b40f002fae4cc7110a0a0e9b5f3d804bafc37ae4fc1798172040404deea6d8760e47456b4fae788fe93c00ad664d1e200ee9f3f43f163ee60a4ed4787b37b2dadf31615249082c3754943cd397a0d59c2569b75f3ea751f6e56e010102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132038dc9aec856e8b8a76b3234bd4a9acb02f41a31ad8ae5ff06ac7344abf4298a4000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200010e00010002000300040a0a00050006042a2a9a9a028a8a0600013a3a00020320a75280c287fe03fdf72f64e3d691fb668f9d55ee75eea76f7eba01fd076de22a119a9a0ebdefa4a74d028e321df7a7635c9c404044e9c9ca65fecd898398d138d5584bed92b2fad1c1aa329306465e33b733ffccb4b9a79260e7ba91519ac12ae0f80482ac07c12f07dbaee5d0cd9676acc132060102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920e272175b2870222e4aaebde24d8134e897b88dea2b4303a66fe1784f4379781a00010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c0200011200010002000300040a0aeaea0005caca000604aaaababa028a8a0600010002caca032075ea3ab9af63bd21444553f102986904dd4e9bff409ab5138011231deed72b270eaaaa0b0453ad16c1362772f529764040c1a20c712cac30589ce0b8830e88f4c97b73596448afc055176dcef4c58632dd2b16de38f7bac5a67edbfdf84a2c4f9efb24a3b94be88cc665e9052aeaa2ed09010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e20dc25996eba86c9ff08bd876e346a13928721a339ec1f5109a259f5feb69f5fea00010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e02000110000100020003000400052a2a3a3a0006049a9a4a4a028a8a0600013a3a00020320b403f087b2c6e65b49d7c165006aa2403707724d73eb1615e652a1968258b49b0f4a4a0ce7500e969a93eaa8a7968f6240406abb414b942d5465279b7dc4d4f487cabe658a62f28afa7459e09e55665fda8205c104725665b07a84020a32d101becf88f61cd3bd0e75178656d07b37d2160f0102206956bd798af452712be6cd409ce49fcffc65394ce82c92d14eda871f0f6e3d1620cfe62ef1b967aae8987ea24a63c42fdda64deb6498bcc7b1253cc35961bf6472000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca0200011200018a8a0002000300042a2a00059a9a000604caca0a0a02baba0600010002aaaa0320128354e427e8be9c4ed8bf16d15fc8659f15833f48df8fc850d4a71b823ae6cd05caca02df6140400971075ae4954a956b73da18500cc67f179d6aa553fdc1644680ee113e8e6ff6a90622d6c055a511ae805212087c30ae35616d91bd36dbf9da65d84d461d03010102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a205bb2f7939b26b01029d0ccc1400e106600de9ec9bd57563641864cd3e9b2256200010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c902000110000100020003baba00044a4a00050006049a9acaca02baba06000100023a3a0320cfd1049e149506ff8806d07e60690b7c4a5f7b687f29ed2cab0e9d9798bb611b0acaca07f1e49e95e5b8fa40403ba46254f2de24132cd66076b30afdac92717fbd275cb8a9c7a5de2ea9a96de41df72f0d10c6f7bce94050fed42636864d26570f2afa15b2f0f2f2bd0c5e6509010220f9af9bd0bd552a0d446840073f881982aa9a8481a8b45177a5df81003660724020e93b66b534d4c031422526220007841955fc8f03a025a86520ae8882c6367674000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef020001102a2a000100024a4a0003000400050006048a8ababa020a0a064a4a000100020320fe2856e64fc82bc186ba7778c0e2bb8b6baaf3219751ea559bef1abb53a42a1605baba02ca084040026856e86868aa43dc03e16383e201ae689b6580acc4624df488041425ec493d87a52e508e488b724619561cba152e2f22593d26708344adaa4c5412b95f10040102209c88408732a0b8b0256a8f1681a52f25b5c7bbf80218c292658b713a83c80315201ddd556e85d4b8d79071cd41bfc8166497218fe2af9a219186e1007ce077a76200010120bfe7b2e7263af7ddb2a96f533104031d61dc44567ad16f78dfd5eade18099a4520eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003000400050006dada023a3a020a0a0600012a2a00020320fc8756100bd9df738f707b1d7e0827c916259b96415ab72b6d5058723542428e0b3a3a08228e940012ffaf5440402cd1c9b25635dd02310fc4ad8310a65e924b18ec3c21452a13b76e7469435f592bbf72ccd339be4585fc7281dbbb260d535d0be2ec7598fbdb5b34951502b404", "e07ec23bef84f9695cab0b5f1f05770943b2fb79522c4fff45fcbce5f6c160e1"),
    (1U, "498001012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00013a3a00020003000400050006048a8a6a6a024a4a0600013a3a00020320b86d904ece0de0bc0654e2a504ac1a3ee715a5e307d5ece48f7a8ed4a8d114380b6a6a08e6f5b1589e2bb28440405f8ece21a4287279b84ba92b8e059efb15e2bccb89c2b5026d306f7fbc534d7530a33da91cfec82c49b5e7407f9f27423229eba7a4f28551957bb678b074db080102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132076f1b5d600d72732f83dcd1a69fc8932d311762a220f5fd2a6cb7ace90353333000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200011000013a3a000200030004000500066a6a048a8a3a3a02aaaa065a5a000100020320ca776e74ae45007c9517afb90b739b751da2e0a5ce3f8144b93c8c37e4a1d2e70f8a8a0c2cda74b709851912c7715c2a4040cdbb509fa2b0c99724e0f0d1cb877f60d46815f7e7182fd180da2a54065e63f467c43cf2c571418802c6d47986b01d379dfb64cf101512a067757927a7961c080102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920ef45f2ae5ebe412a48f3aa4e7adc8cf7e0419a9fff8ac8888dbcf1142ae9cf1100010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c020001124a4adada0001000200030004baba00050006044a4a7a7a029a9a060001baba00020320dd4f876c31060aa36287bdfe0c1284da5401b42db272a9ceab06641776c9f12c0c7a7a093a957af05fdf83db1640409a0371bebfc7374116e99b7d1a85a09ad213159cdaa5d051adfec51d052a8c36348cbce22159c505ade5ae3fe1c4b8802da79704d30dba5dfcda6da7f6931e04010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e2013fd8b1f6cc54d6b750487481d4c46b61fb79d00d1cd5b7e25de70bef24c113500010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e0200011000019a9a00020003000400050006aaaa043a3a5a5a028a8a068a8a000100020320f1a7e2ad9e48eda8a5e5b5e956619a9700c0d15bee78214d89acb76bc950bc76115a5a0e9ab05269722cba7a53e83b5556e44040f2cb55c7c70d38880ffd4a708d56b8f19de0a6eec6912e74e0511bd2aef3d07d61eca2d1148a59c01f049b43051ae4b42dbfc74f360961207c13b15f46aa3c0601022087d51d50760e8dbdd369fe80ff9e1066ec7bda1c10abe0cd94986c444d50b34700000101203ecd65878e3c421e23d1aff3972060aa0caf72c8da321c49d0e3e32e4771565c20b987fd77c3322b9b92ba1e6c645dbed8a28a333e25fbe78599a50eaee00caf2c00012094b5eb2be2aa0dccf65e67488dee8701c68cf4aa5fe35de03caab600c6c055ca020001100001000200034a4a0004000500065a5a04aaaaeaea02dada0600012a2a00020320019a6450d58b935c5eec0c4980d6eee55be48ef250da389eff39eb4a08c3a88106eaea03071a06404064211ce06f2187e9ec24a7409bb3e6513e1757902cc3f234ed4352d5e71e845d929553141dbcb958758e9522b54b6ade39951c180bf398eb7ef4405334958e030102209c72c8df4f0e3284017f589bcb978b38167af99aa1ff6eb4b148e90bfdbe042a202fc670280c5bb77747adbcbc3b017d1d8792d34b1a8d3c195af62f7e25b283fa00010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001120001000200031a1a9a9a000400050006dada047a7a2a2a02eaea066a6a0001000203203c00fb889d6e64902971a49b6ade202598865b7ba62f77c9c64de46142f46eb00c2a2a09bb23e35fce5caeaaf240401e0d9aac24f75cc7c3a5eba3bf0c7aa89d66c3e2d7fc7c674e3b7efa0d3f81bfcdd9b5481bcc7df791f17b3cee0af768d5b9edbd10c99b938e1b77ccd7a82b0201022090cc51841275222982eacfa7175064aabbdf1e9fc0d3b8caa1254fb669cf045f2029156f09ff4c176f940fc94938fe21c85dacbf8a04b324c7a6e4351addd56dc3000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200011200010002000300048a8a0005aaaa0006dada041a1a7a7a028a8a060001eaea00020320bfbdf22776ebbee7c7052603bfd59e91784214f062d27bfa64a99ede9e7ba8e3077a7a04d876334c40405e20334d0a3eeabb928f915e91cea4fcfc10536c6ca9f9e62debb908f0ee12a28747d4266ccb112053106fed076ddbf5b0dce83c50f879529c47aa9ebd9a020e0102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a3275220cdf3463e5f748ee974a210a8dce9fcc6be22aa2eb27a124dc53ba2ab0030386e00010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003000400059a9a000604aaaa7a7a029a9a0600018a8a0002010000000000000000ffffffffffffffff04aaaa012a4040e178983673071ef734b1fdbb2984b6c80bd7b6d6a16bd8ad2a9ea30e26d4c48bc3e8461e45cc8d9a508955b5806b83ca59da187686232b28866f5218a8e49300", 0U, "000300000004", "853e970c82285a8abd7613d1f9bbfe1f30ca9e5c14d1bff58ce77bbe93ba04ac", "47e001012085197b9ea343524f754dc668824184295b6d918b77b025cc491f92e982f79068202311e895c0ba2fc8706691f28808f23ecec88348605506aa0654e94365574d7a000120780fe5828d4161e1f2349a886b1a65429047c1c2adc9f8f757ad323ab9f834000200010e00013a3a00020003000400050006048a8a6a6a024a4a0600013a3a00020320b86d904ece0de0bc0654e2a504ac1a3ee715a5e307d5ece48f7a8ed4a8d114380b6a6a08e6f5b1589e2bb28440405f8ece21a4287279b84ba92b8e059efb15e2bccb89c2b5026d306f7fbc534d7530a33da91cfec82c49b5e7407f9f27423229eba7a4f28551957bb678b074db080102209772cc1afaadd8ff99c5672fcfd7d0024c035f3ac353fa20d8d53f68362e80132076f1b5d600d72732f83dcd1a69fc8932d311762a220f5fd2a6cb7ace90353333000101206ccbf1b01d0a78060b7da0083c585ca4e1d0702c9e16b40b66437f498d7283602093590fb48b55585ed73ae57e09101a8bb18c7e03d138732e5a9a1414b4c3c1c50001204e45da376c1a158af47621831871e7f379808c4def8b47fece1f2831727180bf0200011000013a3a000200030004000500066a6a048a8a3a3a02aaaa065a5a000100020320ca776e74ae45007c9517afb90b739b751da2e0a5ce3f8144b93c8c37e4a1d2e70f8a8a0c2cda74b709851912c7715c2a4040cdbb509fa2b0c99724e0f0d1cb877f60d46815f7e7182fd180da2a54065e63f467c43cf2c571418802c6d47986b01d379dfb64cf101512a067757927a7961c080102201ec571040b25c76b6ddbceb794937f075add861ecc808de40c6fd38264112f1920ef45f2ae5ebe412a48f3aa4e7adc8cf7e0419a9fff8ac8888dbcf1142ae9cf1100010120768c94746f0ef5dd75fbe8b947dc61845fb22d87cf21cd90b806c8641d910d2c204864ab8d3a225b3ea36c43e00485f8a9fbf351d35e51dd8884e61de82e4f5440000120075bc7dae0b65da93ec1cbcffa29f9b9c3bb61713ea4584eb0cdf77e2008406c020001124a4adada0001000200030004baba00050006044a4a7a7a029a9a060001baba00020320dd4f876c31060aa36287bdfe0c1284da5401b42db272a9ceab06641776c9f12c0c7a7a093a957af05fdf83db1640409a0371bebfc7374116e99b7d1a85a09ad213159cdaa5d051adfec51d052a8c36348cbce22159c505ade5ae3fe1c4b8802da79704d30dba5dfcda6da7f6931e04010220799e8cd5133dcf913d1d53bc64f64e30c64294b706ff569a964dadc19b08470e2013fd8b1f6cc54d6b750487481d4c46b61fb79d00d1cd5b7e25de70bef24c113500010120709f9772177598b7e8b9dd8b88b3b4aacc70eca97275ce033bf9110522667e3320dec5f81d751582e168613451936878ea50b3ef6b9a3a7db6adbb2a0b9927065f0001208b54f00f020d9ac4309e22898c70fcff6c484ee42f5442c80159ba7ac753b10e0200011000019a9a00020003000400050006aaaa043a3a5a5a028a8a068a8a000100020320f1a7e2ad9e48eda8a5e5b5e956619a9700c0d15bee78214d89acb76bc950bc76115a5a0e9ab05269722cba7a53e83b5556e44040f2cb55c7c70d38880ffd4a708d56b8f19de0a6eec6912e74e0511bd2aef3d07d61eca2d1148a59c01f049b43051ae4b42dbfc74f360961207c13b15f46aa3c06000000010120d039ae0b7b4a4a71a4c116e17d8adbcb48d0c22daa45a16b5b053f2ad1ac301320d127da04946167c4d36157b8accaebda122dbb4ca558af10227dc7b84c211403000120b89e539dca24e0f3f3a795afc6cace589ba17eaf0fb44c984384597f0e1740c9020001120001000200031a1a9a9a000400050006dada047a7a2a2a02eaea066a6a0001000203203c00fb889d6e64902971a49b6ade202598865b7ba62f77c9c64de46142f46eb00c2a2a09bb23e35fce5caeaaf240401e0d9aac24f75cc7c3a5eba3bf0c7aa89d66c3e2d7fc7c674e3b7efa0d3f81bfcdd9b5481bcc7df791f17b3cee0af768d5b9edbd10c99b938e1b77ccd7a82b02000101209e45c0feba832b1f5b6de84a7040d45bf34d99b92a8ff249ee11e27a1444843c20a0cf9dee5d4d8f8ecfc0c4e2b979e82c728610269dfe960b65313b2a4cc995b30001207332124c694644e3557d80049271b4dcaa1d3db4559149988331db0577a67bef0200011200010002000300048a8a0005aaaa0006dada041a1a7a7a028a8a060001eaea00020320bfbdf22776ebbee7c7052603bfd59e91784214f062d27bfa64a99ede9e7ba8e3077a7a04d876334c40405e20334d0a3eeabb928f915e91cea4fcfc10536c6ca9f9e62debb908f0ee12a28747d4266ccb112053106fed076ddbf5b0dce83c50f879529c47aa9ebd9a020e0102205f01d87cddebe75fe62b81710864f03f5992041b705d53b6f4f950ed26a3275220cdf3463e5f748ee974a210a8dce9fcc6be22aa2eb27a124dc53ba2ab0030386e00010120977557f1906a3457269c16a408c63fc02b2a8aba3deb6b27cb5a815dcf6cc52220eb1378788e51c9c26c8cf2824f48e0869451d6bfd32a93b10d622100c02a87cb000120f5e5d994042791b49ccea6989b38a81dbe225e45f40a797d77edf99296c4772d0200010e000100020003000400059a9a000604aaaa7a7a029a9a0600018a8a0002010000000000000000ffffffffffffffff04aaaa012a4040e178983673071ef734b1fdbb2984b6c80bd7b6d6a16bd8ad2a9ea30e26d4c48bc3e8461e45cc8d9a508955b5806b83ca59da187686232b28866f5218a8e49300", "fcd5be02ba0e934651c0eb9fdb1c999fc3e42673fcf0c8bec062036461fb52f3"),
  ]
  for i = 0; i < ops.length(); i = i + 1 {
    let (cs_id, tb_hex, sender, prop_hex, thb_hex, ta_hex, tha_hex) = ops[i]
    let cs = @cs.CipherSuite::from_id(cs_id)
    let tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex(tb_hex)))
    tree.validate_tree_structure()
    assert_eq(tree.tree_hash(cs), vec_hex(thb_hex))
    let prop = @types.Proposal::from_bytes(vec_hex(prop_hex))
    let _ = tree.apply_proposal(sender, prop)
    tree.validate_tree_structure()
    assert_eq(tree.tree_hash(cs), vec_hex(tha_hex))
    assert_eq(@types.ratchet_tree_to_bytes(tree.to_trimmed_nodes()), vec_hex(ta_hex))
  }
}

///|
test "IETF tree-validation.json CS1 & CS3 cross-package full validation (structure + parent_hash + leaf_sig + node_hash + resolution)" {
  let tv_cases : Array[(UInt, String, String, Array[String], Array[Array[UInt]])] = [
    (1U, "99eb8e58d827942e1d519c80de6861e96e365f0c9f4c01bb12daed4a29ae31a9", "41a5010120c699b3cad02afaee6c9a0ea2a35f078482e53c830ebba510dc349b2a945ff96b20d9c893be859ac2c6a4ee95820ab1ffc63f8ef371054ae8165225886e6898026a000105416c6963650200010e00010002000300040005000600070000020001032091b43a9ebdd181fc2a368e05627b009a64591ed7bb29d78dcd6bef620351edb7004040efb4542a4364d9ce223ddcd170e0a1889f53ef10b7399b0ccfb0b01127189aeee93ee83810425827e8231f504055a8c41e7b6a3be7b062abdc67272533c66f0a010220566e1f1bddcf6b9a3415e3022c316cb09ba33733f6a307a42c7db653ff6ead7b0000010120129388082a7660bda213aaa17e7d6cd5e2b08b37cfa46e2fa0184cceb340ee2520a0ba7c18b0faa49f7cb51d9e8e76dc18efbadec946ba1a17b946ef2b4453550a000106416c696365310200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040499a320a53322e9f9dd948128d46880d86e37b7905b963b66b22b4135412ef758a27fd31a5ef1bbad2927eda2c3b43d11b5e4ade1a8de36f4606373bddc01502", ["6f9e6f4986032c65ab08dbdc329fa2e8ee4e069a5ffd148f8c8baa30108a4e13", "b30fe5a7fce94e0d267f3f8d3e1628c695587370833efcd11584b32978c23dd2", "135d5ae4cd847ad243ad9714213de9839785b3a48d0cb34e8aed817d49bff678"], [[0U], [1U], [2U]]),
    (1U, "4175993ba77257ded5bc35780b81d9a1705bcb93fd48a1c608f256e6d9edf4c4", "43c1010120016bc63e1d96d806bc81719e262d8d549ba8d94280d9b8e5c1c66dd31a04260620b342ebc11e8295c7ca2f090ec9f261ad3c4843233c6995ad34367a4b858ebd03000105416c6963650200010e000100020003000400050006000700000200010320817def30133ff7b87be7adfc299926b20880b1ea76c649f8cf8c7a6126a4dcbf0040402a14e8853b554b318704f79f54bc45160c3a86cf6ce1255a8975df1628a2036c54b0f74c71f53c1f17d5a700a156c8c63db8ee34e1da6ad1d10bdf085cb20b070102204d78ba96720b720c08e91eda3d6a64ac6294e5bde01eacc10049c44427c3d60020355cff38ce6ad9976e79b8a3e557b7f4596fc73e957b77f7352ab042c895686900010120f1201e23f02b1b6c43b221a9129c673d165a027487d352e9f2e6e5b0dae08c3520c936df7ac66e4053861180847a091d7e34a8ed3b417725f365e95ffee42c1069000106416c696365310200010e000100020003000400050006000700000200010320b51846840add8a6587818808f3904e4f0b7fc5df16216cb75ad2977bc8cd4469004040ab58b52e188219e88b13b204e62f68bb41bf27eb715e44ee367c0bf5bf8eba39414e78eede95209f147a1b132cb1760aa79385f8777f2519760ff647a79a4c0a010220827742c6914242c13a34b5646151dfba405a5e853ac359211cbf03da05d41a280000010120e83506d8e79162ccf970455a85ae07227895b680bc2c2aad037689c98f5bbe1e200d4db5500dae34b8a0dd247833e7440a41f4f90f6a644e235ab7f6bdc2d0dfab000106416c696365320200010e000100020003000400050006000700000200010320d29ec99190094a3f9f0c83a16b61d7898c1683a8ac856289b74b4dbe60066772004040683cf80bf9ce265f7aa2b40efa438e8b90bb997e9739486489a2670559b5e56c86e115492503d7cb0fa3ecdfb200aa53d221bfcac04bec84679d253631ce4e07010220b16579b44e6e52a288931345588f394b89c50eeac49ccaeedadb9fd800230c2b2050259b33fe9dd28250eb9a25d3273d506036924f914113bfc08530f09ffcabad0001012063e2101f28444c2d80f88edf4b2bed63b5199dc7b7473e624692900013285f672019fcb3a4588d81d1547fe85b3629b03e3a7ac20db7721d7734dc76e535643c16000106416c696365330200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd100404063e09ce77ece145bdb12faff5896886863b766e25f676b9ebc735d31bc19219701befe4fd605631fb76b52b11c19d3ae7e960b9cd9a805a80a484a196ad32400", ["e96c8b4d7d598e07babb6fb15c0c9c352e1d759ad42713447271803a9ec4f622", "763e016ba5f8da28a6dae2d5413a08a8bdbf61ec228cf4942695c3b7d35a0cdd", "52b28fdc5c7d113990e5b501970fa9ffd624b9b5e624f1ccb28081b56c7fdb7a", "0f056bdc7f23f227f127383185a6d31dcc54750631a929b4a6118b2a28b589a9", "95ee5cf4c849afa9916a85b67bb34e5a1027a32cacad8a232abad38131f68e8d", "c8482cc5a649cee8c18ad066342ec99dcc038f36971a44f1e771a39499489790", "704dd8a4e9385902d8542ebe1089f3be7073cdffbf8e1369e15a3743e397adc9"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U]]),
    (1U, "3ba3dd3a2ef6e53ae1d9bf7f6d6da0fbc37145c4e4b5f6a30dee6624e07abf89", "47f9010120bf0de63c894a0c0b82515a1e54bdf637804d2d994f422b7c7b0aec6f88bf961420a64efa22bea02afeb4c52a8b14fc5748f1a7be700d3e74b4d85f0863421c8a21000105416c6963650200010e000100020003000400050006000700000200010320fa0d4855e5f5224f29b4a7e9caf930f8c3eb93774e3d78adc7294dcd4752a11b004040d2aa8d9091630d21a8e7b2dc2479b8aff1b8ea66b1236a13cac56070e026e6e982d73fddee513f3edabb3fb2608db3a9de56707e7fc4cd14dbef46c62a319a03010220276aa389b98443115ef44c157e1a9d9812c1378d6e4d27eadfc87b83ed4c1b412041149db42b6e8aa8cee1d80b0d0c57bfe24c4fb3767f22a61396d7ff98642f4b0001012042aa8e8c63dd085c5e20bcfc4a01ffa826b40aca0e5ef569853fe042d723ce132055fc35bde3541d606cd5c976472a10ee2fc8235378d8c61854545e46abc504b7000106416c696365310200010e0001000200030004000500060007000002000103203e72b219ea029a20841a115e80f2c6d5c1d39c441de078373210e687f2c4b9ee004040b94ae8b506f247cfa9113c678968dd08d870ffbefd30ef8151e681a3bc7feb693f3924742feaed78feb365584c7faffff18941a9a80c7de936dca7f625b8bf0f01022025fcfcf134e480d81b04fef113421551e477899f4f6a8319bfd9a6f047cddb772050901a518ecd87d5368c631eae236f62d428b2cdcfdd8c46d46df7b27191f4ea00010120b2f2b4b54a788316f8da3017659f9d76eb30d3c37e52bebc7d49169e5c7f7e492051b9ef061f1dc218e71e727923aac410700db493cab86edd7abc1ae9c13d2b3a000106416c696365320200010e000100020003000400050006000700000200010320d514b6b7eb7856396bbd2febc3c76d6bf94263e02267f16b0feb87eaf0ee7cdb004040cc10fa713e5c28521c1602a56b55e3e1143ae4fca1229c65d8f1c6546eb0ce97c8e771de9e38727da75e83973be208d336aca2bf0db638e36514b0bee97f0108010220e15393b64f3f6037c44ec9ae0e0f3bf764be29827368340fc4f9f3dafdf56e70206e88fd6b32a8cd69cd4aaefd611d69c29cebf33f27d234f06e3706c12ebf1e3f000101208e3027bcd8a62fb4c86fb53e311984143ff06573104d976679f761a88cd0a225208c82f0b26f853d1994b841b6846d65d50d986e767f0a685cd26a1224b104b6e3000106416c696365330200010e00010002000300040005000600070000020001032079bbfb6635201f48ef0282e6002999d012133663336a619d19ab06a26825e1f0004040435705adddeaa2cfc2e625452188700e9509a7b15f8c857f87115be90ef396e40ff82aa54c7d65efd86df68703d1b6a616e8a08abc716145a38281796ce7a90c0102209dd573c585868519ca2585e466881b2e811616ed21c623a087abc81bcd869b6c0000010120ba25072ace72e0ddd82a60182d1a04f027a4331e7ffba5270db9b1db39d04071207f2434342b5cf6b14cc159f470cacfb86c8860dacfa8395fdcf686d75c38999b000106416c696365340200010e00010002000300040005000600070000020001032034e9778f7c0bc67e8f1bfd014ccd83d365e2248d0f638cc4dfa231fe0631ddfe00404054970047e655ecceef02aed0df5e49339242882548c0b32ece8f2986a7a4429a35f0996ead4dbdc63b29631b209e640e007f33a4f3d9ff4d37f00e55a8a0710901022040a07a52b8ebde109ee15b4a4ce1fabdaa0cc3b4445f78a366c82bb5e48cff1620d28a6eb0cf57a8f0ecd82a9a52465b8245c49c62932904d82b1a13cf8c8635d00001012044a10eea4588bdb83a28b63c709c8d764a34e8992707ada0724db6f35acb76132093e4f4ae5e9deceb958034444dc537733827ea3b25edb5d83d42c42cd9f54ccf000106416c696365350200010e000100020003000400050006000700000200010320462f1c85d65feda495d8c8a005e93d49316d99b2e56c0377e67a59468ce86b1a0040401aa0755050d98fbe91811228ed9b5b815f45c8da97924585481f68d6664c6e2fe440191c5e2207c455d05cec271e86962a7f7312d824929eda230f579361bf0301022022b8d9bb01c834646272fb0023d451eb979601725c080df703365e5624034229207cdee8285af3b0ecdea54a06b4f003c4e1457bf22738e0c616a36fd0ff37c981000101208d2c7738b2d5bc02ce495a6d1bad8b32da6033f7e14906a21c3e0e1d85d962442054cc59897860062d6e9ba8590f55a32be9dad2c9f871015ae83eda04c712e8fc000106416c696365360200010e0001000200030004000500060007000002000103207c56cba3dcd50c651c437b71109e61f3c8d253953988f2ab4c9d398eebc6516a00404006ef9d439d682775cbaafb72ef93835d4f229732c9580ca41109196bd7801dceb145fcdc3e2e821b67a12fb62130ae0e369ad17ed9146ce0a3ee001848a2ca0e010220dd8c95b427b5a503295d8537c3880c941567f8b1d2a60a93ea43d55c86dea40e20920d8f1d971ca3a3e37c98d3d7535aef404102e8e7d6159c4d9d3ecd9cf3b01c0001012083fdb6ac808e9bdf9e768ef17b074b579359d8b0d9a8220f33e527307d6c393720ad9ced0782f543cabe24567c81bb0edbc14d084164d9fbba8168111f7b60afe1000106416c696365370200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040c92ee8ea2868da71c9dbf9dae2263a9e15984a29fe7c196c52b145931accb6561f8c386b43e6fd9322c69b8fc6a44a3e98e45f21587800efd8bce8d1d1621106", ["99854c0c2e647edc51fa9398361412f9d3ecbc4a828f84a44beaccb415dddf6f", "5ae68956b9ce14388196860b3ab578c2097380725507e99b76278e01d24e6bae", "328b7c67d65afc2d3408536463214000f9fe606f430ab8c9a1611c4723a3fc60", "62f6dee63cb45fa126353d7ce69a1f7bb040d1d93ade9ab33c17f994a3504c54", "29af3375ec34c2db23ed9ff0f377b94dda0f75fa53de9e2275d56c2a4050e19e", "9e6ad5a1063c1b21076d6a5838366d8c344ce17d46d5a0a14e626eb59ad90c84", "3cd5a533775a21d023baf5782ce63a4c7ad679adaeaefd38209cc9eceb605f02", "0e90cd06bd87a3237b08b6ae8e5be1df8ba38492122668d2c3720d17a647e13b", "ac12ac539483eed99d3388765416728dd281f6225cdce8ea11ccaa8564675391", "c932c9ad90e6c27606448e40a80627f01b0240431dd977ca3092804062820e8a", "a4a3579ad17a1e40c627d9df871354ad620951120294f7c241e8c3414c8dd2c0", "c999942ad1fc128f113072d0aa716c1c4df9b84dd34b4c9e315ff8d8ce0a16b5", "80757b782b4c1b6dd8dd8a46ebc0a7ecc12fc911e0dfaf203928f3905c8ac2f7", "76b49d7c38f9caf1ee9a44296bf1ba8fdacb50efe00a550d483217ce496884da", "15eae7d9c11364b0a35af9ddb4ae527b9ec31049b1b20ecf30e0d9c075c9d4b7"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U], [7U], [8U], [9U], [10U], [11U], [12U], [13U], [14U]]),
    (1U, "f456c53f4debb12e0c1fab6767b6e23b1a34932d2f8ba9a21d346ea2eb6193ce", "46d90101209c7cfd6aec9aa9c2268f4e139ecfe675992af819d69d6e40999429a8667ec47220cc381a07d14e538e75629248027c9c5ae2a3ba31ff55d4d6bff69963a19beefa000105416c6963650200010e000100020003000400050006000700000200010320afb2172207951a7e658b1f02e0dd324ad9e3e0488d4b1837a9a17c0ea7a866b600404032624cb44fd12061334e546a98ae3154b863abd489f64d79ec7ef3e2b643be387e832eb79c6f08b813ba70869543989b684a69c52f43695e5f5c9402b40cac020102200a41bc2e2d93f6bae5badd02301c07dd3a6784f135527e9d16879236d79ac70220947a1761f15348838d05c1129b968458d493a97efcf5bd3dccc8d4c0001105330001012004d4acf64013ddf4cd81674e30ac570f8dff91a4cc20615d9abdae6142e03c4920c81c30300604f51d47aaa31eac9cbd76a108f06a7de5f65c4f683dde0b8872e4000106416c696365310200010e000100020003000400050006000700000200010320d8386ae6728b11f3d5a3fa4a6db084a8ea091c55138dec3c5d9ccdf679881923004040fff9aa80d491fe5e9e408af3bae2b881b8f6b5bb7b4e21311cad81531ed292dabce62de3973448980eece956e783534538317ec4ebc79a19a8105300a7814304010220367e9cf48c4915ebf75587ff1a325e4b624e52414b76a4eebeaa3cd0841e050920eb563f55107431cce78742a06fcf404e1a042d7e4d08db231945cde753a11ace00010120e83b570fd681c589c17d9faa103b7893551e456ea98952e1c5dca46e2481871d2006731f85b50fa84eb15777cbd8196c2b8ad5e09cc96b1078d5d2591d1bd83f08000103426f620200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040d8d628096b183064a9402c872644410c46a38ec2e88cf9bbcf4ed528e7c38247a89e6e0984c27026823b8380d07ae8ebe53014bfb7e0cb472fff6f0cd85f4500000001022089e5022949e5509def9e01d05d3144d7f6851c010b1e169aed28765ac3bfee34000001012071e0a4f8c4db2afa4be41f5138b6b233a47afc842db4032261724e6d1b4e97032021ee8cb3e240998b27d56a372bd6efdeca22b181921ab73fb0d76ed653030d07000106416c696365340200010e0001000200030004000500060007000002000103208fb2e77866b7da98988328b263d179ad51c3b7a75d21993d3c422e6d5468e1130040407d6190d22c0a19d8414ebf0ba1ac3feeb11ee79e668add145c581217b8cec8bdaa57d124aea6cc0ade1d9580c0d2379787ad8cb87da0a322c7a7adbc1b7e0c080102207bbb123093071c221f6070d1323f300954a5c7cfe9ff464dcd269918c35eac3c206998eceb2d30e80d0bb4de03a650205aba1126f46625537dceb2f4f9caaf711f0001012090120dda8e0c2ad381a610ac02ce5461766495a175259e0306bee1844211ee3020276eb7ba4ce3b150339d4123f970a379337b1edce0aeef05a8fdb94716470dd8000106416c696365350200010e000100020003000400050006000700000200010320486d6ee512447980a239037aefcfc3182ab3b7fe63306997fb7720e7e765cb4a004040a8061b5c7d704d1eb65f8e3c702be37165c3d0f6dddc6ca7ab0785378da0764830f931c8b0581d5300f2d4bd2dddc4b4f37f5ed97c679a31a08025b28dab11030102200633a86d5b63f670a5068a0800cf57175fc61e109d9473530b6c342e17f55d6420c086d15ebd8e850dec99cc74b6a965430b7b014de0dc17ef6da37dcfb7b6746e000101201aa279b68c729da5bf66fd7ababb757d50176d754d334758ab2e5b5cf943836220591d7b49b509f89edb3d41cad3970640da5884db09e205f1c6e66b24d6f3bc79000106416c696365360200010e000100020003000400050006000700000200010320d29c8b0688f415c62a225b46ffdb863e0edd97a7dcffac53bb71ed1147d60b0f004040b30b58e3980061662054632d5afc2573b94c672c223e8ef89822917b62ed0ceb953083264be15e99ceef6c5c41df092069e0b379d26e51bda1dbcfe8f800ae03010220b8bd92623af578123901b2dfb4bdc794f2c93bf877654dd332051c18b025081e20a6e62204372162ee7506111a24f77117b471d116f92c98ca22f31a5190ef7a0b0001012019eb7801ab691ccdc9b3efd2b09ae7d114d3eeb6738b234ffe89a05530919e7820028ce730cb32e02790d43f2d1e13d040866f51ca932085f8ad1ac15e6c3fdb19000106416c696365370200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040fdfe77d794bb42e5003804651dea5799fb5a9ab7cccb3d120f240a0c0bd4727dd4ecf501e71ecae4b761107f19c83b665d27daf5223ed6d54195073038598a01", ["022119f269a108fce04adac5d5064616b6603cf6433e8744e9d8efd5dcad5c2a", "24373b69b598f82099ce9480ee939f54862dfd9de472369cee4efee71955fe01", "3d33c3ad75256ec7e6077f5c4f40adcac2cca083e438748ecb11fd794dc6a002", "45c1eb06e1324aeaf1ed06678c4cc54e629c41711ef4626a6afff0ec587979c9", "37be7fce3a61f04de0d9bc9ec74e933f127b2f2599d9462d652b666052c8a87c", "545e80f85c7c1daf3cbbb360a8ca4689ce5bd643d9d2b327807498f73050b0e4", "caf009ad02a57a48feb8d64d055509e9a81edba8d325e442cfe75e006a520006", "4e3c8730e027b1e516c88099c727c04ff85d95638518dbe393535a39b34752e1", "c330e5d3e5bf0e07baf12477c643ab14063fbad42fb90688cfffded5866e6159", "18ff40894cec5623fee9d95c949ca66b85ef195c005dfbf1d54487eda650f045", "718bd1082f5366a6845f2f10d96e5ea21f5c993ccfe2962658f5399bee941f64", "812d4a177c8fd1723fdc530fb98a4521fcb7ef27dd49937eb064e7dfcc9d237c", "10e674ab640ddca3b0c9278d749a4dbd01846d3c38ff1d04a291417cf364dfbe", "6c55b03c808493d8c5846e0965aafbf1f4d09556300caf508eae81e63940e735", "87818ce40b5325a9e6a7fdb658af41655d3a19235ef5fe6a17be19aba461dfc0"], [[0U], [1U], [2U], [3U], [4U], [4U], [], [7U], [8U], [9U], [10U], [11U], [12U], [13U], [14U]]),
    (1U, "608e2321c05d16c26b3593cd99c7321485d833ded71203421cbf947442415cac", "42b30101208d1dd2816f2cc2c97ca4e8005cce4e552bc6ba2e50ff73ae0805e9ffa68b192420dc57620f7df6152094a66d59ab70716494affeb674e3ec600b6e746273f7d8a2000105416c6963650200010e000100020003000400050006000700000200010320ef5fbc1db54e9cd68a6d3b55707b4c3d6d4803a2d43ef2f5722b353c47b8825c00404062f6af93f185eacd007b075b209cda7e333a1cc543f3b79803e6fb81298ea7e6dadaaac385a4c5ea168ce4bc2dd4131cf2ee30f42849eef0c9f3df252c048e05010220658b69c8918806a3fe8c9a79babb36be97bd8fb9a63238a80f91df5d575f7d4d203cf6130ad801a359a7ad732e891777be6d5d8fb32442e45994c2d86a70ca07c000010120d5f517b310b572013d4d4ff2ddaaed68248f2f773de6c10be6dc45097ed23b5b20511208f93b7c657c4270ea07c7bf3caf9efb6c23fece108f77f6b40e961b3af4000106416c696365310200010e0001000200030004000500060007000002000103207ce752e5ea5d3252a574c3312b6d7d89173ab58354e52d97de22f12bcf851839004040cff5bdd69ec51be2b1bd4bd308feecd893f0a139cdf1629a7b652e5c1f3a908fe353269074954fbfd45aebc4447321a374aebd5bcc714bbab97807d84e4a2808010220ac90b1f3e03be2bb5ace32297b532520feb5210cc1d3bbfd8e76580cf176d977000001012045263f4d5d04fcb966e45baecf7f744e55297617a31e89b93ec4a98bc041d60c206dd4a5490e10245413519676a3897c46bd48253f6964ce55b7a90a20e8aa1d20000106416c696365320200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd1004040dea79ba455efc4f2c90a076d38bf6dda45071f3f1d5ac73f9e10c21569b2d12be60a551db99f7eb66250a02e16b2807528a7105fa29ee830174b81fa46b7c202", ["2126c0181d483b64cfae0bce17bde3db5f88fd91af2a44aa57b655546ae99807", "95fe502443b67fbf474c1cb3dc1591c03ce8166f5e2080b3aa75a540eeeb657e", "5ee9648fba7f3aae544ddf0b50d763d8d8cea92dbd713045b83df589f170be39", "424f912737c71d21a0d445ca7030e89ea010d698218009b0c0a57fa4680cb94d", "5f806297dae3d18fe6b49c2d564cc89d69e72ecfaf01d9289e379067efd793b0", "7a2640747a4fcd9feb82135ff1eec19a8ad407fc345ae36e8f9ee8febfe8bd01", "caf009ad02a57a48feb8d64d055509e9a81edba8d325e442cfe75e006a520006"], [[0U], [1U], [2U], [3U], [4U], [4U], []]),
    (1U, "6a392c78040481c511f148c938ee720753eacc7f4d75bbe8825cdeda22a1538f", "44cf01012040770c42704bf588ca5ceb2202f8656ab25e8f771cabeb4a8ac9b9126166cf6420cdcac2426ef81f34173fc99a5db8f4d776f217616744dcc5c6670df1ef920c06000105416c6963650200010e0001000200030004000500060007000002000103202e936e9568e3ed759c51b8f1f8df3686b17b3466a1bd6f56302bc6a07f23fb74004040d147d919775d2a63e7dc7c9536cda72f300590f54c1224082cf118e83a090b5293e7eead620eb59105faf4a395dfe584d5908aeeb5f62ed56ce4d069127e43000102200f51ac68bb438251a878d258e3281f6f6624d692161b0e2e73ffb1358a7fe81b201b67697fb0f36fe4ed5991fb21688b82fde43ba114bfe0c38dfc32bd3b9ede3800010120245e24aa2e2b648f303d4a0e2679747e24c2ffdb9efaa77479ab7b038978805a20a7068ffdbe5b3f3e6af4472871c32fe6fd967a706b337b11349b285c7146a7dd000106416c696365310200010e0001000200030004000500060007000002000103202797f62124c8779e21425e38aa13c82ce998682fd94d62d0f8e7d037e70c4aec004040a7c4faa1240be0fb57e580015ae8c9f6c4c7936e4b8efc9c3d1eefa7862c0e7ec6804497daf0e760495ec585c8182f1c1a765ec7ccfbc7363884cb2c0291cc04010220886dfc4d51cccadbffe4846e1d9ab2334070743ba17ca97ba1ba78d0589b545020198f520a593b71b99441728f91a6ad59b1c372dbdc092db4ab99888f7a73d9d200010120bc97937b32d7a3d5298117820cc65ba9b45a0a218f259c0d58728288049fc416207047be6b7145c6645d1460fb1595fe2aa458617994ff8c8f83163cb90d331864000106416c696365320200010e0001000200030004000500060007000002000103207d9b2651b699a24d05e0611005c19bb5f694c30946a4316d2a6dfc6f3588c33700404032e7362f6e20e847b0da883f1cc9a23cf40eb8f2508fa1db4fa74d3c914aedcb71e28a818dc799164d5898ce2a3c470664a148b268d177abeed97db6e18cc301010220874523b7d553a4af0c32b5d2d420becd1a35074d7a58f6850cb04bfd7fea216e207bececf607467199259df0210545e9f965ee6a40b5554b5658de59ccfd491d30000101204522af4e0e20ea7015553c99aecad36258e2c2456e927800248ec04fbb94703820059d25ef18acbf6cccc7edbd81fabd2561951391c94edbbba368871e1aeb337a000106416c696365330200010e0001000200030004000500060007000002000103201147f26b91626e7f8ed71e72d91d9bd330a452054ded1af8312d22e7b57eafff004040778802ce4b7f83cd38ce53998f9e8b24ffa356073aa020ab447d1c383d6ca7e96872656fcd216ecda789fef5d6b84bf39aca5a1ca0d9288dd7de71e9e220440301022084dd341f6d19367d90f17ac23075fbd14eb05c21f77c3fe2ca1880cc42a65b1800000101201a479fcb0fbbc28fb4f2f50891e1909d4094212b1e7acf71c681b5b62287245a20775c086c9bc3db06ed13a754eb6dcd81cedc016d0cd9bd3f6e463398b51b1e2a000106416c696365340200010e00010002000300040005000600070000020001010000000063f31e410000000065d45fd100404047ef29f23ceec0ad318757e8510d45817fa68d81c3403c3966a4f1a1bfc8c1409a8d75c7fa96addee3ca37b9e5174f0216fdd151ceaa022b5f6143930382a409", ["4fcddc57811c52b9bca222cdb6632ee94b151c099a7e191e370b3901bc7e0b02", "568aa789ea2044bc012f9c8eb6ef04da2fb1e35799f45837bbeef32ba8cb4d98", "08f4b3c6666767ff369411d6a0c305947fbea4f3ad684f8a156346dcd6e0c6bc", "c8ed3d1ef95d6f38fb525007d24cb2c20f8e54900f6be73fd450a4ab2b18a15c", "875f73417280d5f11a6774211fcbdcd27d85393055fb909a110a226f1dc396a7", "f9f82f12819457a708e1a2e835e1a6f8c75b5e15dda3f776fe713ae43faa812e", "524dd899b300064f46cebd44822c3a0336ac54f1b7c4717df1a94ed400963a07", "f6a1979083cbc20f9f91a9f50f47cd7a827ea632f62f7e7d7265e7945c66d5ca", "a87098730accca56fc33783cea9add754973584c78e2252c72d30086f55d010a", "0d1e35ff323dba84a91f7a6cea422563b06e71fcfd3dc953bb92ad34ecfcf37d", "ea6e7853f72eb44390df9514313d5753a16d24b4d1373869cb216fdf842f4a9a", "96559d37268b4428a5f85c9e2dffac9182cd0763dd1c5f6dd5c88eb99d4e6299", "e60ebf55a5a8fbb03d7a6a71d47df51d046d32dfbae05736d770b6a9ce940f2c", "e1e748fe15697209f904df9fca22f5ef104f2b776ffd424c800aea347a540dd3", "7fa35246a9a54288f26e442772cfa64c9f7ebab42ebeb24b4dd762f39aa5092e"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U], [7U], [8U], [8U], [], [8U], [], [], []]),
    (3U, "23de91f8b3dbcc9c9990aa57f58aff398d5ebda1936f29804fb968d6c95775b3", "41a5010120479f9378d9fbf70dc077425236ae4128b4cafaf328e35587d3a69e6b703d2b30203d62d4b3dbebeff91567e461f3f45a8b0c3f93cde8837ae2fa423ee86386794f000105416c6963650200010e00010002000300040005000600070000020001032022013a2a1d6fd57345527f0dbb0e17816068ece5fdd68e9e54dde7be277f7b910040405c26ca52a7c23ddd54cfdf4a5fca901dd5df0303e3a4a13158bec89e51edee02508b46bd5ab7d8f25c2c95a254c1a3af620b475e93bf3ae26218838a210dd3010102205546302219ec8e0078d18a3cbb6c73eaac15f2a8725b451bef99171cad25762d0000010120ac75db302b66ddadf23f6ba3e3d6f7cd75678206bfcf60c9d4f1291709f2030d20f62bb285d02488f2963c2b6ed5ba9dedf3812e49884ce73c9eff40b79a46386b000106416c696365310200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd20040404301c34b2ff0a53d2723617d60dec750fb70caf02bb888cbad16900cffe57d9ae6aac3c7bda991b8bdd9daf845fd8c7ba753855da7823fb42d89c894fd99ed05", ["46ba1dd807e33e89e8cf618d5e104fbdcc155001aa98df4234b760c5de541598", "f51b37d8b18f4f04537f7d13e04dfff24b5a962028e190d0de7bc1fa9ee2bf38", "b15d3fef1a2673e09c0d2e4a4a95617cbc7e2412ab9cfd1b493b6a9647713568"], [[0U], [1U], [2U]]),
    (3U, "b0ab2af2502ff68d0aadf9991f92193594cd8474bb369bf7ad732e44f3cefe04", "43c1010120067f870adaf43e2ebdd3dab23563353d35152c9eeed6e560a09ea30e74f00e5b20f6d929d10bd577fafb92d123701a30b67fa33c2db0d85ecc47ce53262bcbb9fc000105416c6963650200010e0001000200030004000500060007000002000103207dcabe89a0832fdffab1b7305d4470bab48c1aa7731e43f92ff323b6db1d38e900404032f4ee4c2a6a2a050a5f10ed1ac49beee99d663343ca80abb7c1ea1cea5018235a880016161e630c4263d221cc13a4bf0c93f9cbcc41ccd6537b415e51a2540b010220e036324a7499763639e1655619fde55bf503b8db7fa8b0fa488ab6c4a12ecd5520cda913ca53ceec4f133bd54f8256a289354c7f9e0c7ed0b63f107bc48ea6c97700010120d756105a5c910feab75eae120681811f084894b6ecbce6901f27c427afc9623620423326c9a81e656f6544be9b22eba06b89f1d30e769df6a3ddd01e12b9edfe56000106416c696365310200010e000100020003000400050006000700000200010320bbfdbbe69ff2a8b752aa58d4b4cdca12b6ffb65fac9d584245ed6062f9ec007f004040c713ed3e17e7507380a013978f426c348e385f5bb177b2609a2e146ffeb69451b2c6037688cd6be1e21683b315e1a1c57e66675fea938bb349a0739c54a30c0b010220d655c5edff93998a075c03f646aff898856ba4f0371d9d00899b5d5b09fbdd6900000101202e2206342a600fdf41b9d6305855c2da47b2a256e277a495c86dfa812c0d0f1b20a00f3e1d082464341dcc58787de6140b01ebfb0671973dbc61fc50945fb16be4000106416c696365320200010e000100020003000400050006000700000200010320d02c069931f402df21f574e3b787cf2bec23229d8173d3af804acb3be87cb47e00404007259d2f80f42d7c789848d5fcc5fe3eaf12537b0580921fd244440deff82e5a492c2c1629c898131adf90dabf7ede092665129567fa7c9ee4522dcbf45cf20b01022079ac1961bc5121ddaaa86b03e7ad5e4199c6fb09c92644d804e7f3197b2bbd3a2011d3971cd36fc9a8d976c3521465a73e69feecc0d78c48a782da6bebcabee3b40001012083f393cc28511b2c0daea046e0361ff7b63e4c32e696e526bb2c093136d2971220385859daa6f0b6e70afadf3c78cc81970e71e49589b82b565fb4ed2443022182000106416c696365330200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd2004040e5f662e8c38f79462057dcbdf675a0060851318775bd477d824c7c5e3046f5e70b4b722ac369adfa2c8ff08f9d192a251e80308a50519a7572178d6d14729a0a", ["fb7c3cf2712a97f328851430375231ad85b08d3dccd55ece8309c325e408b0b1", "71bcf44b823e82ab27a30f3fc0c24f9552ff4af601b495f4b53e8b63df74da06", "59106c4d33e378f9e2a5fdb15bef429ba872d021e44bee813b161776ba1fc97f", "a0597c61f80ef1a5138b42d7470f00ba6bd8a90ba694451fbad32f6d91d5de1f", "57831fe7a6fff7300d6c08354d961db346526424bf59304620629992880b85cf", "40334970988d77b572966572ac32c51f984e92c72ac7c8e8eb1831e0111f7c53", "fe0b68e7226b96263024839550052431347c4ea95491e929514dca357d0cc5b0"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U]]),
    (3U, "6f0a346a6de6df6da9fdab1727e47ebe3d168a9ce50b9ea000e0bd5053a104ef", "47f9010120cb53a1c70961fe0d8e3a6f4662f321cd48b7944643aab8f04af4c8f970aee23a20ff04031ab033dc53c342e398df1fd3e9ed75940cbd87362c4d93fb9c56cf8774000105416c6963650200010e000100020003000400050006000700000200010320dc3df2d7d534433f3a8bb74b6fbb0f1015232a6ee00c9de02350a41b1376edc90040401efce06530c7168cdbbef3e7cda28f2a8df3a0eeb5caef077eb76f15165df91ff1df3adb7cea90c9b6b69a948330a70eec946a2590f8b89951a5f2f7d2ef200d010220d1a12d34c196bd7fe2c9b45835f3aa74216e0ff02e1e561db175144a7be93211202cf843fe4c5e5f2a8cd7c6939e0b2bb3f5a2bc39dcfbb4e5d75fd7bae6930ab40001012011f85b13d2e4254c48710288f507439734ead1ac4d8ca068abb0f8e22d6b7a3b2078595d8029d1686b85e972719e262fa26f6022b17bb60045b3b6b8f750c634ec000106416c696365310200010e000100020003000400050006000700000200010320c5f98bca941b3726c68b4224ff4c5de3602bcd52d35e8474300bf694ca1128ec00404021b580d3ea5db08da724c9916a4653f2debbdaf9e21a25c882be28a0d079e9e82552f75c7ad8815de25dd1720ffd54f591326790d709520d5b4b7d020574420f01022027a97df28313697248236acb240c00b2a1e122597ca3d1491da951096b3e185e2014706affbd158d83997d2b4550d8b2aa060ff68b96d153d187ee3d5dfbb47b2b00010120830449575f5e769fda38cd4639537d7d42280f1d2bcc64058a56cda96d1a541220a11eeccfe83c847fbe8b446e66dfa6fdca04a443530377442efc2fe6abf22322000106416c696365320200010e0001000200030004000500060007000002000103200b95f8571c450a5b6ecd8387b3f024df38f2a32f172251d82add2b16958b63a90040409c8cb293d680b0d6ac0a2870f6e38c10da4a68804ca00b603c0109e9e5e830fe582ee9d55fb6c43e9e2278143881c2d605ba58ceb3f3339459fcbfc0c50f4d07010220d619db922878d3d64c79b6cf8267c3244f5bbe9ab86d4f6b88b96ac643cc4163208941e7120db31b301a5f62bfdfc83a5447ee95650f887865fc34e996d491f5b400010120ebb7e610cfbdd6e08a4761a7741c6936ec838691757458a38d0d605537318d1320289c917ef5740d230a5aa987851f9fce13255ef8872000eb7b83d046b1377c8f000106416c696365330200010e0001000200030004000500060007000002000103204cb61cb1877e2b2259c2f769c296d6196e0ce7a632e4af1712e07be45e93ee41004040013ac16385ca83722f85d4b906d94d7d3b78962aec88bb26c765fa4a8ae08b6e234c1ba45c335720619bc11c9425682510ac644ee40c5c7f0c804b6cb146f505010220a61acbafd0f4325b0f3728598fa8e333473cd1666849e25f164c93002d9b746d0000010120e53b9dda19a3e1357394a060029d1e10c2df780df31d320189b680ab71f2fd7a2047a0f40db39563750f69459d9c9896672701b888692a42820b240c02d69b4e6b000106416c696365340200010e000100020003000400050006000700000200010320d3049f55dbbdf9ff7e446e63caa30d7330a2626df6f752c4ee3523ca4d863108004040746eab17259aba4da98b65d2bebe6f62b5d6d17924ff00191b65c04168bbe65a54a175f5958f72c39331cb9ae2ed4e7e84451c81e93a18c73e1cdf7ed5a44b0101022020ec0ea88844945b9cd40bbd73aab25fd9cad61f6e7bc46034686396941ebf4220db23c799fb840da82fabf2deebf8d102efe6ec94ea4759cdd8feccb0e193e0d500010120975064b35c059382867d9981bfec0d4d01d2ea19d56b6f410e537186c180b16720f88f2c0137f8a6c17c0f458425dd4f7b0e3941fc55d7f68a582da74605316707000106416c696365350200010e0001000200030004000500060007000002000103209ac65b92e41bc59f1e48c5080c6264a59ae6f669eb0c4ba05617b855d41861a1004040a6c324f01d68fc969a4d74f5af6304af69df4d8ccf631570e7104fd1791c602af5296ddc76c242c34f50e59ffdab73c59841f63a89cf75dea56d07e0cf77050901022048292e93cfa2d533f652caeae2df87be20c48ebd477670c035268839de2280722098eb7faec171795758e14e1fca8b08ccb4730d1953810e5ee4e24df7df1179c80001012024f628cd65eb06ac3b5f6b1bbe0ba26974db84e2c68ee61b85c212f156342c4f2087e0b9734a6433242d021f5ea3981f85ccc42ccc898e4ae64c9967469e49100e000106416c696365360200010e0001000200030004000500060007000002000103202ca193829a0762d7dbb5edc03dc76335bf2c42415d2df7e2fca2465a711592db0040403a163615ec0cdbd9151879c7e8b8757185d200620b0c582f0b5ab6ae4c56978a01dc8245811ca1c73fbe73dbea36685154dc06926ad071c88d6cbbac8889820e010220860a8657a021c8886da88c84effce39a35089b20f10a2341b63821b03c45795f20368f61a0bf681fd1208df2e78103f9be11d87d5741b173ddf454e92bdb1f837b00010120a0ab2819a44e589ebdbf3f3f280e415063d86cd4efed62f479c29ed35c59935920636dbb7b9700497baa44d8f8a24267be8068f3e4e0df7ebf82dce73dbca2cfc6000106416c696365370200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd200404032846f27bbaee849a28e5161bebef285ba2d809dc2d808a6bb48e0a4d49bcb1679c9163e682371306479eb00fdb72d5bb3ba9276f6d8d69bea11fb83371c5c00", ["160b401dd15e53ccde33518b5d94826472941cf8fe3a573e7e4867b9a4ca6d0a", "f6b2a420614b5ef8a1ae07b726f7d26fc9b7dd5a375b9c57899e86a7afc6211f", "b56cf2040cace46634a3387abfdfe6def7c84f65c50e795af34067d763f25e91", "3e39efb994cb4444b64081a01984a28efab821c1b5759f09ba365c6253694d8c", "0f8481d4797d7a602878251478dd687a32d728925513953337a9c4dc8ef954a5", "6800cb5cdd93a0193774f05c9e2e60a5788156d6ebff30ed08f0707ee6027a92", "31cba7cd6f645957c6db38b7b863c989d563a072b8209fd13232ac2e08e58f20", "bd255dcccd576cafd078dfbf48168bdf6c265eaf3940be47c6f0c5432bb269b6", "53c6af7ef42925f509e363779bb060b55b5f0cbe31199f444a214756bde7e48f", "fdd2093097aa1b934e323a1e0ee3b53159b0051e2c16336f24146c1538be51b6", "b6cbe2257937fd241d4c4dffa56da03e8238300fa647b86b6c28f30e3d79105a", "7166325772d4e76c2a1b9be3813bc3298f24f4196d8090606e7865a9e2ee0b4f", "ab546e2ab6a3d943deb6084f25b281251d5f3274e90d8da98dddc7bf2689517e", "8a2e290e6539e70cd3a184fc2bf1155f6be125e5e9f8bd57394fd99e3b08f0e0", "17a0fab7a0218efc83f306faff6d81f5c58fb63dbaeec25f4725839b39d27ae2"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U], [7U], [8U], [9U], [10U], [11U], [12U], [13U], [14U]]),
    (3U, "7ed32e544df3bf97c0503815660b3da1170d0f7ebfbb7296fa586f27d68d890d", "46d901012005cbe3d13ff415ebf763c02ca59e8f413e55ee0c2f85c4cb7bdc5e6f192dcf422036ca6d295b2b18c9126859ebd1e4f8480446e547826661ba21d417cae1cdaf9d000105416c6963650200010e0001000200030004000500060007000002000103202b5d6bbd873751a1d3d10536d3aebce68830c53362d7b9dac76cc28c618a0e9c004040e815d3de068601f850a4462c4d9f2742fb75f68bf521f3552d587cf5ca932b80248f22df6c724d0a1525b5180bb08d98c8ba4098c612cc83e39090557e30aa05010220843e16ef7804c11845dce990844dde94e7694ebd21da4e63ae11ca760caa002e2078c4c6cc6d335fc3a2ba9fec567b56ab7819cdc077a982687bb7e3324ba0523100010120ac9f85f7e907982d5dc91bb23aea173c4decb7b723370f7831515df288e4d8192005dc3881dbe9d3c8b3442db56ad9fbf9505520f96f7e53d5d6e60e32e8c4b054000106416c696365310200010e00010002000300040005000600070000020001032008d4f78fc84e16e58642abd093c5f91bc0f618eab6c78a6e583159bbf21c2d3000404085c8605092f780953ff7581a198c8050cf62d2d434dea232d7864bdedf51f7d9b60a01113b773333954e813479b258079c2a8e7b14991527c2ff9f10d388ca02010220fa884b5de8abbd54bbb8233d12725f4d8e85927780b7da08f272f2befae1a509209ed28a2056e89b8fa60226cd0044242b8efaa924f43753c1089ed083044e7ff900010120a8e0fa402d293b89e702f31f215dcf9139cc750262202ec1dc0836bed9fcf713201872f6485bf628ea9cd7e254b67a74b6f975bf8c941512c20ec961595a931083000103426f620200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd200404045376a443b582dcbd5789947b38ffe936bd44549e77868caa22835e43d9d1eca90856a995f723c048b6087dde61944b6e2a91d1c143b66efa24904b17796980400000102206e34062ad53869e6723b4e088501a19529e5d1b92123502daeee4d187afc081000000101208d313b7cb4ddcb81aa674199f831ee837ef2031d69d217bb8871f726e9c92f3e20c6f1bd659ebbb5773c30a957f310d720b586335b4db1be9dc593d40642ab87ed000106416c696365340200010e000100020003000400050006000700000200010320beb50d74c25fe5b2585dbe749db8ae6fedf2aed100f51cf23dc9a3b517b10f4b00404032bf3f60d5225d8342560622899891de93d56286f6bd6d6cc1ec6d3203552b346632d4a48071271fd4dfbfd2e811c154dbd7fbbb654ed03ad83da6b2683b8608010220a91ab467c63cff48ec79abb7ae2e222e894c462112b4682a6e78177a6d5a3e1d20610d620cf5aaa6b8a85bddd683ffd8a7032e8399e0674ac5805ac4948a2cd218000101203af5b767f9ca4d519761d359259bf807b1377e0a24c989413d9c12d8c29770042054c17a02cf0b973265f7b971cd5446255e7cc1c9aed19813d19c8cd3730f0617000106416c696365350200010e000100020003000400050006000700000200010320e62b879060fcadfcd4aef95599c1b2d12e5306f586f1e8cded4e7bf21b484afe00404092b8337c09b03f5f4adae7bb57c0ee69744af0862d1a50ff09d6092a2f9e2f72b902b9a015ea3c3b2c55c88e0a2ab7d30543c62f7427682b79d13e583174d809010220bd4a441ee4ea4fe33bfbfdb2f72bcb2fbfced52cbc8986c697ca989bab1e3b47206caa86b98ff9d4385eafe1b61ae426b83d20cefbc4ef711c8788b6cdf98b76820001012003da78b708a466a9c5138d0a59ca04e32ad22d017263d3ebacc0c10ff309a65820082194714e4ccefcb60b333dc51614e1bf52e7245f3950e6c351d440ec5065ed000106416c696365360200010e000100020003000400050006000700000200010320fb2b0c0b30a3a2886aa4ee6f4a4646919b3b108dc5c5de68e36916aaa5404cf600404056538e1f26c97c10e22d69872c659521608f9be4cccf0048c43097bf3e5a120dde01e3e081f2b61cd6c2fc83a2841a0f662ca15b101aa4a6842d5ce4db68fd06010220749dee13656656fddf02bcef9d82a4f40145ed61d97943e6d596f4f80ce4d264205df7eb9e3f40a1ddf0835e3348b7a248e383392a3924911f52f10c3e8224933d0001012017d552d65ea7248bfc8819bc0005fd58c22ab51bb49a6173ba667cd03d687a69204ef5644ba376507fc8cda2ef2ff72703b7367c435ed586b23da1f3ab86aa49bd000106416c696365370200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd20040401ba863791b92d5d2afaf52a0d92cf0eb7f00df65fa353aa7e9dde0028f99b895282434a8f98c4bbddd1387cbf803d562538d446664602d48dd7a30d813e1990d", ["f0bb6782f72df36901c1f0ca28c58d70dc0a70f3af29b9dbffb188273653e848", "e736f53f9b9ec524eca074333ec66e2d1f0cdd7511f0ddc1a86b5cf023f54e88", "f36dc73f76c7628b1e6277ef2d9181bdfe30e74a89e3051d79f8a34001ea0300", "ab9f983989b113ec149c8313a5755d2991b97e11228e28c8e813c5fd89666d74", "c3c2162a8def60d3ce11ee890e9464f63294c7f4f0a8f089a50ac6468bfb7258", "33c1ea0cdef4228b2744bb67421b5d491e8b8d9a38b225245fe19cf6e2509d85", "caf009ad02a57a48feb8d64d055509e9a81edba8d325e442cfe75e006a520006", "902432744545bdfb1921a72594afab671c6f562a597945d3255d069e376597cf", "11dbfa33e9c0da0147dc16519f85761a07b9b67a5d243a510292cf1f96132c12", "67e2002f9cf809d6c67c8692632e234737bbec8a06276964b8753c6b96a549b7", "2595b787f1d58919c175c0fcb2ca04a3661c7136e760f5b3d982a5434492c47b", "39ccacb5014acb8040662c80e7f28c0821dd0614c769275f22d1e01baabcde31", "f6c809806d2934267f9b9b3b8aa7551882e93874adb728fbfd6a9a5dc3518f34", "001823c6c3fd504a97edf8bcbef6ef9f55ba9caf1606f7fa91340dfc5bc30c88", "0d8c1ae2c18509caf94dedd28ccb7d6586d089bb9300ae28e3f472c995406fee"], [[0U], [1U], [2U], [3U], [4U], [4U], [], [7U], [8U], [9U], [10U], [11U], [12U], [13U], [14U]]),
    (3U, "29cd7188abe4db8c67751c6eb99b872e8c6801738f6b4a59c77f4c3384465622", "42b301012005963d63c82f9bc92908e960ba7c30f3d67f8d11f3d3ac7e3eda1412414e866a20ea4bf41e8db17b129b3d3638c15d9c2402190f63bf35261f48c742855671c793000105416c6963650200010e00010002000300040005000600070000020001032027f24ba0db033a3a6d4f17ac6f6eb1569aacbfd1b243bc95017fd3e5346862c100404004596fae35c968d416d60bb60425894f73b3189ab07177fd70259d06959cb75526012e882a39358fc522dc8fca297c6623cc4ce0f9f0c4940471ef3232bda7000102209a79de85479e8f7be09f0eec2bf28eb131b0918aabc443a3ae09c7fdd1bb365720dfe596c381fb93556e7f3f0e227c73686cc164bf498adb249702b5c2a88006f30001012045ae793725b01671192150d24d05262b8fcbee25a54fca0695d796a39e4fa130204bbcab97669f2a0ffabe789d2251dc5ecdaa4621fdeaa8f10a7b30e4239559ea000106416c696365310200010e00010002000300040005000600070000020001032087f99b31bcbc867a99e4be5b1f1006838c9f55440c43fdb0783527df65a8740d004040ce1e4b2849e3520ac507f7f5c4411ef595623139b5cb63627c7fe8050723aa98607161ca2257a6068ec721f41dc8587178206f23859450f1fc68b0a66539f30901022011744b5d38aefb3377b41c61948bee954798c2aa42a711945747acf99a3a583e0000010120636429108e2350476e59949d4de890483d4be0d2a9bb50809da64ec7add8bb3b203a1654dc33b026d944fdbc0d7ba7ba5329cf7f3ac94e0a143459648a8c04ba27000106416c696365320200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd200404011ca43f70d3a1c61be59a24b55da100fd40c3862ed4578fdb048cf96fad600fc9b79ef0bfba7ddd779ab87fe4f66ba3aefbc0373b0acf8b0c99329c03ab0ba03", ["ddee29cb8c294f0f8709a4f97eac9461c9f04d0c3b9459cb66e28beb75d86d37", "eeee73d4a1292af1e25407aaf648dfeb1ca7a36f707a1b2b6b57d56530dc5dcd", "46c55139b8705c84b51621a76b55dc00993915032d50de46732d5e891ba12d9d", "b3ef7478dc9d87d552be2154c557d8a3c7f8ad22a3f14365d6b7eb1972512f9c", "248a7cfe560a7a5af37e37dd689c1ff9afb57d057b4162656c5c8a3feae4a1ce", "f67d7ffab3e1c97a66c2e176d5382b2e373edf10f9b9864c0641209d191a24eb", "caf009ad02a57a48feb8d64d055509e9a81edba8d325e442cfe75e006a520006"], [[0U], [1U], [2U], [3U], [4U], [4U], []]),
    (3U, "59f2e7224b2469457bd17f7e7c5d7faf6c2715f0849d1382392f75143ba07e74", "44cf0101204f7b8c2abba6d3860e0ca518e771fbb9ca28e8abfb73a226258ad25bfdbce54e2002f387be8aeab40a3dde4ef633c7b7c92ef56dbbb77422a3cd7c07a0f3e55b5f000105416c6963650200010e0001000200030004000500060007000002000103207f0aa27f1c5d09fa007d03f2a566b562af749f0ade7aef54bffe3dd95caa662900404019221a16270c7f1492b8b12c221de23f71293bb95db07524018d8e678662b3205572fdca22852b80aa0a23b208e36f85db944a6d0883321a6194df9e3f19940d010220ede3b2b7790a3c4791a02819c75d92c3e5457479f10947cdef31f6988f15316c20215351bc73e0523deeeb52f67c2cf5af35b55356adb0b06edc08c29c7d0dccb900010120a95dadfc9721e4d64fe7a1231c7a924b04a8c778813d1591ff1fd1530cbe7a5f20e66f0a7f7b2c4d2cda8b9eba942bb857af386d8ea7dddff7daf1a1e6bf30b934000106416c696365310200010e000100020003000400050006000700000200010320cdad38b66c57d0f48dbbb920a17eb4dcb2f5f23550fc226b51e093ce4f53741800404079e82b49eec779562a4180c627a77d212167a44802537bbb71cb72f1b2c34c46dca7f287f5020539b7eb09471ad8e13c809b4be6b64dc05b367839c11846760701022044d0d4e9bbc017cdf02fa429d4bc3c95d561c2100914311f7177852a64c72e3620457039c3c2a73c56680c1febb9861f2931b0e390746c5d22e483c3e08294a8f4000101206fecbf73c4f69e9b993558fb76b4d81f55be71f71b86ed09df49a14ac3dd6b33204e0f12a693fbdcad2b17798eae6d5271c3085db6047f11ab9817581d293d9741000106416c696365320200010e0001000200030004000500060007000002000103205ff8d9c80160229cdadcd2915cbb7eaf640b02456619af4f021877e651fd044d004040060990d3dfc872430295aac6374c384a757aa732092307b5f1db558996614284a64cb298625fd8fc6dc1fa3d08ea2d895d260f4d0ec5f07879f07935214b240801022087d210d82ce5571fe65a58e3de7bb36a2def7402ccc33737f8b3fb4008d0790920b38a08910d5593cdfa50ca83f285f7ce49feaace9fb417d306346679c0fe8a13000101200cbf996f7220b525be3d2b6723c999ee3bef20c32ed778b87e7b5bada4ccf46120b277a996fc380becf45f34a9d682e3ca287603bc7af3f777ec93437c5051deff000106416c696365330200010e000100020003000400050006000700000200010320f51d318438e2eeacc25abdec1b4145b1d739f9f35de54f6f17b13a3c0eca05f8004040910ca4181263804ac6dd7e71430af47f7ffa5b5412d148acf602f61cd1e92dc8da0eee53f0c32d4c88ebd7145bf2511f3f70d4da606e11ba5ad7520e8ec1830d010220ab4de5ab6798e534322fee00f9eb36e6cd50b1ecbe54fb171dfcc718d9ba5425000001012053f9fe9f8106301dfa8ab45f142cc3e11595debde7e85eac153a70f5dd1f804b20c6f39bf7bfd13d9f595e3727e8e777ed6366acecfec79655c21e37acaca203f4000106416c696365340200010e00010002000300040005000600070000020001010000000063f31e420000000065d45fd20040405eba8a2f6aa1ea4fd276baa9e661e8af704a58fdbfd64fa5c0273adf12dc2f55da4096cd756e57a78b195536cdb9c0d4f3740ff3f62125b8ee9e390b5202ca0e", ["1f022093521a41daa58cbba9f85c2d4cb2aaa6ace5950d59b1f3478677fc11b7", "c9406bfce3545f1225d918df165ad74ff3d5ed3ddfd58a7bbcb83f9ba86a98d5", "1d6cfd6ac10e87f88e8da452f4665b89d4a11a9246034d3a3ecae1aaf713e7ee", "a027e36129bbbd989f80a7db87e067ea2e5741f7096de5687144ea3f492e7911", "a2de637b81dd2b85363c6341c344ae4595050917d9cd8d6d8d4e8b6f1a89563f", "6591835230dd41d3db1db665bd62f6735ee24b447b6ba2b7eec57d95d6269f96", "fb6f63117cf00abdfddd603bc3a5cbe73415fd1557b1dc85a7fdc5d36f397863", "1810130802797fc18f41555a517274a627407ea68e5f7ba2d6051a6cc823f706", "4f70277a31592419eeefa636dbba26749397ec97d2f170d9e953fd0039dd367a", "b2cfd780373d309e7c689e14e07e561f4d4092a42b79727995bd2da2934fb5c5", "ea6e7853f72eb44390df9514313d5753a16d24b4d1373869cb216fdf842f4a9a", "c900946515a4cdefa8122421c211b213746de5fe015e12e62a1b3ffc101cd5f6", "e60ebf55a5a8fbb03d7a6a71d47df51d046d32dfbae05736d770b6a9ce940f2c", "e1e748fe15697209f904df9fca22f5ef104f2b776ffd424c800aea347a540dd3", "7fa35246a9a54288f26e442772cfa64c9f7ebab42ebeb24b4dd762f39aa5092e"], [[0U], [1U], [2U], [3U], [4U], [5U], [6U], [7U], [8U], [8U], [], [8U], [], [], []]),
  ]
  for i = 0; i < tv_cases.length(); i = i + 1 {
    let (cs_id, gid_hex, tree_hex, exp_hashes, exp_res) = tv_cases[i]
    let cs = @cs.CipherSuite::from_id(cs_id)
    let gid = vec_hex(gid_hex)
    let tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex(tree_hex)))
    tree.validate_tree_structure()
    tree.validate_parent_hashes(cs)
    tree.validate_leaf_signatures(cs, gid)
    let n_nodes = tree.n_nodes()
    assert_eq(n_nodes.reinterpret_as_int(), exp_hashes.length())
    assert_eq(n_nodes.reinterpret_as_int(), exp_res.length())
    for n = 0U; n < n_nodes; n = n + 1U {
      let ni = n.reinterpret_as_int()
      assert_eq(tree.node_hash(cs, n), vec_hex(exp_hashes[ni]))
      assert_eq(tree.resolution(n), exp_res[ni])
    }
  }
}

///|
test "IETF treekem.json CS1 & CS3 cross-package TreeKEM + schedule epoch derivation" {
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let group_id = vec_hex("476813a66a9e9a464c40e79f4f8449d939d9235c56ea955ba7e230ec6d7f6b03")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("41da010120c929637bda524adad04ac85cf8ab7164d9cd88139aef5c9f7157902707c3fb5820c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c000100020003000400050006000004000100020320be6b0e33b576ab16727c86317eee6b8bbc20b641440f1f55ed68a4861b6746f70040404007c2a631b8a394f6cb8704b1cbbe2e149241ca32f316ffc6f8a541521b0a298dc0239d0ec0e8ab77f3c39b5810da1815d3a83dd4797d0ea5a0488718b8af0201022029eb3645264612282039eb7ddb095a780f39b1904a9613aaad568642a4b9b2040000010120d17b7296c1ac920c635574c84ee59f11c43bf534f4135225dbf1ac360e4629092018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e866138390325d0200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040405ca8f99de58c59bc29c4d7b5bbc489ca7a62a8971d5944080940cf14d6795443a20cd96c290a67b59c28a53e9e9795ac9f21cbb257ca333e75e72e5582ca8e0f")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "7957e5368bbfe5dcfcce0cac8868d3d1943d7733f5c77ef582ee84ab6a281176", [(1U, "8313fdeaeb49196b0e35e38c37c9efcc1014380332a8c4c0783b13a4bc059f3b")]),
      (1U, "2a7ab9e8c1a8077944fa0f59303faf1d7da5ec43c7a3f345910c87478d12c202", [(1U, "8313fdeaeb49196b0e35e38c37c9efcc1014380332a8c4c0783b13a4bc059f3b")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c0001000200030004000500060000040001000203204ab91adcf7be9ea795042e1fd2d3c2021d3bdc7c0a767bb13b96f4b2b75b7188004040c42e9b322d874ac6f51b40fdad15f740ff99e85fa86c0c5da28dddcb9667403eb94e55bd34fd610be9308c86b3e881b1751649f15d34ede85689f59968116202407520875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220c8d8c0ec4526045cce5979e3cb3a2435322b20cb224073c1b00ef0deb336d50b30f7b94d151d792713a4814d0bc3219d627fe44c0f82258db4804ea79bda9c18027da4c9a4ef89cc703d70049104889432", "e90f531363f40f04a0e5207e4fcdad46fb9398ca2c208eee1c198ea3e73876c5", "5ccc25c82569cc9731283abbdb9265187c17503e6f9c4ba2484a9e210e83f5a3"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e1273322018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e866138390325d0200010c0001000200030004000500060000040001000203204bfc816b5eadff216e4e8b80b389fc7183268bce194d5ef5507df3d2de7e903b004040bd3e4e28c0ef9370a4b742f2c25268a2dba5b4f9d7c74f60d49a587464bf2d598a7e92ebc9ab8519d0ec0552e062e34f39b1ee8965b618c828aeceadb5e38c01407520947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220bd0dbd346f6cbc4dc55abf48b1a6088ecb3801ad4bc4562c56459b26fbcb104830eda5351c40df6d9c822b6c27a6626cdcb09daf1b90bd44d3d3bebe3130a0b31a22ad0d0a7689b5fd92c1b95f56ca8524", "ad926d28a9ceaa99e24f66d289098f87d52965f7c903804a833cfa0dfc0d711c", "4179fbbca043d7139726430d976a623eac87a9d18bfee7227f2c4d54c16d041e"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let group_id = vec_hex("e6b740d256274516247a96378b7a5def673d0a934cbc4be462f6904f2f21c57b")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("4302010120e54d0eac71c30f4918d9b69555d66970f2f97d13b1b21dd4448007ed0e3f37022063a5a3255c7f3cf9e358a1d65aac578527911a95d5c350f8d88c87fc2985743c000120272f5613d35fb97890a5753f75c1fd5b20eb18e38a12ee32a8d28efb43fa55380200010c000100020003000400050006000004000100020320d9c620523b20b562fc2cc9e9d739b96405dbcf11e4e3fccf5372c2214d7da4ca0040409c01980ca2672ec79c5ecb84f164a2832511d4df2d197e45ace01c45c474daf88cab25c471a8fe7718c71ccee81189e961e37bc7d9ec6b4dade0dbebe4ed9200010220d1eb73ab6bb8b043f10208539bf40e1db6633d4d2ccb9060078ccad5cc861604200d451ce0bda28eb79d23899525b86e056c56176f7ed8dc5b47d78368a327789e00010120293ec088a08f27c2b909a71f12dcbb2ae355a260345405dc062efcb611dbb87820ad43d6af950545ce6a6631985b2250c20ed04bfcef5fb4d13dcade9cd7f1647c0001207a1dc8703b9a8edecd26a9d4953caeb655699a5f2978aefa42f676e413a3aa130200010c000100020003000400050006000004000100020320162f66c5ff6c647e986a6b0f39858ce42996e41a27a8d2f44c386172ebf6961f0040407f6f22301bd02337844315b9090d375cfde9b9cd7573469a69394fd1ea211eecde201a54df890ad67aef4ea49ae79b97b6ac3cbcb7627e85e2f0b4a0399426060102200688dfd4795e2bbbce6b144077f2311a224635c371e1b3b77d88521390b26f48000001012013e4fc31c6ee339941282f3298aa8ff59604c115e92bd77bd3c49b3fa5c14a43209cae579ac72ba063ab633ea646912093fe3f5c95bf1873a85aec53de106d573a00012088a8c9f18271b261285aa5b78675cfbc6830e2acd056c667a568a118270026f40200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040331c7cd63ebcca3717a789fd9528cef191cbb91fb9dff9813cdbb59c7973b6b6f97002c6adc4d7887a57e9bc4b4aa4a37daf75ab75a6a9e8cd0bdf347ffdea0a")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "d4770149641bb1a5c0ffd9f557df68e4180952f959977e5556f240f1e1aad23c", [(1U, "63e805fe99eb66a41172f6112daab0a2aac147eb16695ae539a4bdbd004523fe"), (3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
      (1U, "8e344683c5650ccfc37ec1d02b74fb6d10559a7681bbbba0c78212313ae69e0b", [(1U, "63e805fe99eb66a41172f6112daab0a2aac147eb16695ae539a4bdbd004523fe"), (3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
      (2U, "bdf045e0a0d3ec655593616eecf26070512c06e8f180de277a979206d4e43383", [(3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d2063a5a3255c7f3cf9e358a1d65aac578527911a95d5c350f8d88c87fc2985743c000120272f5613d35fb97890a5753f75c1fd5b20eb18e38a12ee32a8d28efb43fa55380200010c00010002000300040005000600000400010002032081c6e894eecebb54b549c22114509dc6e18f25783e41214a41bfd650f999e89900404081a8e1468513724b0d29e92af277990df94e423cfc489d8edd0312f30b8549ece52fa334d19692d3f805c0082d66c2997746815f539ff555c00befbfac0fbf0140ea20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b144052207258f9822d7d7c9a1ddebe951d5ce1164b79a8c5acc9bd303fdc8bbfd35aec42300d747fa77976b483e23fbac60d3a75661b3739fd6c673a08977c174e59f305a41d36d1fb8ec950f30e4a8cb8c6f25df020e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b264052203df93139208aa194a4baa2583a6920ee12ccf44b372f57e2ed5f584a0a0bb40d309678a03ad48f2699e79cfb89cb74343c69a38c36d966838f654855afbd536a0f2e7e50670766dc5a741ba16945a5c4b5", "ca878f47a9c9dc41548f1abf08a5f28883c31b372f088a101b44ca3f35480257", "504766baf72d5ca7c9418c872a0e93387d717bb13f319e4953867cc50b57d676"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e12733220ad43d6af950545ce6a6631985b2250c20ed04bfcef5fb4d13dcade9cd7f1647c0001207a1dc8703b9a8edecd26a9d4953caeb655699a5f2978aefa42f676e413a3aa130200010c000100020003000400050006000004000100020320bc486af33db8d4c09b905e857cb0122409ed10b198603a2dbad598b0ed0daed500404063daa824b6e4c9dd256c959dce661f412c3d4163d35ca1ed660f1f26d7b8d4cbfeb187f6e4a38f9fa81f8ffc3079a94e9a7ccb91238cc451ea8f8506c9f35a0a40ea20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c3244052206d970a63bf74a8389adb208aec428058129e8ea1d7613d0f6d28ac591c402e2930e71bd12154b12f5c44252569711106adbe5a85a024cb27f40611e9388367f7eac0eac3e0e5a1bd157b4c17caa0c6617120474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a5664052207a7e692efca430f8e5bacc1d9e6f79a8325e44e4ea829f0ab5ba3a74d3aaba02307757b7c34373a2fd368db395fe66205c501541f543c440a76d867d8476942f83f1b8382be014465b6b10752fab5b6b80", "8f47f28dad256efca060bfa473064ae5ae62cc1a30b2411910c5029a6c4d7330", "0a8222278bb97717570dcbe645ca76266a1a6fbab32e2cd4420431e8611eed12"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d075209cae579ac72ba063ab633ea646912093fe3f5c95bf1873a85aec53de106d573a00012088a8c9f18271b261285aa5b78675cfbc6830e2acd056c667a568a118270026f40200010c0001000200030004000500060000040001000203209ec36399714355d8a97295d60f32aa6c2120706bd235c20641ef8ec6314751be004040854a79189e8701be7944713638a8d8bff90f18ab4b6b7034aca10ce2c4ce2f7b0db58f7ea7c46943df312bd91e7d749204b52beef5fb2db63b591571bd1ea70f407520e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f374052204b001dee9c4a120d0c636cc0cc17bb6e7788f5e523bc5cddd7b0549f28e85d6d30ede8bd9cc61bbfb92232de419a7c98885f9ab48f9af921817f234683a8bb75d85ccfc65c5e8d3702d57045a4ba93fb94", "485893698b0653aaf09945423a842250dc77680f4bbc0e0ac8f5369d0d6ca8c6", "31b55d9f7db7c7e5b7f1c91517029fb661d7379735b8aab5d942b8bb86af38d8"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let group_id = vec_hex("423be13e60cb792908d054f12016df0ef390bcaf997a30e655dabf08059cef79")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("442a0101204b9fd7d9003711f24f13deff295f7e4e0238d3ed29b96a2880bbeaa06d15f6702091db737bc3e86ae847df35c2654b3632004264912f371908614b8b5986d11dee000120b85b0261554e5caaee148aeb22b43c5bf88eef7e15f22536b1068c3431e983160200010c000100020003000400050006000004000100020320a97db37da3835b8451d0cda7fc18338b458f19ac308c87640fd86b1b32e5d191004040bf096e969de74303ac9ae863315a161cd185a4315db28afb3fb7fd4c79eecc49d1342e705f7cadc8cbd204572f76f35790ba9cc985297b326e2d5708d33fa90e010220e167835eefc396f5f55c2789a75c80795e825cd3cd581bfa6f46bd3631eafa5820b9f3a097c546c04bf444d5c4da3aaea2cdb00e567a9097a75826908a48ae34bb000101206f1d0912a1942172908d1353cc797ef87a1b3ee97ebc4bc9bf6733f0ec562f2f201d41f65e150494d0ed0d9aca90ed4fdb7812400db9aea37d60b7f6e1a1dc891f000120b0cbd2b52371b5ced80aa97e9be6f1e9ee39ba75bc7635ec7077c7102ca209370200010c000100020003000400050006000004000100020320901518595e4408057d3dd777a80a07d53d8501ded19cd61856ccf9256c11454f0040403cbc81498ce781b8d2d0e1f8d645825b510919a200777b44daa17602ce09537a89294800645266fc0c2c294b471da543a9d560177af50ce5dbda78a9fe98ba0001022069c2255e9f1c5e21bda11f97ac4364409556bd641b05d44f7ac2f167e4442b260000010120634e798bd04d4be0cedf312999ace36db4893bf235c5a936f4d310264f36d63020659b01cb9207c17b960a16e31bd7c38e4c7332555fe0078afb088e6df28208a00001202173cbb1727b754f15bdd8a299a3a859b5825c17dcdc6c2acb867d5c59c60c820200010c000100020003000400050006000004000100020320c1b4dda2e2e32d72106deac1b30c80f993979d7cb041b337c7e4067ee679d5c000404013b7831cb3341ee6f5d6554a5c5555401df06fc2208fe2c46734dff9eaa566432b63b2e6052267a1e6304891d6953f009221344dd385678999562be6b1616d05010220b2754eb2b1125754bc5d816e5387ecf547759c29b379840509995ad5ae3e464d201c0f40f85e82db7a3e4aabe9b99c33e79ee734e6a8b88e394945627ea87944c700010120d354b7afbe6c7db2d975595742faadd5ba68ee57108d33e7aec8220f81d6bb72208f63b381a3663b73b404173e9f0326b03964ec5b388312b87b5e46cc10c07c8300012012924cb0648c160903544e900240d09af8339df9bffb24f9837e18cfe01e0f960200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040403e33781a685d0f648b9ee27b81c69b825a0381895387405ed10710fa773f8db4262ab225b7716a2a502209e2908115f5fdb8a0905dfd937430e3fc933a4fb80b")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "d17cf59b3e7223b81b6eb3972540978a156df1df164b128c3fba621300e42a1f", [(1U, "a46b1af97fa9cb5fc60a462f58d084f2110906cdba7aa87a167382a76b532289"), (3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607")]),
      (1U, "fd0a2b613b0353968cc5af4dc8cc9fe5a54618e48401d0635fd9f6b14eee0620", [(1U, "a46b1af97fa9cb5fc60a462f58d084f2110906cdba7aa87a167382a76b532289"), (3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607")]),
      (2U, "51df04a380078fda6b55ff0b03e10cdc2c2456749def976e786da494debb8573", [(3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607"), (5U, "412edc724d5f6f1f2fb5d7e8b70a3806a8b310fc83b081478a982db6d52acd22")]),
      (3U, "821a3bf9c737f8dc82d9b29649d5aa0d20ecbaa0f8287774741a288bae295372", [(3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607"), (5U, "412edc724d5f6f1f2fb5d7e8b70a3806a8b310fc83b081478a982db6d52acd22")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d2091db737bc3e86ae847df35c2654b3632004264912f371908614b8b5986d11dee000120b85b0261554e5caaee148aeb22b43c5bf88eef7e15f22536b1068c3431e983160200010c000100020003000400050006000004000100020320e73dcde3e179f8089c4df28862e2cf414f82fd0fa5d334ff45b5a8cfd0048e4f0040406ab24761c38a79d5e833d6516606f4c3295e3a32de1dcd27221d81d60e98e44806d1611651766337ccaee5c6ff30e76c3e10610f7c589eeb0e631a8487ea870240ea20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b144052205f02862ffe8a1e9d0e19c1646cdbf75708407455b1b92224e41205e1481ee35130a6c9f0224ffac7160c19ab5dcdba042a8ff1878a59d26fbb016ef7d64a5c6b0ed3592e59a339521316e751697b9e91be20e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b26405220d639a44992172cfe12a30f9480dec62aa1686b1663eb31d0ec1f4c17c8bf446b308a0356f10c5376b6ccd65af01fe96cac05c91818169974f5faa5d5610e1bb09b81f16108cc66433e4904197988d7598a", "1fe40de697347712836f9957ea0bd58edf52ceac2bfbf098547f3d38d0209a70", "504766baf72d5ca7c9418c872a0e93387d717bb13f319e4953867cc50b57d676"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e127332201d41f65e150494d0ed0d9aca90ed4fdb7812400db9aea37d60b7f6e1a1dc891f000120b0cbd2b52371b5ced80aa97e9be6f1e9ee39ba75bc7635ec7077c7102ca209370200010c000100020003000400050006000004000100020320f3e607d83e4a4997e30b5703138ddb5ad71ea191363f99fa5dd930bb5beb040d0040406b1600a9f3bb2abb945a04fc9df4b66077acfca451d94957eaa0e1b9405511e3780260fa763e452163f0245e296f83079afdc5ed8525a3275d3bef4f65e0c60240ea20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220177960677c134dc9cdf4b5020999d2bd4580d5f65bcf5db93d12197a7cd8f94030b32d803f2cddfd209406b23a7aa3c5a8ed2b2ee2f069398a952894fd22d1f21b674886c6c29265c78d40d22d24d259f420474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a56640522079dfe5effa704eb97b3102c9728743146897918bf76c293e9c7aa0cad6a5743c304a98c652e0343d60fd7e34e6dc503ae4c0ea1825b46680846c42731dd78fcf23cc05e543eb8731aad1fc682290509963", "ba637d026eb01f2e76dbcc96c3d2fa935d1e87d300e7ed9f552d180058f78501", "0a8222278bb97717570dcbe645ca76266a1a6fbab32e2cd4420431e8611eed12"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d07520659b01cb9207c17b960a16e31bd7c38e4c7332555fe0078afb088e6df28208a00001202173cbb1727b754f15bdd8a299a3a859b5825c17dcdc6c2acb867d5c59c60c820200010c000100020003000400050006000004000100020320c01e220dea17dc3ce10b6bb2e7c5da2b2ee7cee9f7b5d14c087c6dfcd6847413004040127e3a0c442d8bbb3aabdd2fe7c52cf78afb8c3f3ef21f27d0426446b9bf3f9fcc05bb37b0e5c0084a82d85d2f5eb381bd979c96163f3931eedb4accdee5630240ea20e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f37405220ee5731299ae302c5154a99d124cec44cca100a207503bd13b04628660914782330b1af61ea5b38f3e2cd1b5cabe5ca0dc482ef30a8b8610ad85b505220deb4743ed31ffc722679a97091bfdc348d088ab2201aacca6cc8b6fc297d3ceb6a13fa80e8d6632ec60a852d7456f13d277d8f954a405220846d49a6e319247eca6d040608caa9ba5b922c142dd60ae1893072f4566d277a30926b0dbc7e2b385d32894c948b68097301c2ed1c466302f360af3458de326344b6838207cd537d023bff1ec672446f5b", "2b065d61a081a08bad0c264fd0acb42f2c7576559dd06d70abf489f5d82b35f2", "fcc016ff84f1dab6df10a1f1c1847187255d3dcba8b1d859a09d66eb40cd82dc"),
      (3U, "2019fb8ee8448730c556519f79f2b6f8b6e5f79156535e12d964a43f25709dbb27208f63b381a3663b73b404173e9f0326b03964ec5b388312b87b5e46cc10c07c8300012012924cb0648c160903544e900240d09af8339df9bffb24f9837e18cfe01e0f960200010c00010002000300040005000600000400010002032057b200689e4f8dbe40e47f29398412d65589579377e727292af8288a354aacb8004040d99d93505895cdfee5070316c5edad5cb345e46c15fd3bcc367557d9ab91ff75f427bf33df5fa04f53ee9c2d029a002ddcfb2730acd688c06f2fee9ab32daf0b40ea20d30c196bad209e989a37a7e0d05b2f165a6dd9a9064145aab85f52543845945b405220fd976830106eacc41ca78ffc50db0905d7e62168a95adbd5d32cb75e35f67066300ee0d24e45e242b555b0bb99f03750d2eeb732738b2f7da744cb1694e493f2e2a64f9b46a5e4d2d8f0d549528c2df06c206d5afad9c6f39964dc6e5087c30075e2c36f8f51c05bfdbad9f4a1e50992be38405220c1a015101204d307fea6ce4f1804f7d7619b216b750df82f74cedb85bfa0ed6e30ffe32a5c3cce40776d09c8903dc630ae9b5c78afde32b1a07ff6dfb9f0ba5c0205f532f649c00d32cddeca76adc301fc", "7655f9d9bb86ad7d509f3b14737508dcf7264ebaae24ee4067a8953e5be64ffe", "e91a12d86125a8d5acc0872133f1e289256c749698427abdcaeedf0139273688"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let group_id = vec_hex("e32626784d0f2067b8bb5005bb160d536bf666d9116ab532fa202009a1df4aed")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("4793010120cdc78e82d128e8cf4d1436b6a2085818a88dbfc764ae4405c4a05cc6c7072a5e20f3d556cd98ecd39b00b09f0f2ff6d7838b295045532e7b39ddf17306a48e7a0a0001201f2e3b192d5a46393f7bb45b50907b33588f0727cf130cef329b3a98b0704d280200010c000100020003000400050006000004000100020320ef5d06379e6995b358b6c3a9e78d53b4ea11f3b4f31d6be7598cf82eb01d31f70040409b87ae3e1f1f30008378bdf83a01b3b9690c5c13d2333b24c7c886ce76b194b55db2c1cea94deafef1fea98567d4b19698f66761228d2c1965dfd4ffebba0b070102207d58e18ebd4767c41c7c30f4f1b3cd1160fc3512a998e94803bd0dc3a1f7b7602017bad85d154884a2e839c46e283c5d6965c720a63b44257e8a1cef0862be4a8e000101202d5f656c1828c1608c83cda4979d0a30070dc3b58c2a853f61cfd24c6792873820a44fc7445114a79b6b54ff880862e38986014a64d9287286df281905a1c89ffc00012093c42c752d50a5c21b10367170b4627ac69bce9e1f26d1527e109d35e5ab3c1a0200010c00010002000300040005000600000400010002032012b2b0ceb635b2987091ad32d16376be1792252cbbeb58f06d99b4e29d3b26b00040408fa4740ef325f0d59e17d782f4e75acd69cc51ae42549b1b4e5a998c9bdbb3979cfb06774694e98083a77fdac0b974d73a6b060fb86db590a22c411994596f0d01022082d9f899ae1878305fd45a418f5113a80bbc96d20203d2e17dc417c8ebaba226203e7f10c204843785fc5feddb61e0423648737d8ffe8b7f2de807c80908d21bfc00010120a8fe7aed0801ce119dea10a1c768060b087a9c1fd2f75489b9d193dc6332a04b2037e3ba9ff8616b4366185cbfb09c1f7e114307bf18ffd064a4900ab7829f2b8f000120f6e938f6504ca5e61d7eec445b8cb7ca51dff2de1c16b5436767b5accacd25450200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040a026c67773ced8cc445b9e90d03ac205c44c81ac3e0e0c67311bdb50facc93fee36323dcbbecaeba1c3d70519b92886223f4d70d068116f9fb59aefd1cb606040000010220f3793bf7a360a418e4cc39ad2dcfdf262ca6675f7aa9ab38c0904f33362f20540000010120c73366272eba3633266f50b4830dbca5ad799eea6d748b8b1020da859292654d207d24efc3ca69b5959c4da1eedcb1b47dd40daef25873962705b2ae2baccd5311000120a2257db7b675af494dd353c8096a0a5196c4bc8039ec37638742ede242e548060200010c000100020003000400050006000004000100020320981b9cdfcf3070cde384910cca7bb236bafc6fd0f52575e26fbd6fd53a6b092d004040449b36563a850eba85dce9eac03f26b549a771fce48cf981a63965eadaac1118f3072c174fea12c2f1d38a0f69de7ea07bdf018f164bd8141979e028fb1f6007010220f4e766427919d55a1ea92a2f315602ce22ac4769c310c7deb8ba73bd6148d44c20486dbe194107c965c80b479581fe3e718ee1d32bd93da38457c6757bb3d9c689000101203d1fb2e91b498f58b3796ec3d7089ae8791ad259a40ae7e2ff55a10a6d3c5a24200665bbaba18222b914670760b9c383548052ddbf3bd02663d6a967eda680eacd0001202abcbadb403e183d8645c7eaf6e9cfbb12c61ee55c24af08ed347d3edab29b420200010c0001000200030004000500060000040001000203207df0010b5f13623114abe8d7d5965985b63596025b31da4385ded6d4360db7b50040401cacb260523b9a711edfe39bec87555fc75c224da71a7996c73833efa0c17d5737ce2290d03c2014f4867e58461b414f4a9c4c661edc63b90469edbba76e1a05010220e4e4a846e25a434bbff1623ff9e09325aba2d38aad660e29d3fd6964f0010d57206072997abddcb97e58b8597eccb6c510ae0d185d1d0f7cd3078c6a781e8678bf0001012065430412de2e17b8e5790b1c645668cce199af6232d9d8c7270e097d9599eb4920d5ffd82727a7fb50795b507cb223c00086dfc35e0ee88a0ef412087658f07340000120bfafddd644fe5983eaf09f71efa3e8334a3054494f05a7a362680485b685e3b10200010c000100020003000400050006000004000100020320094b21913ace4c23353c6be247f61b61ad2ae740c5d392921f94e7130bac495c0040400026f379a41b1a1d88582a0a9cf713b5510d125e58b8193aa1bf358296a697068cebcce437a5822681c65522869734d2ab7c2ad0d5398cc6c115be2520a8c10a0102203f2a14f1ea82ef446a475a11c2e0e1bd268d40e836fee48c1d13bd00e408025b203eb70fbf84312d4c3c1f6c916a683557a4d507b96ef4939e89f051e4b183880600010120b894b249e8dc2b6a721a1bb61c1086e5ba6fcd78365a054629b72c2a61701f0620ad8f20fdf4ea85f0ed56b1e0bc8076b5a4349853f5005c23a3d48c4a7879fe4f000120dfc720d86bee8a7fdd31589c24cb61e66dfb51ba12dc993e63744af847a243590200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040fdfad84f20f5b90dbad0d5d1728dee6c39f5b4f51ad9a9378fa37f1fad541a984c282393e4a11e77c5037e31cf1ad35dd6d8dbbaed6e038ba73a73ceb221520f")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "6c57a72a27ea7bf77f7c34d5405a86f719ce6596d297c4d28097ff596991f37c", [(1U, "c2cea7241c151037066f01683d5a8c7490f122884e3b2291b344242acdbcec92"), (3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (1U, "9d0630b354095a0ea2eed286f1be51aef6d35a4625cdba9e1f540a0840d99399", [(1U, "c2cea7241c151037066f01683d5a8c7490f122884e3b2291b344242acdbcec92"), (3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (2U, "c78e686b2f3b9b3ac2f37f9376c7a89f86cedec0dcc06331af05f419a85cece2", [(3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (4U, "5c97adeca93f043809e4ab184ab7adf09d8697ecc54b74615aefa0ec84bf0ca1", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (9U, "29d0793e570b3971132b808c92612a2d1fc4306b6ac618e053207656454c1ca8"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5")]),
      (5U, "a4698245b162baf8f0f475edfcd90acaca81e416faef012d38eaf03786cb12ef", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (9U, "29d0793e570b3971132b808c92612a2d1fc4306b6ac618e053207656454c1ca8"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5")]),
      (6U, "da6baf0333574be8bc8953b4191682bd4256dc9662bbd52c3471b3805fdec080", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5"), (13U, "3b2f69cd936de4b61371282d4704b44f4ff5b71ed32a70815a876907db524b26")]),
      (7U, "b67cd571d34842439c15920bd4ab8f1539a4a541199a85d90e4ff8cfa1fe2516", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5"), (13U, "3b2f69cd936de4b61371282d4704b44f4ff5b71ed32a70815a876907db524b26")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20f3d556cd98ecd39b00b09f0f2ff6d7838b295045532e7b39ddf17306a48e7a0a0001201f2e3b192d5a46393f7bb45b50907b33588f0727cf130cef329b3a98b0704d280200010c00010002000300040005000600000400010002032016d7b8138552f543ae1218dd79c2ba5d7cee6b66e91e7b674fe4694fbe01a2aa004040d78e6150f5018faf8a500dc037bd9620ee9240c3c753f4d53f8f5018ab5ad682ab2ddbc2f92cb42d7e212251b8e4bc125d216cfbdae1ee3839b94210c26a5c0a415f20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220c09bd9c86961ea500977cdab22f1d3ebe91804a9929f7db0074f80401052863630a0888feb1531dc1728020747dd7dddb87d3800bf31df590c2995eb350844cb051e84452e5d143ffec9759373b88024eb20e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b26405220f06361a207e3507a5c968c8faf56091c0eeb22193b9d4a476f8d5643a469662730b8c2c907d5ffd213e7254fe749349d2e2cff8edde6a291d8d714a645afaf571e1e0f9cd50818a51bc78db6eeb0ec048d2016c0114dfcd2011df1bc275212b83ff40af5d50bee114d10b4340809c5540e07405220ec6c3121f39fe2ac9c99e25606cb6a99607fd43967a12bb674e76f9b4072e906309f4b3c881bdd0c506fd1d4ec5cf05dedf628d6ee3f71de2b57ea7b715b7e8ad9cd87086547dcfb151b6b7a075e03fc03", "941f81cd1f82f54afb19a5b814f9a879f22a991cbef3bb54fe4f4d445a712271", "1dd30892aa679e04a3546c355d6e235c7b679df3243f27ce3e1d0a8b5c75385a"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e12733220a44fc7445114a79b6b54ff880862e38986014a64d9287286df281905a1c89ffc00012093c42c752d50a5c21b10367170b4627ac69bce9e1f26d1527e109d35e5ab3c1a0200010c0001000200030004000500060000040001000203207eeaddd512633784bbbbca8a813d5a4824ed73ca991430f2d2073adc3a8dcf8d004040802592563632e4f357c2917716b5b683a491ccffad012bccb1958f3c3b73539f47f5de705171f9c605640abfa1f4fbf62c6422365696037347453b29f357b507415f20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220ddd0261552898f0c238975e60e2b5e49c85f699f068eba8a79c147bd263c821f3074ff6776571da2568b387226b95b26e3485e51a128774c5a3a1fdfe4a8dde3420b7d5347d20703e9b16d847a8608819420474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a5664052208ddc00c3beb3cb16d741d7fab434d2e946f3328b9f1e59f2eabc8426ed4ade51306083ec4b494a76c03126ccf009243d494c92b11c96d2cfbfc0fc2f9fcabe165883decd86641e5f83cc5e7c9e78e900fe20393604807b6006db6ed3aebb4784ccb15c3cb72f9a3e625ff04ce1b29087390a4052202a2e11f664e2719fbfe370147534795eabd2c85581121e95547123e7eacc2a6730b674c4a785a20418d65edb106060f21505d0d7315c174ce6d69f54b2b4a35b9957add8d9039aa3b81ae98dc8b75c2cbd", "dd1152ed5a9549586f3bb8989e3163ecb95b27128113195f10250da1ab6a3ad8", "44de85ab8129becd6929c765306031c51ce6b621c176b6a5d5f2f776da118209"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d0752037e3ba9ff8616b4366185cbfb09c1f7e114307bf18ffd064a4900ab7829f2b8f000120f6e938f6504ca5e61d7eec445b8cb7ca51dff2de1c16b5436767b5accacd25450200010c000100020003000400050006000004000100020320f8214f9636ca769d0b67b7e764ee04ada5f003cca662634b150fc8511fb1c9db004040128a94b6995714d8f15782681b4590a2e54b911024e57711c03e88048f1d3b78db64aca65dbaee6e3f0accaaa04a6740ee3c4908c71db92232fdaa51bd56130140ea20e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f37405220aac1b36f5ccce5a4bed377d0144b062133aa0cc3221a71c14dc1600624a6122b306cd7fd0bac564883c134960a6868c1c42e268792a9c36a1df9699193261579a25054571ed7866d78a94a8fc9ba1b01dc201aacca6cc8b6fc297d3ceb6a13fa80e8d6632ec60a852d7456f13d277d8f954a4052205622195e0bef58c01de9324c57c89d2938ec40b3d43137332584cbbaf24da149303c77ab1fc3bd0364c37e73865a9c89bfdf882149c89ca0960d8f68e967a2207b3268e8d376a02bc48c30b0efebcc0697", "6c6b178322412b9bb750c302683cc6068e8f802a43526ecc188b00013f809d59", "fcc016ff84f1dab6df10a1f1c1847187255d3dcba8b1d859a09d66eb40cd82dc"),
      (4U, "20e68013771dddbccbd8b0af493dc0f2f82ae62e72f7207e878875ae21bbb5742c207d24efc3ca69b5959c4da1eedcb1b47dd40daef25873962705b2ae2baccd5311000120a2257db7b675af494dd353c8096a0a5196c4bc8039ec37638742ede242e548060200010c0001000200030004000500060000040001000203203ee9ac46ab1d87f9da2818cb55735f8e802c4045ecf9a7406b51f027bc76f08c0040400b569ed1bd4d3c56c8fa0a0e0b318dbe6fc3bfaa9424607eafd7c489001a0ea8a2a5b09ae778187aa50985834d8870ca4b699b85c7139fd5a5f3ce8261e1f207415f20c5ed143bae8705e433a2ec2494776bbc49ed4903e53ac76efb87b9c8c98ac134405220db343125965e7d4643ef74f7d1a5933bcb3648d750f838112996609dbf6b1c2f3019b16af393cc8d8512be8f43634c5e81957258eae8f56708ce04168e6b6e24924b6ceec483d7a53eebc8648ae934fe0320138d0962f8f209d95e99e7dea47dd0d73f34a0d9b33cdbeef28017f2566614754052202bc9a11cd29952a21eee1ae573a2ce11e4e303d87698a0ac5afd5a7bd483ac173088cf6d5d2acdd05b816ba89d5d6e0896c0659d23c6276368da7a9d451a4916db02227319ba83fe0ae21c03c084987c4b20ec1706d709fc0949190db10f39202d37fb3a50f54d5330af7934e458d5191167405220cc2d74cf72928c6d872c472dd40b7a47bde31c4ac0a3fba801beb72c8fb6641b30cac90b7200172f7aa479c348c569a5ebcfafdc6ab5fdf9107ffa50fd84490c20aff5fd40fc1e56148799c45daa96b374", "d681f7b3222cacfab52572feff07675f1803e652f0a86b73ec85433ba90da16e", "972b4d07f7fdb94b968bd9b298cdd863913aee453339532c9a46c2ccc9232be2"),
      (5U, "2065392578860484fd52e84aea9fb12ad346ec40195978df7093e40f10c4991702200665bbaba18222b914670760b9c383548052ddbf3bd02663d6a967eda680eacd0001202abcbadb403e183d8645c7eaf6e9cfbb12c61ee55c24af08ed347d3edab29b420200010c000100020003000400050006000004000100020320ec825185a713f342a8a25510ee0f36366d156bffd36e92dd7b16f94f8e06a81800404030c7a45c4f01698c23513b2f7fdfdef522e60fcb137aa9c7f9c1b58c0bf421675a242c5065b864bdc786e338b5741ed6668f1d1ac5086cdeacdb693e9c2a9a08415f20d3397562ec84fd1ebcf1ba024963581f8cda58ed0dde8197f470e155a1835170405220019e216e80055b52b2395cfdb12fd5d0ee77a9e5b0cf68c9766a02b7f47ddb573024b3bb439719f060a80ab951ca8c149787668618c4a1830284ec9e678c89ae9413f2553a2474573497f496a719f3c60920b6f91f1c8bb32e84464864ed6154fec3a23b5aa7b08e8a2cf59ff79fce58a41d405220213cc69916681fc52d36d65622d332f13a03d839f9681fa026ae9a09d147b16b3076650f4bc07db40870f0ea272d7302566335ae864c8b48c5e821d6829c94f5febf13a4806bc7f7e7e1c5243a741ec9c42060ce6eaf6f12c9cae0bd49b2e1a35eef8d29607ba4177df94108c08a6f1b261f4052203b559547d095016a2b4ea91458dc34532ef42456b07b1af639b0a36598ef676830649a54f41cd9bbc2f6df951c5918d4b1a5831d9fbeddd0c4cf57657613a93eac44e4c2b9c597e461c0eb20c10f033ce4", "223439405232982ebcb07c5562fec3cb75d607db5bd5525be94c4c124249cd30", "fb25d3705254c9691756c8df81cc6cb4a0d76182d9504841ac113b7fe31c0f12"),
      (6U, "205272bc926c7f6a12805418b46abd7de5f54b85259e4b602a32c5a9d3229dc52220d5ffd82727a7fb50795b507cb223c00086dfc35e0ee88a0ef412087658f07340000120bfafddd644fe5983eaf09f71efa3e8334a3054494f05a7a362680485b685e3b10200010c000100020003000400050006000004000100020320e0b6b23100790b037885e70b74587ea07de4a9b50a3a2862e03b5658ebef779f00404012a28ded49c96a7a52d74cf41d431435000020d3b2f9ab3884a3692cd5c6467951c496fe84deaf45765b0cdca6f62ef9281b3a159e31949d4ddc1e91c1fa4708415f20534ef54c317137e9132d8461d8daf1c4e950608d9035e542f5294d72c2deab1f405220fe5f990d7876360bcc7d9d6aed1a9937a193e16b3b47f9bcf517a535be44e84b300690626647b9a31cf07a28e69f17238fef56375e12cbc27c2cde1dc08c788d0f639ca8478fd7649055c9b7406712a397200ceb7fb07184bbbaafa667f8af402366584ea507fd6f6a28df505fd9a9f570524052208dfcea4b902fbe7d8f2736ac96a12d9a6ee961008c39f980ad3cdb360e75082a30be8ad94ca869846906486a12c204310aefe26658ef5f5a094ee4f15e1aab28c64482c00d7d5244eb4cf463412aa62d7b20c11e34549f7f1a9244140657c4639918fbb79b227810084c5b42de5c35f2f3614052206b98dcd6542608ed6067cbcb4048e34991841af33ce89b4149259dcfd6338a0930509fff1e109cad9ff8d3085917c4bad599226b598a92bd68034dd430ebda455f7065fe54293c3af34a0c88016f1c8e28", "d983104b1f9d0f149bdd799a8ea0e91c4047efdf7ea1605a23027fa3ea7e899b", "680875f1b5daf35716d2d89eb5718cdcb8acc37e32c3a663f72e8fb53806b3f3"),
      (7U, "20b9169060172d4a32cdef3c99be7f37f7e087f10fb3e9431c3966cc4c18b5dc4920ad8f20fdf4ea85f0ed56b1e0bc8076b5a4349853f5005c23a3d48c4a7879fe4f000120dfc720d86bee8a7fdd31589c24cb61e66dfb51ba12dc993e63744af847a243590200010c00010002000300040005000600000400010002032000fd0dc9035edd7d213ade789125cb9bde94436d1c89c70d4abeff6dcf7585d10040408ee24814614c07808f6f48225f72c35661e7c26310a7d6ca94e234cf4a1743060c6c5f7cabfa77896dfe5da7d71e8a403aaa899a6d9dd239cdcd205074d69400415f20704b90a9170754f3149820aadc2e2950110f6390142cf96796dc000093434f65405220b5d34fc5e7d0126db8711ecd5ec5e3e2c636f34bad5e5fa23769cc9e54fd5152303686774adcf7f704d8c1c2fff96c4dba710e6c4c55fb70a80de6918b00df7a74620619ebc06fd3da71db2ea8790c6c9220c431ef52600c1532ca5967e9c6d643ce667253ad5567d201d085d68bad39a0074052208db67c2561a5b1116664899050625088e84240e0264e19be875b98a0e48fca5230b0aeef3cb535289868251ae24382b86e5bcd063185a116bef8f6da4a48bafab34df7f3d6fbebacdc720bae5dda076f3020be95c5abb055e0212a90efad57b8b63e6c9d35d47601392c78dbd492bfb56731405220273dea823a36daf0e731c9ea03246c6495196dcbae11b85971e9671fe135f02130965807f286f2bf90f3c22acdced506baabddec1e4259fb969beca4c3e9c244231a9270f6721e7b13c567d446bb6c66fc", "bab902a5dc3fa0213148c367db9332e31893c6dab439e2cf47920be05cd64e46", "625e8da3f11eac0805e494ea05c22ce45bfb0831ad6ec30a846935ec8f09eb6a"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let group_id = vec_hex("476813a66a9e9a464c40e79f4f8449d939d9235c56ea955ba7e230ec6d7f6b03")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("41da010120c929637bda524adad04ac85cf8ab7164d9cd88139aef5c9f7157902707c3fb5820c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c000100020003000400050006000004000100020320be6b0e33b576ab16727c86317eee6b8bbc20b641440f1f55ed68a4861b6746f70040404007c2a631b8a394f6cb8704b1cbbe2e149241ca32f316ffc6f8a541521b0a298dc0239d0ec0e8ab77f3c39b5810da1815d3a83dd4797d0ea5a0488718b8af0201022029eb3645264612282039eb7ddb095a780f39b1904a9613aaad568642a4b9b2040000010120d17b7296c1ac920c635574c84ee59f11c43bf534f4135225dbf1ac360e4629092018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e866138390325d0200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040405ca8f99de58c59bc29c4d7b5bbc489ca7a62a8971d5944080940cf14d6795443a20cd96c290a67b59c28a53e9e9795ac9f21cbb257ca333e75e72e5582ca8e0f")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "7957e5368bbfe5dcfcce0cac8868d3d1943d7733f5c77ef582ee84ab6a281176", [(1U, "8313fdeaeb49196b0e35e38c37c9efcc1014380332a8c4c0783b13a4bc059f3b")]),
      (1U, "2a7ab9e8c1a8077944fa0f59303faf1d7da5ec43c7a3f345910c87478d12c202", [(1U, "8313fdeaeb49196b0e35e38c37c9efcc1014380332a8c4c0783b13a4bc059f3b")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c0001000200030004000500060000040001000203204ab91adcf7be9ea795042e1fd2d3c2021d3bdc7c0a767bb13b96f4b2b75b7188004040c42e9b322d874ac6f51b40fdad15f740ff99e85fa86c0c5da28dddcb9667403eb94e55bd34fd610be9308c86b3e881b1751649f15d34ede85689f59968116202407520875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220265f574d1ea8475bb460822c4767bd7318b55ca83cfed56bbcc84a66a5a65c4b30d434fa678589e50b0cbf565cb28cde87079f043057274c9533642e517a83195cfba3e4590ed774019731e01ca39d2ac5", "e90f531363f40f04a0e5207e4fcdad46fb9398ca2c208eee1c198ea3e73876c5", "5ccc25c82569cc9731283abbdb9265187c17503e6f9c4ba2484a9e210e83f5a3"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e1273322018fb8325dea495db27f818b49f80fbe1e41bd07e8f56e519325b0fdf5f34a69f0001209461d191779dc58ef19be7df44f74252e5fefab3e0b7e04d05e866138390325d0200010c0001000200030004000500060000040001000203204bfc816b5eadff216e4e8b80b389fc7183268bce194d5ef5507df3d2de7e903b004040bd3e4e28c0ef9370a4b742f2c25268a2dba5b4f9d7c74f60d49a587464bf2d598a7e92ebc9ab8519d0ec0552e062e34f39b1ee8965b618c828aeceadb5e38c01407520947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220e839bfa9311068e4c46d93d094a5f6d6c0d805ef6e2235b2f709e5a99785841e30b6b3459f1ba03f75d64a5bd3a7ca14f7d4ea4bac14edf562e216529f0acdd0af61bb3177e5a371f28d60afb557ecb088", "ad926d28a9ceaa99e24f66d289098f87d52965f7c903804a833cfa0dfc0d711c", "4179fbbca043d7139726430d976a623eac87a9d18bfee7227f2c4d54c16d041e"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let group_id = vec_hex("e6b740d256274516247a96378b7a5def673d0a934cbc4be462f6904f2f21c57b")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("4302010120e54d0eac71c30f4918d9b69555d66970f2f97d13b1b21dd4448007ed0e3f37022063a5a3255c7f3cf9e358a1d65aac578527911a95d5c350f8d88c87fc2985743c000120272f5613d35fb97890a5753f75c1fd5b20eb18e38a12ee32a8d28efb43fa55380200010c000100020003000400050006000004000100020320d9c620523b20b562fc2cc9e9d739b96405dbcf11e4e3fccf5372c2214d7da4ca0040409c01980ca2672ec79c5ecb84f164a2832511d4df2d197e45ace01c45c474daf88cab25c471a8fe7718c71ccee81189e961e37bc7d9ec6b4dade0dbebe4ed9200010220d1eb73ab6bb8b043f10208539bf40e1db6633d4d2ccb9060078ccad5cc861604200d451ce0bda28eb79d23899525b86e056c56176f7ed8dc5b47d78368a327789e00010120293ec088a08f27c2b909a71f12dcbb2ae355a260345405dc062efcb611dbb87820ad43d6af950545ce6a6631985b2250c20ed04bfcef5fb4d13dcade9cd7f1647c0001207a1dc8703b9a8edecd26a9d4953caeb655699a5f2978aefa42f676e413a3aa130200010c000100020003000400050006000004000100020320162f66c5ff6c647e986a6b0f39858ce42996e41a27a8d2f44c386172ebf6961f0040407f6f22301bd02337844315b9090d375cfde9b9cd7573469a69394fd1ea211eecde201a54df890ad67aef4ea49ae79b97b6ac3cbcb7627e85e2f0b4a0399426060102200688dfd4795e2bbbce6b144077f2311a224635c371e1b3b77d88521390b26f48000001012013e4fc31c6ee339941282f3298aa8ff59604c115e92bd77bd3c49b3fa5c14a43209cae579ac72ba063ab633ea646912093fe3f5c95bf1873a85aec53de106d573a00012088a8c9f18271b261285aa5b78675cfbc6830e2acd056c667a568a118270026f40200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040331c7cd63ebcca3717a789fd9528cef191cbb91fb9dff9813cdbb59c7973b6b6f97002c6adc4d7887a57e9bc4b4aa4a37daf75ab75a6a9e8cd0bdf347ffdea0a")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "d4770149641bb1a5c0ffd9f557df68e4180952f959977e5556f240f1e1aad23c", [(1U, "63e805fe99eb66a41172f6112daab0a2aac147eb16695ae539a4bdbd004523fe"), (3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
      (1U, "8e344683c5650ccfc37ec1d02b74fb6d10559a7681bbbba0c78212313ae69e0b", [(1U, "63e805fe99eb66a41172f6112daab0a2aac147eb16695ae539a4bdbd004523fe"), (3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
      (2U, "bdf045e0a0d3ec655593616eecf26070512c06e8f180de277a979206d4e43383", [(3U, "ddec167100eb2a1d64f90031eddb412dc8ca5ce874d5cd9c408e895c5f5da1b0")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d2063a5a3255c7f3cf9e358a1d65aac578527911a95d5c350f8d88c87fc2985743c000120272f5613d35fb97890a5753f75c1fd5b20eb18e38a12ee32a8d28efb43fa55380200010c00010002000300040005000600000400010002032081c6e894eecebb54b549c22114509dc6e18f25783e41214a41bfd650f999e89900404081a8e1468513724b0d29e92af277990df94e423cfc489d8edd0312f30b8549ece52fa334d19692d3f805c0082d66c2997746815f539ff555c00befbfac0fbf0140ea20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220fa63ccdba45b41895a9ee1f331cad8312d63a078159b0de27c8688a497c1f70230fff451c4096b75cff095118b35396be59f7b8fbcbce97d1748cdff3c4c9b6d0eaa2edef4e2576e6f97961a3b233f647220e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b26405220e4a8ed6cc172795bfe07cdeb87fda0d29a0351fb1ab9f53cf7a8f34e8aab441030aac320a2be0f872ead61962cab1d6595d3bf0adefbb7d56d52d106cca59769170a1b6a066f70a1cbf85975ed4611d3c4", "ca878f47a9c9dc41548f1abf08a5f28883c31b372f088a101b44ca3f35480257", "504766baf72d5ca7c9418c872a0e93387d717bb13f319e4953867cc50b57d676"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e12733220ad43d6af950545ce6a6631985b2250c20ed04bfcef5fb4d13dcade9cd7f1647c0001207a1dc8703b9a8edecd26a9d4953caeb655699a5f2978aefa42f676e413a3aa130200010c000100020003000400050006000004000100020320bc486af33db8d4c09b905e857cb0122409ed10b198603a2dbad598b0ed0daed500404063daa824b6e4c9dd256c959dce661f412c3d4163d35ca1ed660f1f26d7b8d4cbfeb187f6e4a38f9fa81f8ffc3079a94e9a7ccb91238cc451ea8f8506c9f35a0a40ea20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220fc69f578cf4169dd375fb6f82b1ed48ace6e3005cd38d320791621c37d855e2430d8cf03669024d73f4b39dfbd6aa051f9ac6b692513ad9c08f113c707124de2b29570be25ec43503c02368bdc7894d03720474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a566405220f5a06a0f292c6f97ca1d61ea746db31a1cdd3cf5d4f39a0bf1a5d6f10eb1057730f653cc93ecdce5e0ce5afc69304bae6b4a02df91a92d5463ea9f4111ae7fb5dbe4381a3fefc5bf013d69ee7c58b42e74", "8f47f28dad256efca060bfa473064ae5ae62cc1a30b2411910c5029a6c4d7330", "0a8222278bb97717570dcbe645ca76266a1a6fbab32e2cd4420431e8611eed12"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d075209cae579ac72ba063ab633ea646912093fe3f5c95bf1873a85aec53de106d573a00012088a8c9f18271b261285aa5b78675cfbc6830e2acd056c667a568a118270026f40200010c0001000200030004000500060000040001000203209ec36399714355d8a97295d60f32aa6c2120706bd235c20641ef8ec6314751be004040854a79189e8701be7944713638a8d8bff90f18ab4b6b7034aca10ce2c4ce2f7b0db58f7ea7c46943df312bd91e7d749204b52beef5fb2db63b591571bd1ea70f407520e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f374052205440d9c6ed5140f17c9b66cb9cc0fa5b06377a774c1439c0ab16c857d9e6686930c301a71bbca130741fc991475b996c4cde48c97a293aa6977a21f5a37b11e0399543b0e2a142b7df72f455944e347726", "485893698b0653aaf09945423a842250dc77680f4bbc0e0ac8f5369d0d6ca8c6", "31b55d9f7db7c7e5b7f1c91517029fb661d7379735b8aab5d942b8bb86af38d8"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let group_id = vec_hex("423be13e60cb792908d054f12016df0ef390bcaf997a30e655dabf08059cef79")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("442a0101204b9fd7d9003711f24f13deff295f7e4e0238d3ed29b96a2880bbeaa06d15f6702091db737bc3e86ae847df35c2654b3632004264912f371908614b8b5986d11dee000120b85b0261554e5caaee148aeb22b43c5bf88eef7e15f22536b1068c3431e983160200010c000100020003000400050006000004000100020320a97db37da3835b8451d0cda7fc18338b458f19ac308c87640fd86b1b32e5d191004040bf096e969de74303ac9ae863315a161cd185a4315db28afb3fb7fd4c79eecc49d1342e705f7cadc8cbd204572f76f35790ba9cc985297b326e2d5708d33fa90e010220e167835eefc396f5f55c2789a75c80795e825cd3cd581bfa6f46bd3631eafa5820b9f3a097c546c04bf444d5c4da3aaea2cdb00e567a9097a75826908a48ae34bb000101206f1d0912a1942172908d1353cc797ef87a1b3ee97ebc4bc9bf6733f0ec562f2f201d41f65e150494d0ed0d9aca90ed4fdb7812400db9aea37d60b7f6e1a1dc891f000120b0cbd2b52371b5ced80aa97e9be6f1e9ee39ba75bc7635ec7077c7102ca209370200010c000100020003000400050006000004000100020320901518595e4408057d3dd777a80a07d53d8501ded19cd61856ccf9256c11454f0040403cbc81498ce781b8d2d0e1f8d645825b510919a200777b44daa17602ce09537a89294800645266fc0c2c294b471da543a9d560177af50ce5dbda78a9fe98ba0001022069c2255e9f1c5e21bda11f97ac4364409556bd641b05d44f7ac2f167e4442b260000010120634e798bd04d4be0cedf312999ace36db4893bf235c5a936f4d310264f36d63020659b01cb9207c17b960a16e31bd7c38e4c7332555fe0078afb088e6df28208a00001202173cbb1727b754f15bdd8a299a3a859b5825c17dcdc6c2acb867d5c59c60c820200010c000100020003000400050006000004000100020320c1b4dda2e2e32d72106deac1b30c80f993979d7cb041b337c7e4067ee679d5c000404013b7831cb3341ee6f5d6554a5c5555401df06fc2208fe2c46734dff9eaa566432b63b2e6052267a1e6304891d6953f009221344dd385678999562be6b1616d05010220b2754eb2b1125754bc5d816e5387ecf547759c29b379840509995ad5ae3e464d201c0f40f85e82db7a3e4aabe9b99c33e79ee734e6a8b88e394945627ea87944c700010120d354b7afbe6c7db2d975595742faadd5ba68ee57108d33e7aec8220f81d6bb72208f63b381a3663b73b404173e9f0326b03964ec5b388312b87b5e46cc10c07c8300012012924cb0648c160903544e900240d09af8339df9bffb24f9837e18cfe01e0f960200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040403e33781a685d0f648b9ee27b81c69b825a0381895387405ed10710fa773f8db4262ab225b7716a2a502209e2908115f5fdb8a0905dfd937430e3fc933a4fb80b")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "d17cf59b3e7223b81b6eb3972540978a156df1df164b128c3fba621300e42a1f", [(1U, "a46b1af97fa9cb5fc60a462f58d084f2110906cdba7aa87a167382a76b532289"), (3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607")]),
      (1U, "fd0a2b613b0353968cc5af4dc8cc9fe5a54618e48401d0635fd9f6b14eee0620", [(1U, "a46b1af97fa9cb5fc60a462f58d084f2110906cdba7aa87a167382a76b532289"), (3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607")]),
      (2U, "51df04a380078fda6b55ff0b03e10cdc2c2456749def976e786da494debb8573", [(3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607"), (5U, "412edc724d5f6f1f2fb5d7e8b70a3806a8b310fc83b081478a982db6d52acd22")]),
      (3U, "821a3bf9c737f8dc82d9b29649d5aa0d20ecbaa0f8287774741a288bae295372", [(3U, "5458c23e63733d4cb2a5dd36fb12bfb5a7dfa6a694bfc289f997afd09ac35607"), (5U, "412edc724d5f6f1f2fb5d7e8b70a3806a8b310fc83b081478a982db6d52acd22")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d2091db737bc3e86ae847df35c2654b3632004264912f371908614b8b5986d11dee000120b85b0261554e5caaee148aeb22b43c5bf88eef7e15f22536b1068c3431e983160200010c000100020003000400050006000004000100020320e73dcde3e179f8089c4df28862e2cf414f82fd0fa5d334ff45b5a8cfd0048e4f0040406ab24761c38a79d5e833d6516606f4c3295e3a32de1dcd27221d81d60e98e44806d1611651766337ccaee5c6ff30e76c3e10610f7c589eeb0e631a8487ea870240ea20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220e463cb88ac53283ee2c7dff04bbb00d54375749744fd989a74ed381ddebaa440301db4e0713becb36807d38efb75c12f2e7ef868ac3dd4457e96c1324600c7754c320b6b640ffcd2e4f88e2985a31d475620e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b264052202de5fe0b541edcf904841044abe009ac5d00bdd91ead7c3e653270d450e56f2230c89edaab5574fb8712c5ecdce42da2c1daff5c2883e8746740ab6e6bc204ed8d175f32bdff404dd8544b0885c1897a60", "1fe40de697347712836f9957ea0bd58edf52ceac2bfbf098547f3d38d0209a70", "504766baf72d5ca7c9418c872a0e93387d717bb13f319e4953867cc50b57d676"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e127332201d41f65e150494d0ed0d9aca90ed4fdb7812400db9aea37d60b7f6e1a1dc891f000120b0cbd2b52371b5ced80aa97e9be6f1e9ee39ba75bc7635ec7077c7102ca209370200010c000100020003000400050006000004000100020320f3e607d83e4a4997e30b5703138ddb5ad71ea191363f99fa5dd930bb5beb040d0040406b1600a9f3bb2abb945a04fc9df4b66077acfca451d94957eaa0e1b9405511e3780260fa763e452163f0245e296f83079afdc5ed8525a3275d3bef4f65e0c60240ea20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c3244052208f92d3eef990249f98fdc5d74fc959877f5c9e8ea75cd5e501b07945fc699d4130968defe9113e49b38ae82dcc5916fbe482e137c9ec1402574e63936ddfd7e9d6ab67277fcc70a6d46ed9a50ab6586c6d20474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a566405220eb7465ca61341e7a52c622920be09bb620ea4b73fb80aafde9ef02e0985bf95930bf0f969bd2e824da82e4a6c58195766c568c262e10473a8b9ed8fa0d21387636a09328920ce0514d696517ccfc545a9f", "ba637d026eb01f2e76dbcc96c3d2fa935d1e87d300e7ed9f552d180058f78501", "0a8222278bb97717570dcbe645ca76266a1a6fbab32e2cd4420431e8611eed12"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d07520659b01cb9207c17b960a16e31bd7c38e4c7332555fe0078afb088e6df28208a00001202173cbb1727b754f15bdd8a299a3a859b5825c17dcdc6c2acb867d5c59c60c820200010c000100020003000400050006000004000100020320c01e220dea17dc3ce10b6bb2e7c5da2b2ee7cee9f7b5d14c087c6dfcd6847413004040127e3a0c442d8bbb3aabdd2fe7c52cf78afb8c3f3ef21f27d0426446b9bf3f9fcc05bb37b0e5c0084a82d85d2f5eb381bd979c96163f3931eedb4accdee5630240ea20e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f3740522015626e1dff56abbd7e17ed65f3c6f8d867397316a3af7d227efa39b957904c0730433a798cb61cb6c543ac994e6769b5b7e959724bde741d451652eed69d87bb4c89b3ef7df4cd06623bee97c919d9fe25201aacca6cc8b6fc297d3ceb6a13fa80e8d6632ec60a852d7456f13d277d8f954a405220a9cf5fa5c129eb5744a2a7385315cb0e87316dbcb5badd3765b73c5d7a92030930854cda4628975498d399856d840dbada66ff775e096d84d66aa1a0ced1d0bbc7d657e7466babd403e3274d591416d7f5", "2b065d61a081a08bad0c264fd0acb42f2c7576559dd06d70abf489f5d82b35f2", "fcc016ff84f1dab6df10a1f1c1847187255d3dcba8b1d859a09d66eb40cd82dc"),
      (3U, "2019fb8ee8448730c556519f79f2b6f8b6e5f79156535e12d964a43f25709dbb27208f63b381a3663b73b404173e9f0326b03964ec5b388312b87b5e46cc10c07c8300012012924cb0648c160903544e900240d09af8339df9bffb24f9837e18cfe01e0f960200010c00010002000300040005000600000400010002032057b200689e4f8dbe40e47f29398412d65589579377e727292af8288a354aacb8004040d99d93505895cdfee5070316c5edad5cb345e46c15fd3bcc367557d9ab91ff75f427bf33df5fa04f53ee9c2d029a002ddcfb2730acd688c06f2fee9ab32daf0b40ea20d30c196bad209e989a37a7e0d05b2f165a6dd9a9064145aab85f52543845945b405220680ea416a7f46902a674d6d93d38e68bffb696a3883ebac2138145c54330c0513001fee1919eb14260fad04497c14bfd8e37b23c73f9795440b7f507ed92209197647f65abb5d753f90ded3678251e8c74206d5afad9c6f39964dc6e5087c30075e2c36f8f51c05bfdbad9f4a1e50992be384052203a96e67c14eea12d05205b276b75094392ce098021c61f4ffe997feab2a69b5e30bb66869cfdb91baa71645fdf224371b60716a91bc6c613239de0f7a526472cebcc2749fedb1bd4c1cb5ecc8b8ac29402", "7655f9d9bb86ad7d509f3b14737508dcf7264ebaae24ee4067a8953e5be64ffe", "e91a12d86125a8d5acc0872133f1e289256c749698427abdcaeedf0139273688"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let group_id = vec_hex("e32626784d0f2067b8bb5005bb160d536bf666d9116ab532fa202009a1df4aed")
    let epoch = 28061UL
    let cth = vec_hex("7977581cbf08ae1819408f7c1feb8c8c0833fe6d68468f278b1902cff981dbb5")
    let base_tree = @tree.RatchetTreeState::from_nodes(@types.ratchet_tree_from_bytes(vec_hex("4793010120cdc78e82d128e8cf4d1436b6a2085818a88dbfc764ae4405c4a05cc6c7072a5e20f3d556cd98ecd39b00b09f0f2ff6d7838b295045532e7b39ddf17306a48e7a0a0001201f2e3b192d5a46393f7bb45b50907b33588f0727cf130cef329b3a98b0704d280200010c000100020003000400050006000004000100020320ef5d06379e6995b358b6c3a9e78d53b4ea11f3b4f31d6be7598cf82eb01d31f70040409b87ae3e1f1f30008378bdf83a01b3b9690c5c13d2333b24c7c886ce76b194b55db2c1cea94deafef1fea98567d4b19698f66761228d2c1965dfd4ffebba0b070102207d58e18ebd4767c41c7c30f4f1b3cd1160fc3512a998e94803bd0dc3a1f7b7602017bad85d154884a2e839c46e283c5d6965c720a63b44257e8a1cef0862be4a8e000101202d5f656c1828c1608c83cda4979d0a30070dc3b58c2a853f61cfd24c6792873820a44fc7445114a79b6b54ff880862e38986014a64d9287286df281905a1c89ffc00012093c42c752d50a5c21b10367170b4627ac69bce9e1f26d1527e109d35e5ab3c1a0200010c00010002000300040005000600000400010002032012b2b0ceb635b2987091ad32d16376be1792252cbbeb58f06d99b4e29d3b26b00040408fa4740ef325f0d59e17d782f4e75acd69cc51ae42549b1b4e5a998c9bdbb3979cfb06774694e98083a77fdac0b974d73a6b060fb86db590a22c411994596f0d01022082d9f899ae1878305fd45a418f5113a80bbc96d20203d2e17dc417c8ebaba226203e7f10c204843785fc5feddb61e0423648737d8ffe8b7f2de807c80908d21bfc00010120a8fe7aed0801ce119dea10a1c768060b087a9c1fd2f75489b9d193dc6332a04b2037e3ba9ff8616b4366185cbfb09c1f7e114307bf18ffd064a4900ab7829f2b8f000120f6e938f6504ca5e61d7eec445b8cb7ca51dff2de1c16b5436767b5accacd25450200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040a026c67773ced8cc445b9e90d03ac205c44c81ac3e0e0c67311bdb50facc93fee36323dcbbecaeba1c3d70519b92886223f4d70d068116f9fb59aefd1cb606040000010220f3793bf7a360a418e4cc39ad2dcfdf262ca6675f7aa9ab38c0904f33362f20540000010120c73366272eba3633266f50b4830dbca5ad799eea6d748b8b1020da859292654d207d24efc3ca69b5959c4da1eedcb1b47dd40daef25873962705b2ae2baccd5311000120a2257db7b675af494dd353c8096a0a5196c4bc8039ec37638742ede242e548060200010c000100020003000400050006000004000100020320981b9cdfcf3070cde384910cca7bb236bafc6fd0f52575e26fbd6fd53a6b092d004040449b36563a850eba85dce9eac03f26b549a771fce48cf981a63965eadaac1118f3072c174fea12c2f1d38a0f69de7ea07bdf018f164bd8141979e028fb1f6007010220f4e766427919d55a1ea92a2f315602ce22ac4769c310c7deb8ba73bd6148d44c20486dbe194107c965c80b479581fe3e718ee1d32bd93da38457c6757bb3d9c689000101203d1fb2e91b498f58b3796ec3d7089ae8791ad259a40ae7e2ff55a10a6d3c5a24200665bbaba18222b914670760b9c383548052ddbf3bd02663d6a967eda680eacd0001202abcbadb403e183d8645c7eaf6e9cfbb12c61ee55c24af08ed347d3edab29b420200010c0001000200030004000500060000040001000203207df0010b5f13623114abe8d7d5965985b63596025b31da4385ded6d4360db7b50040401cacb260523b9a711edfe39bec87555fc75c224da71a7996c73833efa0c17d5737ce2290d03c2014f4867e58461b414f4a9c4c661edc63b90469edbba76e1a05010220e4e4a846e25a434bbff1623ff9e09325aba2d38aad660e29d3fd6964f0010d57206072997abddcb97e58b8597eccb6c510ae0d185d1d0f7cd3078c6a781e8678bf0001012065430412de2e17b8e5790b1c645668cce199af6232d9d8c7270e097d9599eb4920d5ffd82727a7fb50795b507cb223c00086dfc35e0ee88a0ef412087658f07340000120bfafddd644fe5983eaf09f71efa3e8334a3054494f05a7a362680485b685e3b10200010c000100020003000400050006000004000100020320094b21913ace4c23353c6be247f61b61ad2ae740c5d392921f94e7130bac495c0040400026f379a41b1a1d88582a0a9cf713b5510d125e58b8193aa1bf358296a697068cebcce437a5822681c65522869734d2ab7c2ad0d5398cc6c115be2520a8c10a0102203f2a14f1ea82ef446a475a11c2e0e1bd268d40e836fee48c1d13bd00e408025b203eb70fbf84312d4c3c1f6c916a683557a4d507b96ef4939e89f051e4b183880600010120b894b249e8dc2b6a721a1bb61c1086e5ba6fcd78365a054629b72c2a61701f0620ad8f20fdf4ea85f0ed56b1e0bc8076b5a4349853f5005c23a3d48c4a7879fe4f000120dfc720d86bee8a7fdd31589c24cb61e66dfb51ba12dc993e63744af847a243590200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040fdfad84f20f5b90dbad0d5d1728dee6c39f5b4f51ad9a9378fa37f1fad541a984c282393e4a11e77c5037e31cf1ad35dd6d8dbbaed6e038ba73a73ceb221520f")))
    base_tree.validate_tree_structure()
    base_tree.validate_parent_hashes(cs)
    base_tree.validate_leaf_signatures(cs, group_id)
    let leaves_priv : Array[(UInt, String, Array[(UInt, String)])] = [
      (0U, "6c57a72a27ea7bf77f7c34d5405a86f719ce6596d297c4d28097ff596991f37c", [(1U, "c2cea7241c151037066f01683d5a8c7490f122884e3b2291b344242acdbcec92"), (3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (1U, "9d0630b354095a0ea2eed286f1be51aef6d35a4625cdba9e1f540a0840d99399", [(1U, "c2cea7241c151037066f01683d5a8c7490f122884e3b2291b344242acdbcec92"), (3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (2U, "c78e686b2f3b9b3ac2f37f9376c7a89f86cedec0dcc06331af05f419a85cece2", [(3U, "dcbb5fa7afcd36141986c9fa4da53cb45f11618448f62003e20229bbab99d4ab"), (7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b")]),
      (4U, "5c97adeca93f043809e4ab184ab7adf09d8697ecc54b74615aefa0ec84bf0ca1", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (9U, "29d0793e570b3971132b808c92612a2d1fc4306b6ac618e053207656454c1ca8"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5")]),
      (5U, "a4698245b162baf8f0f475edfcd90acaca81e416faef012d38eaf03786cb12ef", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (9U, "29d0793e570b3971132b808c92612a2d1fc4306b6ac618e053207656454c1ca8"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5")]),
      (6U, "da6baf0333574be8bc8953b4191682bd4256dc9662bbd52c3471b3805fdec080", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5"), (13U, "3b2f69cd936de4b61371282d4704b44f4ff5b71ed32a70815a876907db524b26")]),
      (7U, "b67cd571d34842439c15920bd4ab8f1539a4a541199a85d90e4ff8cfa1fe2516", [(7U, "b909dc8279f182745b4d3fd9a22508ff7c97ff79c46d596d45c6a98bed80936b"), (11U, "f66adb1a7aaa7c4894f4cf9a864fd7d167c8b7afbc04bc6b6dbd03499ff60fa5"), (13U, "3b2f69cd936de4b61371282d4704b44f4ff5b71ed32a70815a876907db524b26")]),
    ]
    let update_paths : Array[(UInt, String, String, String)] = [
      (0U, "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20f3d556cd98ecd39b00b09f0f2ff6d7838b295045532e7b39ddf17306a48e7a0a0001201f2e3b192d5a46393f7bb45b50907b33588f0727cf130cef329b3a98b0704d280200010c00010002000300040005000600000400010002032016d7b8138552f543ae1218dd79c2ba5d7cee6b66e91e7b674fe4694fbe01a2aa004040d78e6150f5018faf8a500dc037bd9620ee9240c3c753f4d53f8f5018ab5ad682ab2ddbc2f92cb42d7e212251b8e4bc125d216cfbdae1ee3839b94210c26a5c0a415f20875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b144052206971b8e9e3dd52550eb1380a9d105673b153813b9e121972bac53b6ee609a01a3071a29b6c0f6f9a847c8a8914a740111a503457c34354172bd21c958881918558e10d4b63acbc600688e6cf824ace51cf20e9e97edd5834611f0788fdce837fcac57eee8f745bbd9beacc7281b7f8303b26405220a93cc518c156e9f1c140dbfd117c17d9076c29671c0b588b62c64303bb20866330f0d776d5d8afe6d0e6f98d32441b22e6d67dda3f14b9d5598626fdcb761ba3e1c8496537daf19e936d89ffcc0e7928b02016c0114dfcd2011df1bc275212b83ff40af5d50bee114d10b4340809c5540e07405220ecf03d1ee87f6de3100ca32c7bc289a5dda47b9d79ed121e9bc09581c792822330862fa3f2ad2a3f9b1a4ae50424a5e4ebdb817462278d6e5ff756121f2a3dcc62c9b05aeac15f15f9ca1118efbfdd393d", "941f81cd1f82f54afb19a5b814f9a879f22a991cbef3bb54fe4f4d445a712271", "1dd30892aa679e04a3546c355d6e235c7b679df3243f27ce3e1d0a8b5c75385a"),
      (1U, "202977dde00d92cbe2df634c38f8be11e31816805f290da1c8effe722f1e12733220a44fc7445114a79b6b54ff880862e38986014a64d9287286df281905a1c89ffc00012093c42c752d50a5c21b10367170b4627ac69bce9e1f26d1527e109d35e5ab3c1a0200010c0001000200030004000500060000040001000203207eeaddd512633784bbbbca8a813d5a4824ed73ca991430f2d2073adc3a8dcf8d004040802592563632e4f357c2917716b5b683a491ccffad012bccb1958f3c3b73539f47f5de705171f9c605640abfa1f4fbf62c6422365696037347453b29f357b507415f20947e7324f01ecf1c62064e33ef5325b9e6d4114546fec0f98c3788704eb6c324405220b29f96fad76d805c1ead64d7be67bdb74ac10c36dea9ebc9afc67e453d67076c30b7e68cb7e528d63646811d1e4a35507ecce98d1428113990cb5f6be0242e3f17e500cf10735d17fe925263be2e30533020474908df65132a375c37352fca56e2fbf0c490cec2acaf29ca60dcf49716a566405220941178cbc3144aa43c9825de9403a8e216b2e131c6e75cf43e699591a1d37369303719ee0f7197a7ea40919685178560b54839c1415aebab40669913b03527402953834d776c8b2ae427704a42dfcb5e9b20393604807b6006db6ed3aebb4784ccb15c3cb72f9a3e625ff04ce1b29087390a405220e2bf824aef50ac64b245e95679ee3f7862de225a93e3df5e2dd3253aeb740527308ce038a3bafbcd53a6ee583f6397021c67d118c4ca8e30cbe0360dd5b631613f9ad734cc08edf1d068e11c59b5a95c91", "dd1152ed5a9549586f3bb8989e3163ecb95b27128113195f10250da1ab6a3ad8", "44de85ab8129becd6929c765306031c51ce6b621c176b6a5d5f2f776da118209"),
      (2U, "20022aa3eddfe3c9f1e4bc8f5eef6f59aba6f46fca791d5ffdbdc8a2b8b8e9d0752037e3ba9ff8616b4366185cbfb09c1f7e114307bf18ffd064a4900ab7829f2b8f000120f6e938f6504ca5e61d7eec445b8cb7ca51dff2de1c16b5436767b5accacd25450200010c000100020003000400050006000004000100020320f8214f9636ca769d0b67b7e764ee04ada5f003cca662634b150fc8511fb1c9db004040128a94b6995714d8f15782681b4590a2e54b911024e57711c03e88048f1d3b78db64aca65dbaee6e3f0accaaa04a6740ee3c4908c71db92232fdaa51bd56130140ea20e32dcc85797daeaf6e02e338ad51174c3804a7be549b6d3f1af1b0d477008f37405220fc3a2a74aa07cf8da79e4f37970e5de1aa1e4d0e99571a8c7505b3e9856d8a5030860f9daecca96f4f90462ebff5382b8fb4d2e0ed02a11dcc32e43609e94295382283d5f56adfbc835703056a0e729d8b201aacca6cc8b6fc297d3ceb6a13fa80e8d6632ec60a852d7456f13d277d8f954a4052200bfd788428f133220736984404ec85a92a75847f0e907cc5c63c92a3c147d720309160abf7537101f21318a8d634fae3b022a926b588b3cb6700333973607332de42a219d5b16dbfd7d9be2ea8a8f5cf23", "6c6b178322412b9bb750c302683cc6068e8f802a43526ecc188b00013f809d59", "fcc016ff84f1dab6df10a1f1c1847187255d3dcba8b1d859a09d66eb40cd82dc"),
      (4U, "20e68013771dddbccbd8b0af493dc0f2f82ae62e72f7207e878875ae21bbb5742c207d24efc3ca69b5959c4da1eedcb1b47dd40daef25873962705b2ae2baccd5311000120a2257db7b675af494dd353c8096a0a5196c4bc8039ec37638742ede242e548060200010c0001000200030004000500060000040001000203203ee9ac46ab1d87f9da2818cb55735f8e802c4045ecf9a7406b51f027bc76f08c0040400b569ed1bd4d3c56c8fa0a0e0b318dbe6fc3bfaa9424607eafd7c489001a0ea8a2a5b09ae778187aa50985834d8870ca4b699b85c7139fd5a5f3ce8261e1f207415f20c5ed143bae8705e433a2ec2494776bbc49ed4903e53ac76efb87b9c8c98ac134405220510219f30ee5ee23490b877501484e6f72a97b250ea300700941c2262b32cb2030130fc9154197e17dec8a1c9fd8a0497160b60c9129034d344adc5224147fa129495fce8822e96b493b6b42bd8ffea6ff20138d0962f8f209d95e99e7dea47dd0d73f34a0d9b33cdbeef28017f2566614754052209e9657e2663a7a5a9332cd7c622aefa6922960a8e9a09e02c7036f19e291262d305857ff919ac69358f2a1e81b42caaf33812b2985fd009d51e2546b1313cdbe0bd25c5d62eff6ac716e73277a2297b82320ec1706d709fc0949190db10f39202d37fb3a50f54d5330af7934e458d51911674052209c455badb75452fea0b2aeaa77914182448255d4be01447729a5c4a6f2876971306e92b22d7aecb28b926fe613486c3fc44a3a636bd5d8e44bfaa83869d4328669375c9d42819cb36c0025249b78a0e867", "d681f7b3222cacfab52572feff07675f1803e652f0a86b73ec85433ba90da16e", "972b4d07f7fdb94b968bd9b298cdd863913aee453339532c9a46c2ccc9232be2"),
      (5U, "2065392578860484fd52e84aea9fb12ad346ec40195978df7093e40f10c4991702200665bbaba18222b914670760b9c383548052ddbf3bd02663d6a967eda680eacd0001202abcbadb403e183d8645c7eaf6e9cfbb12c61ee55c24af08ed347d3edab29b420200010c000100020003000400050006000004000100020320ec825185a713f342a8a25510ee0f36366d156bffd36e92dd7b16f94f8e06a81800404030c7a45c4f01698c23513b2f7fdfdef522e60fcb137aa9c7f9c1b58c0bf421675a242c5065b864bdc786e338b5741ed6668f1d1ac5086cdeacdb693e9c2a9a08415f20d3397562ec84fd1ebcf1ba024963581f8cda58ed0dde8197f470e155a1835170405220b8c25a6b83a665f274da40f58e6a3525378369e5b227e320f2dd3027c6d30b21302827ba6962bde03d3a7eb4e0cb4da48a4a838d449b7973052f3eaaba703cfdd1d0605049fb328eccdc9d65414bc11dea20b6f91f1c8bb32e84464864ed6154fec3a23b5aa7b08e8a2cf59ff79fce58a41d405220a97f37ef0eeaa830ca495cb11d1da991ba0819f627e380c303604d3ed999403230ad42bdc9ed2c69b8a95f66b388abdb3a7494711dd9310689e58788242ff21dbbcc40065490882e743d846c863788bfc02060ce6eaf6f12c9cae0bd49b2e1a35eef8d29607ba4177df94108c08a6f1b261f4052206ecbbab9edb35d4ec0eb9209e28b9e25ecccb551c2143b02723330d45f40a268309832c6778bb14a45a2929123e4579394345750e1eb87a2d40c4e07235b91308a6b50f3080be16c51d9e4880c9b69dd07", "223439405232982ebcb07c5562fec3cb75d607db5bd5525be94c4c124249cd30", "fb25d3705254c9691756c8df81cc6cb4a0d76182d9504841ac113b7fe31c0f12"),
      (6U, "205272bc926c7f6a12805418b46abd7de5f54b85259e4b602a32c5a9d3229dc52220d5ffd82727a7fb50795b507cb223c00086dfc35e0ee88a0ef412087658f07340000120bfafddd644fe5983eaf09f71efa3e8334a3054494f05a7a362680485b685e3b10200010c000100020003000400050006000004000100020320e0b6b23100790b037885e70b74587ea07de4a9b50a3a2862e03b5658ebef779f00404012a28ded49c96a7a52d74cf41d431435000020d3b2f9ab3884a3692cd5c6467951c496fe84deaf45765b0cdca6f62ef9281b3a159e31949d4ddc1e91c1fa4708415f20534ef54c317137e9132d8461d8daf1c4e950608d9035e542f5294d72c2deab1f4052202e80d6d40aaf357928d1f9a69e4e3d2a588615233380bf56b875fce81da0b04330c3152f00a61f4051002249605062a3c70a21bac47b03fab52ccac3043552367b7cf3f774d629e29960023289033d6ee3200ceb7fb07184bbbaafa667f8af402366584ea507fd6f6a28df505fd9a9f5705240522073f9546cb5fa10c5a1c851eab1c1ecbf49c2a7816361e4f52934affce1815475304dec52256081a2415c4369efeced5a7df8abcb01dd5da0f38f80637242391f440f7c04e2784fe075cc071a25c1c600c820c11e34549f7f1a9244140657c4639918fbb79b227810084c5b42de5c35f2f361405220537062630b46d5c71c0de3cd858fc6b858e3c1b05dfabc3ca8df83f97593120d30792d30ad2c7da300ec4af5bcd8ffba07d74d756a49403927f2f111807c930d2306ecf8a9993e36d90edd20c0732357c9", "d983104b1f9d0f149bdd799a8ea0e91c4047efdf7ea1605a23027fa3ea7e899b", "680875f1b5daf35716d2d89eb5718cdcb8acc37e32c3a663f72e8fb53806b3f3"),
      (7U, "20b9169060172d4a32cdef3c99be7f37f7e087f10fb3e9431c3966cc4c18b5dc4920ad8f20fdf4ea85f0ed56b1e0bc8076b5a4349853f5005c23a3d48c4a7879fe4f000120dfc720d86bee8a7fdd31589c24cb61e66dfb51ba12dc993e63744af847a243590200010c00010002000300040005000600000400010002032000fd0dc9035edd7d213ade789125cb9bde94436d1c89c70d4abeff6dcf7585d10040408ee24814614c07808f6f48225f72c35661e7c26310a7d6ca94e234cf4a1743060c6c5f7cabfa77896dfe5da7d71e8a403aaa899a6d9dd239cdcd205074d69400415f20704b90a9170754f3149820aadc2e2950110f6390142cf96796dc000093434f65405220bc532f38e6991ceb74fab5edbcfa1e8f411890426511171542600df259c92f5330ab048f4ff511e6aa35f8789dabc7cfac0bfda4b1c6fc637a7ab634fb7900198e6b35516d7459de08176635a62ee9083320c431ef52600c1532ca5967e9c6d643ce667253ad5567d201d085d68bad39a007405220fbc7878fc0f42016837db7eb644249400a9a017bcb974d02b944b28afdaeb005309b7e3ab7a98886079eebee33b11e20aeeb3d3b24fcb699d42e95aa94b8f70974ccb0d64d63471c6a2dd7b023ce1014a720be95c5abb055e0212a90efad57b8b63e6c9d35d47601392c78dbd492bfb56731405220f1fe07547166e9077e1b6fdf9d986f9be6e8c9edc0520a407022afe0497a4311307416768020b836a3833a6f48bf5d6096ca24ecf8f28071cc07ea13283374a49c768900a1abadb177fd056b47b07c1d26", "bab902a5dc3fa0213148c367db9332e31893c6dab439e2cf47920be05cd64e46", "625e8da3f11eac0805e494ea05c22ce45bfb0831ad6ec30a846935ec8f09eb6a"),
    ]
    for u = 0; u < update_paths.length(); u = u + 1 {
      let (sender, up_hex, exp_th_hex, exp_cs_hex) = update_paths[u]
      let tree = base_tree.clone()
      let up = @types.UpdatePath::from_bytes(vec_hex(up_hex))
      tree.merge_update_path_nodes(cs, sender, up, group_id, [])
      let th_after = tree.tree_hash(cs)
      assert_eq(th_after, vec_hex(exp_th_hex))
      tree.validate_parent_hashes(cs)
      let gc : @types.GroupContext = {
        version: @types.PROTOCOL_VERSION_MLS10,
        cipher_suite: cs.id(),
        group_id,
        epoch,
        tree_hash: th_after,
        confirmed_transcript_hash: cth,
        extensions: [],
      }
      let gc_bytes = gc.to_bytes()
      let mut ref_epoch_auth : Bytes? = None
      for lp_i = 0; lp_i < leaves_priv.length(); lp_i = lp_i + 1 {
        let (my_leaf, enc_priv_hex, ps_list) = leaves_priv[lp_i]
        if my_leaf == sender {
          continue
        }
        let priv_map : Map[UInt, Bytes] = Map([])
        priv_map.set(@treemath.leaf_to_node(my_leaf), vec_hex(enc_priv_hex))
        for p_i = 0; p_i < ps_list.length(); p_i = p_i + 1 {
          let (node_idx, ps_hex) = ps_list[p_i]
          let node_sec = cs.derive_secret(vec_hex(ps_hex), "node")
          let (sk, _pk) = cs.kem_keypair_from_ikm(node_sec)
          priv_map.set(node_idx, sk)
        }
        let (_keys, commit_secret) = tree.decrypt_update_path(
          cs, sender, my_leaf, up, gc_bytes, [], fn(n) { priv_map.get(n) },
        )
        assert_eq(commit_secret, vec_hex(exp_cs_hex))
        let ep_sec = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), commit_secret, cs.zero_secret(), gc_bytes)
        match ref_epoch_auth {
          None => ref_epoch_auth = Some(ep_sec.epoch_authenticator)
          Some(expected_ea) => assert_eq(ep_sec.epoch_authenticator, expected_ea)
        }
      }
    }
  }
}

///|
test "IETF welcome.json CS1 & CS3 cross-package verification (group + schedule + tree)" {
  {
    let cs = @cs.CipherSuite::from_id(1U)
    let kp = match @types.MlsMessage::from_bytes(vec_hex("00010005000100012028b2cd6417984dc4708c61a1cce7c0f11d181bd36d6f7a610ea21cb96f79ba6020275d9e6337b11a5e21ba755f2353053a500103efa1c5ac7c07d3a78f8817ad2d203de79c7e370156ce25a88d897a8ea7c8f90fea1f71fbeb5f31855312d8750007000120b640fbb0df8e646b29c83c5ed08aea89f72ab108922827ea76cd3b917d6d99420200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040fd81837a40a9ba774bb44db665081f4d0ff2a8f680ce5c902b17acc4ae6d9a14b9d4e9b4f8e7d74af8ff42032ec9caadf267e85931b550eebbe480150d4b9b0a0040401ec696ab731d5a7b1092b0db9912fe35086e188ce2946996bdf3cec463849f1a32f653b6e246b8b85a486ce3f604891501052c3d7bbee2155fff6a367e5a1f03")).body {
      KeyPackage(k) => k
      _ => fail("expected KeyPackage")
    }
    let welcome = match @types.MlsMessage::from_bytes(vec_hex("0001000300014076208e1faada70f08b91ef7f7f79ed1da917d9ce3cea5e5ce22e4a8b10f4311559dd20a87de170e9dc54bd4a8a48f38cd5c949f0cc82fce8ea72232417975ec6bad95033f6701d639694cbb51a4b2d0191f432add5267eea7b33f3c0c7edc65a28650adb0008f08b84a420bf1070516cb079a8e5c4159a40e80bee12b78b86d125155b035f52e8a131469cf1b9645d70e270d3aa21c04945fa80b7fea30ccfceb436e4df23558cdc1a6cd435db3199314795b7c488b4bf0855cb589ad9c7eb43ea8bc9edef6b85ad1c97451b706e5de27aabe664dca132a288b3fc091b9100e470fb506833aaa4ab279a44c92c21e34dd295b6e49978d8c93cf20537bebc1a467177500d7fe6b127d5b3d13bf038cd2e8ec00937db6fd4996b2f2e416b810d0822b77bd71b59bf1e486c1ad74da0de9872f839b63928a03ae11e4dfacb7cf27ea2c35ae233d9c63fe901ddd4e7be7e643912bb39ad8a728792753bc8314317388e")).body {
      Welcome(w) => w
      _ => fail("expected Welcome")
    }
    @group.verify_key_package(cs, kp)
    let verified = @group.verify_and_decrypt_welcome(cs, welcome, vec_hex("c697caf7ae54f695f9411d9dc81a206b91fabcaac62a13763213a045ecd72b1e"), kp, vec_hex("4e61ed19803e994259745f59aabd3f0be3c171ae99d49a29974b5a5cee134241"))
    assert_eq(verified.group_info.group_context.cipher_suite, 1U)
    assert_true(@schedule.verify_confirmation_tag(cs, verified.secrets.confirmation_key, verified.group_info.group_context.confirmed_transcript_hash, verified.group_info.confirmation_tag))
    let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
    let (k, n) = st.application_key_nonce_for_generation(0U, 0U)
    assert_eq(k.length(), cs.aead_key_len())
    assert_eq(n.length(), cs.aead_nonce_len())
  }
  {
    let cs = @cs.CipherSuite::from_id(3U)
    let kp = match @types.MlsMessage::from_bytes(vec_hex("00010005000100032028b2cd6417984dc4708c61a1cce7c0f11d181bd36d6f7a610ea21cb96f79ba6020275d9e6337b11a5e21ba755f2353053a500103efa1c5ac7c07d3a78f8817ad2d203de79c7e370156ce25a88d897a8ea7c8f90fea1f71fbeb5f31855312d8750007000120b640fbb0df8e646b29c83c5ed08aea89f72ab108922827ea76cd3b917d6d99420200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040fd81837a40a9ba774bb44db665081f4d0ff2a8f680ce5c902b17acc4ae6d9a14b9d4e9b4f8e7d74af8ff42032ec9caadf267e85931b550eebbe480150d4b9b0a0040403a9c005610287480d74ece89dba6696a3c1bdb4ffe0da6c60824ad7ff3809e630fde475d1f24e3cb9ea6533367ce8654ab63b59875b905ead1af05bfec282e0e")).body {
      KeyPackage(k) => k
      _ => fail("expected KeyPackage")
    }
    let welcome = match @types.MlsMessage::from_bytes(vec_hex("000100030003407620f5c79ed89f7806b7da95df92ff6c760601eceda0d7017b82d69a9df7727d8b4320d2481a99ac83f36f552ab3176394eb739a3985fbac1a62fb5bff9ca4e4964d3833d3073bc3428958710169b048c854cefe52554e88c28a7e6e82c7469b4fd30239fe03a09bb811811162622f11f8b2aa741f63a240e825347868a893c650fa48d34eac9c586c49e41fc33c420e5bf33f6be1aa9acff5b551877391a5f56e29c73e141e2d97e2233bece24f7ca62e89b564722a99898e809c5879f7de08174418315c439078fe8e36765931bd0287043ab543350b53c910ac8e2186ab7a3ca29567e642acf439bafd5181f98c3bf8b3474dd7352893b55977f5c951ae0a40ce602b21c1c8e6d31bd3daff016b6deee26b1eb60bed7637fd791fc3f9b3f508a85945c5bcb78a092f1a3ab71bd1dfc3d3cf96c6b781b6bbe585b40b9b0f03017e9d80bd42088b371a0425367e9bb3e4844572510d8fc89109c85ade70809bd9")).body {
      Welcome(w) => w
      _ => fail("expected Welcome")
    }
    @group.verify_key_package(cs, kp)
    let verified = @group.verify_and_decrypt_welcome(cs, welcome, vec_hex("c697caf7ae54f695f9411d9dc81a206b91fabcaac62a13763213a045ecd72b1e"), kp, vec_hex("4e61ed19803e994259745f59aabd3f0be3c171ae99d49a29974b5a5cee134241"))
    assert_eq(verified.group_info.group_context.cipher_suite, 3U)
    assert_true(@schedule.verify_confirmation_tag(cs, verified.secrets.confirmation_key, verified.group_info.group_context.confirmed_transcript_hash, verified.group_info.confirmation_tag))
    let st = @tree.SecretTree::new(cs, verified.secrets.encryption_secret, 2U)
    let (k, n) = st.application_key_nonce_for_generation(0U, 0U)
    assert_eq(k.length(), cs.aead_key_len())
    assert_eq(n.length(), cs.aead_nonce_len())
  }
}

///|
test "IETF psk_secret.json CS1 & CS3 all 22 vectors + schedule integration" {
  let psk_cases : Array[(UInt, Array[(String, String, String)], String)] = [
    (1U, [], "0000000000000000000000000000000000000000000000000000000000000000"),
    (1U, [("55c388e0e99fba6c1633d6b70c50ec3def72563aec7ce787847574bc27ed9d71", "e0a059e7da3660c691b5accb5342a0940f0ac7ea4ae4c886186249698d845860", "66b25bdc9086da6e266ed0828040d7a9547d20ddcfd2988d48113a10afb5a23d")], "aa6ee4e7ac86bec0a39c185ad88995e9b86eea9ecca113691090c53bcc86344c"),
    (1U, [("4e96d00ea2059b6c70d0e8777970e65677abee0c4b90e881c4cf7b4aaa8d9184", "62e3157cbb3799d0f54fb873e7f7e46257a01e9e4297413e769c4f0afeb1a206", "924a5371246476aca6a92eec7d295af3c9ed3f905aaeb97dc4748ac4cdc889fd"), ("8034d46a6150c7c4817f7584edf51006ec8432c55ae1de77d0ccd51c523ed97d", "27f5dd47bf87802cdfac24f1bfde71595a62ea8bc6a9ab335ba23c98d5fee267", "07ade6664316831d1ceddc1f7f8b26ff132f7130f4c6c6c51f07191d8f2a328e")], "e582f70f0b6a48dc9a50583895bc90012147e59bf7ba90b29673075fdb646ff2"),
    (1U, [("42aacc1afc76b1ada7a60114dd51aa740301ae8d4686f17560fffd29bc713e2f", "013bdae5ca37feb2e7cfa41a9fe09fc3f3d0784f32db2e7f0c065a0d4aefa963", "1be1e330144602b77c4205b139ca8b35e380a1f961efdbeb16a9516133c6dab9"), ("b4f3ad1afea819ec085d03d2f6c09ad5223df36ae3c04b4b309b3f86f0718708", "3781c20fec9b8df596b485aa0f7ba9107347a0fe14ff3d90a91379938ceb2682", "86ed1b2cccf4d67c588dc9b820eb701372215829bb5836f1d76e997030f48be6"), ("f8b94054d4ddd4040ac8e842b9a1cc88060ae0d0434b2543be14d0e9143d3b08", "6ff21d47faeb5ebe292ee8edd7a85e8650b8e0af483eff99c0c3e44fa3e459a1", "f3ae63a6abc2730c1620716bc47ce230da09da55839116d2ac7d9723167a36a9")], "f53ae4e49385c8655baba15eee503cc6a62898e459275a4f809aa07e9276dcdf"),
    (1U, [("b50a24a843c39597853e5369cbc0ff6e217dced2bcda45a4178f343ac6a6b869", "215f03b3262bf139a1f5194677a00b3532bc15ba6efb50e5aa2a680ed6e10438", "36522eb9210800490a7eb3e21ff9a32739e1d0859b9c1c57a510a9febaa48111"), ("abd00df4d4f2740b425c8d7bce4baa0cce09e04b06a0b35f007476ee515135f6", "7dba1c449de997096a524c2bec39ba0996987148793bacd8ff4aa99cdff74af8", "b304c6ade543ef54fe75875c21472d6b1585768517b3182c7e5b281423fac4cf"), ("74727932dee3778b1ffbf7d47ce1043839fbbc09c87953a1516a94bcd1f6a3ab", "3dbba7c5e1712adb2a90cfbb97e5689afa7d770a8c1125800ca1813c36c95ca6", "928189bc36e840898221218839832f98c3ca18b61557b76d72289d8a54107808"), ("1040d64243fe5e852805295c89acbea99d0785ac730c72308fa30d0def8e39b3", "2fd49e925216db08a9dc320fd9625e0bbdb6095da1f61b2e8ef33f1574b85366", "b23cc14eb856af892cfda85aa3f688d2e8ed2a1baf93214c333062a09dd3ee5b")], "57b3f32574edaa3d2f881e75107a6834da8b7217902c420e394ece92d2412fe3"),
    (1U, [("6d2f24a484ac5f87c48e60225c65147103dc807a237e5f8817aea47a99ba879c", "881a1d7c8da36746dea7cb562bf912cfdae244d6eb3880f9e0f1026548dc31aa", "e66f4bf1ec1e7c74af56dbacfaaa35086d94b02ec3c61a196ee6b3b33c8ff77e"), ("659f8743ae60d9912d159015d11fbf18f958cc34fee295ce89c8f8e767e04f8a", "5dae210592a907d51714fe5b177d3e442ea3070cd47a2e1908141c7d5409f99e", "b90e11dce8cc91ed8f66beba3916700be41ee147857cc049e7a83279452e1ed4"), ("04c16c0d7da83056e2789590241b5aba7bb2d7ccd7faa44cc71fa7b3e2032913", "47342226ce7f05631f4f2b7f41dfed85d93c2f1d414b1a2d756d6b6d4bdd6ff7", "db781f2fac3c9cf9af6518ceec69af91705479ce7875a1b800c966e84339b365"), ("a04635cc93eb1ee945062d76b828b1e5bb11c681c9d8358e9de8ef1cf81ef730", "87b11501959d512b844a45e282d57daa5140d4b4df2b76f0aec4f72f9899c042", "02451bbf8235edf8f05209b94e5c7fc21657b2ddf47ce3c7fcc415a821bedd23"), ("1a1a328df85a9d8d25bbd744ab17cafe108b6fb14ce9ce5c3ac08b3b9c4da5ea", "633e909efd2bbbbc16ef63ac1a0c3e69fe9941a7ab32310b541736097e23ffff", "f3149ba9c6de3acbc5c60d7692981ac8f94726c35bbbfe3a4333bb3efbfd2df5")], "2479d008ad482e524c53c1c60f34f75fa5e9df3666d3abff6e7fe43c3fd5d0e9"),
    (1U, [("54fd491faf5ddbbd1692dfe8c37eeeb9ce807e4544ed88c89294151a7e6382e9", "4f3e8c45c34e76168153869d9d59d16ea5c1f566c2a0c7bb4b63ca103f2869e3", "8feb757cdb6323d6a7a9724d8e2d686b8a2642a01f4cdf1053cd604b3ed93089"), ("85096ace75ba1d1da42b9b532ec6b8b7e2e432ced5a839384d55793da3d3685e", "8d1c60870916083a23b457dbb7f335459c715f629e013bd38e8b37a71f480fb5", "079873f05fa0f7f56812911a59efc6b1bafbecfcc98216bca381d899e2dffeb0"), ("de7f574ffeba17641b1b128f04f4055b56ea1b448753e1c8632fec70d8e73400", "d3ee0517724d7e42115fb10e32b92f0c32c057cda070ec07f648063ccb24b6ba", "a7272ee666823009c49b6e7a8b2dadafa5eacf054058ab7cc8846f4b728a2980"), ("ff2fb3547db4f2841a157eafdfd06c685b0a95769f7c2b7952716b3ba80720fa", "452b599d585863351dd8939152be131b01f58187bfb49d361d9b5e9793a9538b", "2a4a23f4d0eb6be9b93af1dba09ad23471201001a2c28154386a5289854ddc0c"), ("6fc81997a9058c9fc227b891a611f0b5d7604cd4a6ebcbdbd5d2263e4fe5b1f3", "741740669bdcba01747f120c5d16e3ffc21beb32c9db2139b64eb8300a324ce6", "2bca52c0903e5c7a69a2d96da46eaf048f189c141efafce0e854b162ed43190e"), ("0d91272f99b304f0432b52d1be12abc9c0be5d28f6a1cf6e6ae758a3f4d6292f", "54a483fa861a5ef5e92ad0bd695b93746fcbf73710ff89bb4646f8dbe3cd5e78", "a24fac42b3e9b8cb3e251f9255674ec11f8ecd7df4e9e7c6885d90654036155b")], "9008853aa205ac1009b36b38d0aae0f69b755b9097ccafb4d317a64835b8e098"),
    (1U, [("931d4c0c019961f3fbaf04884cfdeb026dc0b545f8f604f9f2f1678d1ece7bed", "ceabc5aaabbd8cb78c81e54f24ff641d0e3b7cb72d5a7de0f3bb2df4995c85b9", "599eb3bb1fab7457f5c6719654f3a6df78458ab98cee93593f116f2a4efa0c5a"), ("9f05d6afa95d045720bae6f60cb72a5f5b108b7462158f1656f050be8bebf8f1", "56e09a7a486c3d70c19adc316a0d9bbbedc2a33d3dadd6bd005332fb7c803218", "e00490e721d824c21d99d03b4e6ad352eafb15ec7668090466d8a02408eb9fcc"), ("7fe78c80b66e2d821aaa497725226077d7c49468944fe201bb19f3c808a1bb84", "ddb34c423e34a97015e536d2c9098ce10983078f2c2ece0814ad458f38bdd9b4", "db87226e138c65834a59da989653a1b1b21998b40fac1b7a02ddc7bc56e689da"), ("67e3eb2ad644a77330d4a5c0e54c3966d97d448aa3602beca3420ca8b6ea392e", "41876779789c8c6d68b8ef83720895ad186fbf5cefacb679f1f0cae1f9532843", "eab6d1d0f2f7b9e3840235a71d2562530e0b96d5982ffa67a3a3449261d5839a"), ("4caf9c0f518493699914999d6001bb48437d50eb0834b85f13339e8ed0d79dce", "7f9b42337bafa1461698b9cab6efc7e7e9b347601f14c0e17a7152067c49f40e", "ad35ff9c129963dccc29cf525792ca77ad0e0d0fbf4a134e0d5a239f5229c06d"), ("e4493bb3e989a18d5f79b7106f50b5750d649ca850fea7a1d787b1bf27e857cd", "5b10e5ba751264b318756e31b8b25b46ce2291f42c145ae491966bace39cebb7", "dcd53bb8098d75ceff74e0b10c23092e6dd4ea07dec079471143a659322d65f2"), ("d23e12d50892a71c3ab080555f3adbff9edced063308ad236dc6218aa897591f", "ee454f9d626a769d5d20dfeaaa8a4f743775c326788f24f9170ebb0677046b62", "8b78cc9b05a3021955d6427236ba8a8063d36acc10e4809f159b358a5dc4dba0")], "39f6cc5caad75ea25016cbd19881dccb745810e0b1b8c2cb72ea55cc6c756d41"),
    (1U, [("7416eb8faaa77298d8f608f953f180f2559d9b3fa9f7d97d6eca37ed0c24d649", "6be310ed7b0ea27dc7fc2fc36babba10df3ac0a9fa8c93f9af2370b1c63deb1b", "9db85bfb0898d8781e7fead35aa31a3135f9b7d0c341b504c426db87230f7929"), ("bbe018c22961133a99f554cc507f48e2832c19ab489256dc7b69f39b8b6b7815", "5b295f732b36171fa9bf380a3792e9e7ec12a7334cfd688b07a690b431393615", "c8e2e289bfa69359f26f504a226e370079cc0b14f12ce3a95581d9184fdc614b"), ("69ad7e548babaecd04bfe753d897bfc67063085cd16c03a570af5897b5d9c18e", "ca1ecdec2ca35bf66f85ec922668b30a1bf5fa493bc6bcc51fbdd4bfd1bb9682", "5f05b68f3a2a086ee491061eda3ff82fa5e4cc8d033e44b97a84faaa156236d6"), ("de0276069e15c47abff49a17a9557794cc9e729c5a7d2663035efa30c3f7b0c4", "ae9ec5ec2e225531fc63a31c3e8f32b74d3401fb7c7c54380d6b6eec2cdb3d7a", "f938c3a4fe8acc6bd47141ac60a2cdd0b09b4fbfebda5d2b7c6d3344e2842cbc"), ("e0c1da8264ce40eaa7f7069a1227f414b21d73dd276f16dead8b9cd161630f89", "880ad8c057b149f956296fe28c3cbb6845433b8f4fec45c62c4b7382155db1c6", "52942a66abcd7256fe347ce6f9e65e41b115864077866559f6e993c01bea9927"), ("9a1f212b59457942eaf067f487ef48076fd911059b0a02c04450407dc1d63bcd", "6c21f1ceb39e3c259bdb078d91df608bc94d0521a303938186ee388cd38ca8b1", "afcb5e1fd39bb79754e18a3312f0aa7b2735188a96b87b3d6d59f1ea18d6ab64"), ("efc71d3d43b597df96d29d69e542beab420b8ffb42890ed56a4eadb458404be2", "913fe8c8f6d357eded5e72d2dd5322845d6f451ca2fe7413e2d098e4f6409095", "ea086ca77a4502a578affe9582635969625639a4bcdc4e7c4e611adea168f2c4"), ("80989c70d0c16bfe16178677cf86e8bd92d782d41b3cb87e72fbd15ce1820ff3", "5d0789ed20dd8e9ced5071c28028384eafd0e964afbd7b5771db6bc7f8e3d2c8", "cdf8234460643eb740e8537706efea21b34c32e7c0720eacb5861055ce75cd34")], "b79ede2883d907d9d02464e87e04a2c9ec447671ee4540847305ac36e2df7ec4"),
    (1U, [("65ab91b9a1e25678f34f64aedc4543e607a5bbab9b00207daf060d12d5aa1ed1", "0d1f00851f00896248dbf15428a7ff53e7e7f404afcf89cb92fae9c91f005cb1", "5843ff07f660bfa6558ad7b028d38c3de9060ed13dcad4bc48bb664c6b3beae6"), ("7086225f84eb5eee0f15460418be0cba06be44cd9260fdaa2871f5b44670f577", "98f83df2c2d955c3013cfdbadfa7fb09e76e39d0bcf20d4ebcfbc3d48bfaa0f6", "bcb4ab7b9967c5c0fb821e3fe190656ebaeba317ebabf5e0416d5c9fbe543f87"), ("faba2d05c2b41f380130daab701728980986c4303b25ff2a1f003f80f4b5cd59", "920333177261a23922b78bf640c7841e1f4990cce7026fcc2f9aead9f720fb47", "f0373d574ec9c5f380a36f0ba0bcf197b1c508c095c409425fa2aba5fabc455f"), ("aa5ef7eb6695184bfaf43c9705ca73b7f3bd63cd11f4d7570b164c567dcc5cce", "ecb03543a81194ba5820e7daa1c6532adee027ef98740e9fb3936453e7bad59e", "36417c801af471c7c79a4b162c9c2373a07b46239e78ba5bf34d55fe9e630fbd"), ("0ce75fa92f96115d1d33e4009d145abe6e40b79347dc38e8f4ba58b4258cdc2d", "cadc9205c25ad13fe3b4651350f1890019f40ee5014606befa42391b6868cecc", "3963f1e18e87edebc6f0bfc49fe34730c2090fc8c89b9f1fdd389e22047f7a5b"), ("cd40d2de9e69a8c8af26f36ffbbbc65e808ccf38795f630612cffedc271e3c64", "f1ea566af86a64ef019e14430acbbdbd7a7a763cd7f9ac4d617c29a5b143436d", "fea40f4fa3067e60546d5aac3c15c412f06a4cd236fdcc414db1f8e1db7d8b4d"), ("0edc8299691ea119ec2ec955337e80d81daf487f8d53737af71d77843a66b5b6", "0699bbecea948eeac33a2f7e7d8a97e708afdd138e95aa1aa88c0d573e0a9728", "c0a7cbe19f78ee3c4f124993f79c8e5ef18538d35f9fdbae6df7d6eaed50d855"), ("4f1f8caf76dbe3c8799f77a7c49aabf99f66778465f8ac955316b073a4df977f", "0b63f71e7fc2c605a94a09dcb7d3ceb38b1bd70044fee865593255d53d51b054", "435f6489f92f58c12c4980a3cf06d7753da34353bc29386c7a8d9bf0c38f0909"), ("25833bcb726ec6e3c779cb63a01aa39af43f96dde6fd77364aa70f9851b452f8", "25936ee456178acc21273bb8d0c28bc745c0853bc63aa5e81a5d5e6363641a47", "44cffe0fbef7f5496fc8d8b705064a5ea15f6c4016da212a0ebe253512861de2")], "7b6e7af18faf0f1fbc22b186d5b06e1a1333ec5430dcc1a3ffedfd1637a9714d"),
    (1U, [("34cbc7ee1e1f5d395203a7dee2c6a5a9f3fa4616d81bcd7cf28dc3370455b32d", "ccc8dac9daee41aeafc255bd9762e5c194fd8f11d315746b0c1068e9b1a1bfa2", "766855fdcc856dc57d97fdef7be78fe67debc2e597d09b2782c9604fc305cbff"), ("1ecca00dd15e3c8eb8ad64bd897846b1c0245ae515ae5f3c7847037cea4e4611", "fc8e3bf876302049ca626f1c008fc3928354e029e0f7139f519bd3ab99bc0b17", "8668032192a52ec0c9eee9e9ad22ffd120c249c16f3c6818c6fb58516c27d705"), ("e1493d8b46592425c467faa2f04ccf770b715bdc7a0ac6390440a946a64dda93", "3109f4a631560b32350a983d7fd948cbdd4e66c0a97f126e1e8905ce930e55d8", "b74ff64b90242bdc0089d8409ab0343b307ed3f884222812aaaef18738b21ca1"), ("1a7dba0fdd4862468142c1d4d49169fa4745f3c6553ef951e3c23b4e352d5c77", "ae5e687afee3d7a8bd028ffc305715da86fd7781aa4dd3ee6d5e2b3545755dda", "1dfb9b50df98ea2d80610364ed127061b02c4f2484a46bcf5589af5517c7bb64"), ("d2f19994e2a33d6855a6f8c0507bad09e3f0a60d9d40b5a744f2668f871431e1", "05424199c8bdd307edaa9289931bcee843fedc34f9c448ec799f20dc782a89cf", "050679f0120a25b1bc18f47f05d69962822016728b56923068ead8e10c966053"), ("4bb31fc6f3608ca2b8cd62d7ce0eec475e6add29670aeb1011a87073135745a0", "ca285765cb0247700cd02939db7d8df4038db1e02483692c4b858d7d34299c08", "c6d8c8416d42acd3d72fb5eee7f5670508617d6285acab1c0b57d637c21f0de8"), ("6f812f8ada5fac10d6412471441a0c39e1b4104c235dcdea152b6cb51d2ead17", "6f9a4419b241f737747b37b00328022c047165717bc9a1b80ed0f5fc4a79a29e", "03bf6011f57d5a8c5bc994839bf4ac17e39570d413724294a12ead16938a6da5"), ("b2f6db3cee3e9af24f585856b007368635ef60163de911e90a33b7db4949181c", "e7da72d25877b4f1c503caa948fd04ffebfd4e444fd65316c17c40fcd68e75fc", "48f414d2d9e63cdb91f5c4378132780c993e35987d49471a1d20ff8ed3145713"), ("e3285170cc7a8c6b4398924b939039b7b6b63fe219f59d8caac1f667035a060d", "0e3fda1ccee83752cad5fe74c0a3858571d0d5a0d769ebbcf0c2e79ed70c6acd", "65dd0e319803e0361178f0ce6d64af8ecb6992644695400f532c2760efb6eff8"), ("82fe2da78f8d5a56c09870e07c66dc89b810840b9221ef0181fcd3dcda37f0bd", "7ed828b6a156e36a16788aee05df12b73d169e6a9abee18ccddd56b51def7e1a", "8f31dc83d22d4df129e3db3e0ef7d1ce361fb942ff087712cf502699372560cc")], "55cc191e0d3a186eff36f73c343e6d0b9e33a66296ffd29acda8896b98ea974a"),
    (3U, [], "0000000000000000000000000000000000000000000000000000000000000000"),
    (3U, [("9993e9691c59fe7608d34ac5922d7edf46e1b492a489e1de5710d562184e29a3", "248713aebd26ad481aed25a7d791ee26410209f641a12c3492fd1ce5ed856e41", "d3d0a9a654aeff4fb8213169edf092f27eed261c05d92772024c2c5b257b2b40")], "2300f5daf24151bcc63618c4150d75adae2dcd5de0f8beeb866fdb2b5019960c"),
    (3U, [("c4e57766aa00414135b98e60b8e897896565af0f3d746c32d04dd4cda21d2299", "4031689beb1bc9408e50f3ddbc04f7390e38afcbe88d8090c1a5a3e7469a8fc0", "daeccb5a5522ee2578427727a6091194ad0d5a83ea4e0a9318ac27758d03574f"), ("2ed6e6c554f046664d1e370fccbd64f6a9ba0f4163fd2785a8eb1bcf865e8b8e", "787e4bfaf0f4f73624ae0f9f012e7cb554f4dfff31c8c57df7b091d4cd8be903", "d3ae0fea4056bf88ff37ebd6efed07cdb41f2f306de9d88ac5762c2a245a8545")], "4137e7535a749ef9c6055be84e2850168d64fddf843efc210e199701d088174b"),
    (3U, [("3d8dd0e24cd5aadce0d783b9e359464b244f54173bc2022851fbf5c95c69ebbe", "3f1368d1df4fcb50eabd68fd3cbab8e5747a198d196a1bf81295d5956bf46ed0", "446eeb4b93bf2edd1c9c9a2107f5fb9afe8c2fe1992bb1c622c276af5bf78c3b"), ("d2e082dc0a266d1f85a70104f67195d52626a6ae7cb3c78e5a1e908d5a51215c", "60d196f0ae819b12334c093eeb5f47bd982a90504744aa66114952983cab654a", "6bad1ce868e3b8811f959d566f3bca83af90998cd12fea7cf31419beee361108"), ("9af31adf6dfec4aefded085eb56f3b7a76aeaf9670a60d0421435fcf071dfe27", "d18a6add3fb1a8ddbca28503fa07bac7ae631b719309048199cd5dcb212c81a2", "9c230e7e004e50f92c312880bb06c440163f6179fc89c095206e419b4168ed2e")], "41160ff11bde63bc79c72b84231dd18347b1baeb43a3c163efee6c675cf73a55"),
    (3U, [("14bf51595dece569e349634c2b89d1f5a99c20f62bc1140473b892fdbf1242aa", "6439da277de1de3644c48f57a7889cfb40545f9f219b517af97a4cff7c185ef8", "fc1f47d034b45ed2d5e81faf5bebc1ab5853113618c531de30001cc3239ceacc"), ("63de05bb4b190abd27a76cd6a39c053cefc21e79061c70c9dc9aaca85295bb93", "535373cbcc857ca51525cdff406f0dd0b8e4ac662b1200c760e9d745131e91a5", "4d523a1a43e36b5659deb277871036c0fb8fbc0e5ef06c80d4a912d5d72ef0af"), ("3bdea56c586e3ba1222f8e6f06069fa93d293c25486dcb191f9a849d0a8fbea6", "c35d968f5ca049f8730c58d5372086cdd71edabcc194e404c3ba34a304cb71fe", "4c13f3b6e14c1c6665cbd1d2ff906b9c6aa367561857eceaf2db541f632ff503"), ("3c2038d096f8bca21a94899522f348d94502ef8fce4b9859de960bb19b7eb463", "f2f8a9e6796de226e8b030281015fe3770cb3a14d121efbede0c4b96823ba719", "436207ca65fbefea9751630aedd3dd326da3c4ff9976ce7d78fab83a6cc3ed29")], "7b815493e0c968dfa2f445291dda376a37676ace7f92865489ac2896af03ef49"),
    (3U, [("43b290dcdc4d2c813aed5ab32f9b69e9b7eceee3a24ac838f2c9e930f15b0c23", "ab2bcd1e724983aee7f1c453661842364459b1b464e0ba3e69ead175508606a8", "f8115771b3496f7a9a7355e677cb794268f51b9a26a33c0211fa8a7842b2e0ce"), ("bfc17f83ac4fa220f9f75710587435f517a944e6caef9fada7f6f534b1c3adeb", "52b01e28770a2a8fe932a168534b573b751e1fd4d067f1a44694ffb948b3162b", "7178548013105df7e70f9449369eca80c7479247aeb25ff51a57753383d2d20d"), ("98b2401eed50769f9bbf1c53602e3889e13a12ae4798847c16dae9a34b950831", "8fa30f1584459a94ac654e02d4b2945f2381ac4c018569bb12f7a83d0dd67c78", "b2c854adc63dbf1fbe791bae411c7cb73f507db3ff86d29ed2d569f655dcec5b"), ("8bec9eb591c0ce60f442a0e7260fe2f3876a1be02d755936cb7fce3b8060e0f0", "053bd72d0d845fe7b9804b29a01d59e598d70f651c1c6b2422ab3935db324343", "078808879a24ec2cb8e058fc9cf4a3b30f061d8f743c65358bd7d6d6df81d8ab"), ("f266f8345387eeddb99ac6b4ef7114954e624261e5fb73d02f73439cd4b8bdee", "e4ed1be45271533120bad3c79df7f3f4e6ab37f377ca4fb328afd165a2f8479c", "401d05b5003aee1d968c9bd2cc6591edfc9c87f78a6e44a8339eb25454a7b4d7")], "714bbd3f42bfd7ae6a4bb9a5544837bc8b603f08edd00d4e4b02cab525f9a5e1"),
    (3U, [("a705b467b27f3f3b78604ffadc328a4a7ca65b7c674d97d8c0bdffab9ab2c6c9", "44a497b2daf955fc5423aac357bab5bf6aa04696992421f56482b1e75b820d14", "ecfc52bcbc6cbeefd26905a1414e42d0ae6a9ff45828d6eccc0e1d392a4cf56e"), ("9fd7bcbc8679ae61eee56e7f9c84acfa11bf3a8737a9c7303bfd379de91d639d", "d5f0bcbe7b6ebfce11fbeb2d909a153abdcbf8b36866f7d148bdcb950020c4fc", "2d83e867e353cd90ba082c9fe14ac58b4329a59382580d2d952b005a8e48d9a5"), ("92c9c86dd67155fd7e5e74d1a573ecc4ef98b677fe0d17153c744713ee942eca", "6b166b2f99b73e3e5fa1302d5b8d2b6958a3056293c8817138bbefc816e29a85", "fb04908361cec405dc1d2b7c4d2589dfbaadbd4803bfe7bbf3799f1400313d25"), ("cd7be6f22277bb471db14125b487f015edf35918bf5675375df3d42a1bbf9b59", "7da00755f80059994209f5aa7893a3b63d8db82d0207d2af1bbfba1dcac338ee", "e5debbf8247ceaa05df141d94efe29507ea32ee2446c2c048d7e0463dfc4a452"), ("ac1845834e2c6474f82d9edf7f7edc1bf88faac9283dad4bb863e282cdcc9cbc", "75b0e2621305c452f092f9133411ef34b2f6d341d6afee4f57316c416f09c2be", "24b4b7f822affe0f1bce07f5e789f53974823fdeccc33da9d1eeae5a04b2ad8d"), ("72b34e5a0106ef23e96bf3ada9acb03b6ddb59a87bfb308a9c4df1b0aba6d971", "9ed336d45f82a395c465ceb280d7733454e655f20b327a5337ad331c5b035e49", "36465a5fddee8d67cb7976cdf8fd99fdc0c9938c6845a9d21fa6ef442e73a6a5")], "c0c8204a866370433ef074e2060acf5863b2241f51fb49718ca25d2fa2557529"),
    (3U, [("1dc4326763117cd137e56c39462fcbb5bcb25bbea9af0170a530db304f10978c", "6969b68151d6ba7060ad726c7a92023d3ea77f8a9bc93df2cd3eeae5030fe57b", "0798c59e031e8bd3523f47710e517006ce9fc1d4b4eee282ad03a90c21e9a862"), ("d0cd4e703de1c13300da557e3ba2600b3f41ae1b2de179944a8d038f40ef9fe6", "69f8ef362d07ad2810df1f8b6a57f31dba78b9ade98359b233f59cb17fab5a76", "b833bfde6d53e854042343fd1559e74a3698c8feee154980a597e14de97b61dc"), ("f2e2a55e36f8d5eb9ca882a54562d6090915d0d6649e2dda7ef04e34eb5079c0", "a0fe2037b7070e2b6e2947a5d7b2104acc68f508880c24e1c6fd2b9ec77ba7f2", "d3ac448980c5f14a1aa24b51d301e64211fb31eb83f7f55cd7d692787caaaad5"), ("3dff5c414de7b04d831896eb9d8a5dfae7e18768747667556af231faf1b9d855", "3799359c5f8345835e967b66a89bdf670398e1cf898093e72ab721bc30c233a1", "89560d23e6bb30d10faa2235a0a2a44a97ab8176560664882e46e4f10e3c0d49"), ("4f4e34fb9ecd3ab7c97b09969bb18767f8244027af3f0cb71e0caae740e608c9", "3c7d517bd7fd6503a9a202afa7e4c2ead518c00f8b9018802d3daa1732990c3b", "0e9a81c47c11dea129bd3f33939b04e69500d6f0f69819a9de77f20277cafff9"), ("d597b4f217a23d75092c2c6eef01ed00882883d25a76de87fa39465c6849a2eb", "e2db94017cbe3bd6f852e2736e6602e4458f5154037636737fe9424705bea2f6", "bcacfa14231288c9782e36f042c49baf63dfe5b88942e7de4211939a9db26e33"), ("878ea066429fbeae4b1a33f1413f255bec8eeac2685bd1df8b3f4f0c1459ae5f", "efd3bef843d810a95a831713ae6d1ffa2ca1f3a8db52d8192cf485a1eb54eff8", "c7e1570ca2d11f9a759e22faf275be782e29b6766f480907a23ea861f0b4a1fd")], "c8ed4469a2a757e3380e59ea3b61288be04b0e97c882dd6e9009f2c393a31c1e"),
    (3U, [("1f3ee651906873849c430681176a50ab890ccb68fe4a81d6fb0120c7c658b0d2", "cf7dc4aece635294cf8871cbb697edaaa2af026b18620d2dd087a7da0799519e", "4dae8b147ac0bd1b58aa30fd27c45a1a7f3b043eda0e547b8e28043ee34d6c9d"), ("5bbe95164718a34b41be7f172d48f5e79bce59136358f2b01a40cff1664fe17a", "82c47a2ce71e4b2ee1e4d5c303e24f95e571ea0f08e4a4d43c20025ed5995879", "53085407f89dcfddd5c9cb2bdfd6a613e7a04f3edc02d23137a795988f674288"), ("e18fe7d529fb31a57fdef1f1cb518c3c46e95be62173feca8fe4007d60606ac9", "ab850836f121a97aed81d348b92f0537cc32ff9d8b7212d37d18c526e25843b7", "7e8744c49e32f4fc02ad56158d19ced1f1dbff9c830894cb36d6931bb7b25f02"), ("ac4dd5dc214b85097feed19229e98d985dc56f203abd088aa776f393a01596f9", "f3b8267635d7cd19976980ac09bf2846b88d6b51a4dac4b575bfb114a18c12a9", "4adecd8c6527fe6dc7b89cc883d327a37e87aa608a22dd21b26b295701efdaac"), ("9490e237c2ddddda1b5aa98b9cc5f0bec75b2155e2959760c1d1afd73d910b47", "dbe7b8cf5c25ec8d9a393460b0ecf0909d25b479c22fb3ee1c3e935b4661fbdb", "1b9a00485eea3d1bc71a1d25b609a1162e419ff8efdc4305f5218ea31a931018"), ("c96daa6fb388215d09d1c084d5e705a903ecd532cb2ea6293b78062cd6dc2988", "953fe4473f1caa2aef1be58d99d1485d77a664947f7665c7ac5384ec95a4a00e", "e26020d851c99c9f81570dcd3d408a6fea11139f56be6821d33a4328976c7cb1"), ("78dd46e81cd09684bcfd34f70b021be97ed864dbb2efe0d24ed6d63bacdbd3c6", "ab07cb886460c96a4911be92d33dc735212b6cc4ef6632943df51bff18a75a36", "1f12a4bde6697fcab893f23cd1e38ddd6d022f1230a7c33b7ae723f2431b262c"), ("3412b0191f6f0fd3e1521f4c3859c2c5a5f4e35cece3492048209bfdf65dcc25", "52c05f3c454fe9c9a0bbd9f1fa428d3650f39ccfbbd83f7e683076b79aa49192", "4b8f70e7511eb7fee7a47638822aa0ca34ecbad09430f1a1534e8a069e7b341f")], "ea66d4b5a2d555ffd457bc3064eb3b500b0af97eea4f5bb3bd8e19ddad19a210"),
    (3U, [("a76c1d6a4a49bda85fa3df5ab898d7ee881ac7d6c3b1f1a1b4d765d7e59d6df7", "8eb14e73eb1ad431089b165059648f9513b125b52487a1d9f83172c263639ab5", "557ea88ad3b4062cbb0f0b09f2670bca2912546d1201d9ff0b977a71b21bef46"), ("c041d10b632e14972030ced82fcab117d13b4eac349d1da9f78e02a14e60dcdc", "2bb1abb7d30ae4d273eead1c747bf27249ba224b296cb8c3292dadd54ddfaa29", "517c0b859a9aab7b04b34ce52f0ca95d254002b073df4fa11ca3e1e5999f8f4d"), ("92b3c5887a370cdec91eed18da86453b9fa7b3ac76e5235197ad3f4977b7912a", "a2fc0f058108cee3b0221fc33b194af45bcd4657d6d7d5a792f708e8e2fcec93", "4fd5648f8ef63933b10b82f8058b9a47eee20048347255afa17d639f8676cc5a"), ("29277bd8669346fd316bdb4d02a46f446dfbdd07e8bd7e78049fe8a70e0285d3", "d1f99568e4c393d2c9bcf66268dad089f4d837f52064ecb7dc2551af5bb1f288", "4ddafe0d03a845b7f3f1a2494ba17a7277158878d0b90c1144a2381f5e4d51fb"), ("30ea43955b39b50508c987f538d76555afd232bd3ae7ba85417d536531dc3ba6", "fe691375581413bee701043204760de68451c605f9be1233b549d714cfa60844", "31102a40e8dedac92913b6753a49cc0077146640630b66c990dfc25a6371bc73"), ("595e9af955a0b03345c70a8c5036817215d809c6a651936c21c5d612e833fba5", "98fd1f352697c8fcca1097e94e056efbfe6be3d4c0b0307d8da67edb27589040", "f4971066a3883025ae19f8f60d28550a8b5e3652b71b86052d3cfe4c3fb354ed"), ("69a73b4b9aac85d61a5a8349a8d828e27b20481e3654311100174a93c147ea40", "8d78b218c1a1c9c8295a18b6958a1005be78f5575b07fe0d825708c29f1fff88", "06be983494923dd57b6405cae169a92e2f02c2c9f7370b59d61ab61fd742c6ad"), ("21112a5dffbbdaf074709091b7a0c0a56c400f84987370b3e3e7e96a26f1c6f5", "167ae6d6029d4495c0bc566fcaeff8ac31d51a60e26c88c26ad5ce15495e36e2", "a48fc15df4ce790a28d59a9fc91ad75c4f2ae493d626fa85f6254fc8d700616f"), ("4c9491d06d8644da8e0f61531232b18f1b501c8d801fc6b875b71c15fab74cb5", "9f40fab07b344f322a9603ca37b18ed3e6f92001f2e80849645cfcc1d091a77e", "6cfc4c41a4eb2ad7ccc24ce9949359c468b05b431006b8ac2968eed2742f3281")], "577e4470d60c5ac4441e7883bb0a52e45d29e2e0823c348c0ccd2bc07741c606"),
    (3U, [("6b2a06221a83f4052fa4d21a948260b5b205983a2367e1cc8436909f057fc121", "10c99d82b37079a0b1b7d504a9e49e8dd5597e00d43f45aefe2b85be9f0747c3", "5583d62beb37e6c7be2c0649951e6e10b2470fb500e0e73a1dd335f17dadaebd"), ("8aa35928a0e437d968a8bc7794d8c197a72b9e69e53ee097c57100c50207c865", "9220e7bc9df73bfe659dc6a3225b3944b667f98118cbaf0bba9b6d7be17aebea", "57e90f7e5b9d3f5b2c5258dc55eb8d5e63d0264cf9d6b04876fbdfb4ac1e05a8"), ("1f06359bd9e9956cd30173b2dad18dba77818a92960b7c027887904e495bbe5b", "9c2075146ea3aec0808d9475efb97b9984200f483bbb62a8a858b23aadcc1890", "ff8fe813bcc10059918fd59963ee89d59c7a002c89e2c3e496c1145070af8ab5"), ("3cda0520e984eefbda53af98183532f87e270d50cfa08104057a3a963fa2b5d1", "b8b939e9ef75a91eac7738b6387dd438c4d9f1c1356fdc6739b3dbf07c5a3f03", "eccd5685a4ff2fce9de1106245210db2f3dee9f8140fc4ac5904880cba1e7ee2"), ("54bc3d0158bad5677f8aa5d140e5dd1d1b634a66dc32741daaacb92804267da3", "811b5aa3b035313aa9a46f1c962bf201e256faf2184c4f1a946c907133b1dd0e", "4400614077c7094c516b4601c4b86606fd43253a9007477a38ac29d5850d96fe"), ("c95e8c1abe2aa8dc80ab531545142305cbfe743639e8b3b68f9057609d345dbb", "b639c077787b90184571eabe8914d1afbfdb8d4eb2ceb57152b444e1bbc92c69", "3adef9c27eb42a12cff85653318c4ffc7219f9fdd97fb87f8ea2ad4e96d17abc"), ("cafd9cef3c79f73612fed8856664d14de8c11a97fa156ccb94d6cc170e94acbe", "f0fa4a528889110619dec319576e10f575afd4304a3d691ecaaa3fdbe4afef9c", "4a722c7f443f33c2fbaabb2bc59dd4ea253e1ba26581d42dde801c19aefc2eaa"), ("35fe473871cc2cec9471ca9b250bf4eede7c93caa2d0c691d11e095b90900d1b", "392cadcbd3e8189e5319f7d740c428a1b31fb03a002d7c0130401ba56d657a30", "3a4a74075ebe5759a26e208a55e5da75450cc11c66ec17168f4b799a899d9068"), ("6fa0c420d38e9d8a131175151fd335474c60a883f280a891c99124f59955f6d3", "b188cba666cb6bcb70393fec601ba891b5eb915cf7d74fbc8b71376efc2ca817", "577a4bd4bef09987c37a2cd20d4ad1e0fe18de17ef9b71eaae0e6efea9c55b85"), ("3a13cd11d45383ad734030ea863035bbfd480206522b6b62af12665d12246725", "fd1bc9c8051a6a3fa4f2fb7c68553f228cb34858f8ec62e9e19426bdf3031f11", "3163631f005a9bf996518bcbaffd542f2ffc66bbde28232401c733525d382d36")], "1c96a8f7010c9860bd628da9128c93c1820dbea4dcc7090a5782f8e3aee8ee8b"),
  ]
  for i = 0; i < psk_cases.length(); i = i + 1 {
    let (cs_id, raw_psks, exp_hex) = psk_cases[i]
    let cs = @cs.CipherSuite::from_id(cs_id)
    let psks : Array[(@types.PreSharedKeyId, Bytes)] = []
    for j = 0; j < raw_psks.length(); j = j + 1 {
      let (id_h, val_h, nonce_h) = raw_psks[j]
      psks.push((
        @types.PreSharedKeyId::External(psk_id=vec_hex(id_h), psk_nonce=vec_hex(nonce_h)),
        vec_hex(val_h),
      ))
    }
    let psk_secret = @schedule.compute_psk_secret(cs, psks)
    assert_eq(psk_secret, vec_hex(exp_hex))
    let ep = @schedule.derive_epoch_secrets(cs, cs.zero_secret(), cs.zero_secret(), psk_secret, b"ctx")
    assert_eq(ep.epoch_authenticator.length(), cs.secret_len())
  }
}

