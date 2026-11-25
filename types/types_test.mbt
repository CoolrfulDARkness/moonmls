///|
fn[T] assert_tls_err(
  expected : @tls.TlsError,
  f : () -> T raise @tls.TlsError,
) -> Unit raise {
  try f() catch {
    e => assert_eq(e, expected)
  } noraise {
    _ => fail("expected TlsError \{expected}, but succeeded")
  }
}

///|
fn[T] assert_invalid_enum(f : () -> T raise @tls.TlsError) -> Unit raise {
  try f() catch {
    @tls.TlsError::InvalidEnum(_) => ()
    other => fail("expected InvalidEnum, got \{other}")
  } noraise {
    _ => fail("expected InvalidEnum, but succeeded")
  }
}

///|
fn append_trailing_byte(b : Bytes, extra : Byte) -> Bytes {
  @tls.bytes_concat([b, Bytes::make(1, extra)])
}

///|
fn sample_capabilities() -> @types.Capabilities {
  {
    versions: [@types.PROTOCOL_VERSION_MLS10],
    cipher_suites: [
      @types.CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
      @types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    ],
    extensions: [
      @types.EXT_APPLICATION_ID,
      @types.EXT_RATCHET_TREE,
      @types.EXT_REQUIRED_CAPABILITIES,
    ],
    proposals: [@types.PROPOSAL_TYPE_ADD, @types.PROPOSAL_TYPE_REMOVE],
    credentials: [@types.CREDENTIAL_TYPE_BASIC, @types.CREDENTIAL_TYPE_X509],
  }
}

///|
fn sample_leaf_key_package() -> @types.LeafNode {
  {
    encryption_key: b"\x01\x02\x03\x04",
    signature_key: b"\x05\x06\x07\x08",
    credential: @types.Credential::Basic(b"alice"),
    capabilities: sample_capabilities(),
    leaf_node_source: @types.LeafNodeSource::KeyPackage,
    lifetime: Some({ not_before: 1000UL, not_after: 999999UL }),
    parent_hash: None,
    extensions: [
      { extension_type: @types.EXT_APPLICATION_ID, extension_data: b"app-1" },
    ],
    signature: b"\xAA\xBB\xCC\xDD",
  }
}

///|
fn sample_key_package() -> @types.KeyPackage {
  {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: @types.CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
    init_key: b"\x10\x11\x12\x13",
    leaf_node: sample_leaf_key_package(),
    extensions: [],
    signature: b"\xDE\xAD\xBE\xEF",
  }
}

///|
fn sample_group_context() -> @types.GroupContext {
  {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: @types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    group_id: b"group-42",
    epoch: 7UL,
    tree_hash: b"\x21\x22\x23\x24",
    confirmed_transcript_hash: b"\x31\x32\x33\x34",
    extensions: [
      { extension_type: @types.EXT_EXTERNAL_PUB, extension_data: b"\x99\x88" },
    ],
  }
}

///|
test "official messages.json all 17 wire types 100% byte-for-byte roundtrip" {
  assert_eq(official_message_vectors.length(), 6)
  for i = 0; i < official_message_vectors.length(); i = i + 1 {
    let v = official_message_vectors[i]
    assert_true(v.index >= 0)

    // 1. mls_welcome (MlsMessage::Welcome)
    let raw_welcome = @tls.bytes_from_hex(v.mls_welcome)
    let dec_welcome = @types.MlsMessage::from_bytes(raw_welcome)
    assert_eq(dec_welcome.version, @types.PROTOCOL_VERSION_MLS10)
    assert_eq(dec_welcome.wire_format(), @types.WireFormat::MlsWelcome)
    assert_true(dec_welcome.body is @types.MlsMessageBody::Welcome(_))
    assert_eq(dec_welcome.to_bytes(), raw_welcome)

    // 2. mls_group_info (MlsMessage::GroupInfo)
    let raw_gi = @tls.bytes_from_hex(v.mls_group_info)
    let dec_gi = @types.MlsMessage::from_bytes(raw_gi)
    assert_eq(dec_gi.wire_format(), @types.WireFormat::MlsGroupInfo)
    match dec_gi.body {
      @types.MlsMessageBody::GroupInfo(gi) => {
        let tbs = gi.encode_tbs()
        let full = gi.to_bytes()
        let sig_encoded = @tls.encode_opaque(gi.signature)
        assert_eq(@tls.bytes_concat([tbs, sig_encoded]), full)
      }
      _ => fail("expected MlsMessageBody::GroupInfo")
    }
    assert_eq(dec_gi.to_bytes(), raw_gi)

    // 3. mls_key_package (MlsMessage::KeyPackage)
    let raw_kp = @tls.bytes_from_hex(v.mls_key_package)
    let dec_kp = @types.MlsMessage::from_bytes(raw_kp)
    assert_eq(dec_kp.wire_format(), @types.WireFormat::MlsKeyPackage)
    match dec_kp.body {
      @types.MlsMessageBody::KeyPackage(kp) => {
        let tbs = kp.encode_tbs()
        let full = kp.to_bytes()
        let sig_encoded = @tls.encode_opaque(kp.signature)
        assert_eq(@tls.bytes_concat([tbs, sig_encoded]), full)
      }
      _ => fail("expected MlsMessageBody::KeyPackage")
    }
    assert_eq(dec_kp.to_bytes(), raw_kp)

    // 4. ratchet_tree
    let raw_rt = @tls.bytes_from_hex(v.ratchet_tree)
    let dec_rt = @types.ratchet_tree_from_bytes(raw_rt)
    assert_true(dec_rt.length() > 0)
    assert_eq(@types.ratchet_tree_to_bytes(dec_rt), raw_rt)

    // 5. group_secrets
    let raw_gs = @tls.bytes_from_hex(v.group_secrets)
    let dec_gs = @types.GroupSecrets::from_bytes(raw_gs)
    assert_eq(dec_gs.to_bytes(), raw_gs)

    // 6. add_proposal (Add body = KeyPackage)
    let raw_add = @tls.bytes_from_hex(v.add_proposal)
    let dec_add = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_ADD,
      raw_add,
    )
    assert_true(dec_add is @types.Proposal::Add(_))
    assert_eq(dec_add.body_to_bytes(), raw_add)
    let kp_direct = @types.KeyPackage::from_bytes(raw_add)
    assert_eq(kp_direct.to_bytes(), raw_add)

    // 7. update_proposal (Update body = LeafNode)
    let raw_upd = @tls.bytes_from_hex(v.update_proposal)
    let dec_upd = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_UPDATE,
      raw_upd,
    )
    assert_true(dec_upd is @types.Proposal::Update(_))
    assert_eq(dec_upd.body_to_bytes(), raw_upd)
    let ln_direct = @types.LeafNode::from_bytes(raw_upd)
    assert_eq(ln_direct.leaf_node_source, @types.LeafNodeSource::Update)
    assert_eq(ln_direct.to_bytes(), raw_upd)

    // 8. remove_proposal (Remove body = uint32)
    let raw_rem = @tls.bytes_from_hex(v.remove_proposal)
    let dec_rem = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_REMOVE,
      raw_rem,
    )
    assert_true(dec_rem is @types.Proposal::Remove(_))
    assert_eq(dec_rem.body_to_bytes(), raw_rem)

    // 9. pre_shared_key_proposal (PreSharedKey body = PreSharedKeyId)
    let raw_psk = @tls.bytes_from_hex(v.pre_shared_key_proposal)
    let dec_psk = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_PSK,
      raw_psk,
    )
    assert_true(dec_psk is @types.Proposal::PreSharedKey(_))
    assert_eq(dec_psk.body_to_bytes(), raw_psk)
    let psk_direct = @types.PreSharedKeyId::from_bytes(raw_psk)
    assert_eq(psk_direct.to_bytes(), raw_psk)

    // 10. re_init_proposal
    let raw_reinit = @tls.bytes_from_hex(v.re_init_proposal)
    let dec_reinit = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_REINIT,
      raw_reinit,
    )
    assert_true(dec_reinit is @types.Proposal::ReInit(..))
    assert_eq(dec_reinit.body_to_bytes(), raw_reinit)

    // 11. external_init_proposal
    let raw_ext_init = @tls.bytes_from_hex(v.external_init_proposal)
    let dec_ext_init = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_EXTERNAL_INIT,
      raw_ext_init,
    )
    assert_true(dec_ext_init is @types.Proposal::ExternalInit(_))
    assert_eq(dec_ext_init.body_to_bytes(), raw_ext_init)

    // 12. group_context_extensions_proposal
    let raw_gce = @tls.bytes_from_hex(v.group_context_extensions_proposal)
    let dec_gce = @types.Proposal::body_from_bytes(
      @types.PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS,
      raw_gce,
    )
    assert_true(dec_gce is @types.Proposal::GroupContextExtensions(_))
    assert_eq(dec_gce.body_to_bytes(), raw_gce)

    // 13. commit
    let raw_commit = @tls.bytes_from_hex(v.commit)
    let dec_commit = @types.Commit::from_bytes(raw_commit)
    assert_eq(dec_commit.to_bytes(), raw_commit)

    // 14. public_message_application
    let raw_pub_app = @tls.bytes_from_hex(v.public_message_application)
    let dec_pub_app = @types.MlsMessage::from_bytes(raw_pub_app)
    match dec_pub_app.body {
      @types.MlsMessageBody::PublicMessage(pm) => {
        assert_true(pm.content.content is @types.FramedContentBody::Application(_))
        assert_eq(pm.auth.confirmation_tag, None)
      }
      _ => fail("expected PublicMessage(Application)")
    }
    assert_eq(dec_pub_app.to_bytes(), raw_pub_app)

    // 15. public_message_proposal
    let raw_pub_prop = @tls.bytes_from_hex(v.public_message_proposal)
    let dec_pub_prop = @types.MlsMessage::from_bytes(raw_pub_prop)
    match dec_pub_prop.body {
      @types.MlsMessageBody::PublicMessage(pm) => {
        assert_true(pm.content.content is @types.FramedContentBody::Proposal(_))
        assert_eq(pm.auth.confirmation_tag, None)
      }
      _ => fail("expected PublicMessage(Proposal)")
    }
    assert_eq(dec_pub_prop.to_bytes(), raw_pub_prop)

    // 16. public_message_commit
    let raw_pub_commit = @tls.bytes_from_hex(v.public_message_commit)
    let dec_pub_commit = @types.MlsMessage::from_bytes(raw_pub_commit)
    match dec_pub_commit.body {
      @types.MlsMessageBody::PublicMessage(pm) => {
        assert_true(pm.content.content is @types.FramedContentBody::Commit(_))
        assert_true(pm.auth.confirmation_tag is Some(_))
      }
      _ => fail("expected PublicMessage(Commit)")
    }
    assert_eq(dec_pub_commit.to_bytes(), raw_pub_commit)

    // 17. private_message
    let raw_priv = @tls.bytes_from_hex(v.private_message)
    let dec_priv = @types.MlsMessage::from_bytes(raw_priv)
    assert_eq(dec_priv.wire_format(), @types.WireFormat::MlsPrivateMessage)
    assert_true(dec_priv.body is @types.MlsMessageBody::PrivateMessage(_))
    assert_eq(dec_priv.to_bytes(), raw_priv)
  }
}

///|
test "primitive enums, Credential Basic/X509, Capabilities, Lifetime, Extension roundtrip" {
  // ProtocolVersion
  let pv = @types.ProtocolVersion::Mls10
  assert_eq(@types.ProtocolVersion::from_bytes(pv.to_bytes()), pv)
  assert_eq(@tls.bytes_to_hex(pv.to_bytes()), "0001")

  // WireFormat
  let wfs : Array[@types.WireFormat] = [
    MlsPublicMessage,
    MlsPrivateMessage,
    MlsWelcome,
    MlsGroupInfo,
    MlsKeyPackage,
  ]
  for i = 0; i < wfs.length(); i = i + 1 {
    assert_eq(@types.WireFormat::from_bytes(wfs[i].to_bytes()), wfs[i])
  }

  // ContentType
  let cts : Array[@types.ContentType] = [Application, Proposal, Commit]
  for i = 0; i < cts.length(); i = i + 1 {
    assert_eq(@types.ContentType::from_bytes(cts[i].to_bytes()), cts[i])
  }

  // LeafNodeSource
  let lns : Array[@types.LeafNodeSource] = [KeyPackage, Update, Commit]
  for i = 0; i < lns.length(); i = i + 1 {
    assert_eq(@types.LeafNodeSource::from_bytes(lns[i].to_bytes()), lns[i])
  }

  // Credential Basic & X509 (empty and multi-cert chain)
  let c_basic = @types.Credential::Basic(b"alice@example.org")
  assert_eq(c_basic.credential_type(), @types.CREDENTIAL_TYPE_BASIC)
  assert_eq(@types.Credential::from_bytes(c_basic.to_bytes()), c_basic)

  let c_x509_empty = @types.Credential::X509([])
  assert_eq(c_x509_empty.credential_type(), @types.CREDENTIAL_TYPE_X509)
  assert_eq(
    @types.Credential::from_bytes(c_x509_empty.to_bytes()),
    c_x509_empty,
  )
  assert_eq(@tls.bytes_to_hex(c_x509_empty.to_bytes()), "000200")

  let c_x509 = @types.Credential::X509([
    b"\x30\x82\x01\x0A",
    b"\x30\x82\x02\x0B\x0C",
  ])
  assert_eq(@types.Credential::from_bytes(c_x509.to_bytes()), c_x509)

  // Capabilities, Lifetime, Extension
  let caps = sample_capabilities()
  assert_eq(@types.Capabilities::from_bytes(caps.to_bytes()), caps)

  let lt : @types.Lifetime = { not_before: 1700000000UL, not_after: 1800000000UL }
  assert_eq(@types.Lifetime::from_bytes(lt.to_bytes()), lt)

  let ext : @types.Extension = {
    extension_type: @types.EXT_EXTERNAL_SENDERS,
    extension_data: b"\x01\x02\x03",
  }
  assert_eq(@types.Extension::from_bytes(ext.to_bytes()), ext)
}

///|
test "LeafNode all 3 sources, LeafNode::encode_tbs, ParentNode, RatchetTree" {
  // 1. KeyPackage LeafNode TBS does NOT append group_id / leaf_index
  let ln_kp = sample_leaf_key_package()
  assert_eq(@types.LeafNode::from_bytes(ln_kp.to_bytes()), ln_kp)
  let kp_tbs = ln_kp.encode_tbs(None, None)
  assert_eq(
    @tls.bytes_concat([kp_tbs, @tls.encode_opaque(ln_kp.signature)]),
    ln_kp.to_bytes(),
  )

  // 2. Update LeafNode TBS appends group_id<V> and uint32 leaf_index
  let ln_upd : @types.LeafNode = {
    encryption_key: b"\x11\x22",
    signature_key: b"\x33\x44",
    credential: @types.Credential::X509([b"\x30\x01"]),
    capabilities: sample_capabilities(),
    leaf_node_source: @types.LeafNodeSource::Update,
    lifetime: None,
    parent_hash: None,
    extensions: [],
    signature: b"\x55\x66",
  }
  assert_eq(@types.LeafNode::from_bytes(ln_upd.to_bytes()), ln_upd)
  let gid = b"grp-upd"
  let lidx = 3U
  let upd_tbs = ln_upd.encode_tbs(Some(gid), Some(lidx))
  let w_suffix = @tls.Writer::new()
  w_suffix.write_opaque(gid)
  w_suffix.write_u32(lidx)
  let upd_raw = ln_upd.to_bytes()
  let upd_sig_enc = @tls.encode_opaque(ln_upd.signature)
  let upd_prefix = @tls.bytes_slice(
    upd_raw,
    0,
    upd_raw.length() - upd_sig_enc.length(),
  )
  assert_eq(upd_tbs, @tls.bytes_concat([upd_prefix, w_suffix.to_bytes()]))
  assert_invalid_enum(() => ln_upd.encode_tbs(None, Some(lidx)))
  assert_invalid_enum(() => ln_upd.encode_tbs(Some(gid), None))

  // 3. Commit LeafNode TBS appends group_id<V> and uint32 leaf_index
  let ln_commit : @types.LeafNode = {
    encryption_key: b"\x77\x88",
    signature_key: b"\x99\xAA",
    credential: @types.Credential::Basic(b"bob"),
    capabilities: sample_capabilities(),
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: Some(b"\xAB\xCD\xEF"),
    extensions: [],
    signature: b"\xFE\xED",
  }
  assert_eq(@types.LeafNode::from_bytes(ln_commit.to_bytes()), ln_commit)
  let commit_tbs = ln_commit.encode_tbs(Some(gid), Some(5U))
  assert_true(commit_tbs.length() > 0)
  assert_invalid_enum(() => ln_commit.encode_tbs(None, None))

  // 4. ParentNode & RatchetTree with blanks
  let parent : @types.ParentNode = {
    encryption_key: b"\x01\x02\x03",
    parent_hash: b"\x04\x05",
    unmerged_leaves: [0U, 2U, 5U],
  }
  assert_eq(@types.ParentNode::from_bytes(parent.to_bytes()), parent)
  let tree : @types.RatchetTree = [
    Some(@types.Node::Leaf(ln_kp)),
    Some(@types.Node::Parent(parent)),
    None,
    None,
    Some(@types.Node::Leaf(ln_commit)),
  ]
  assert_eq(
    @types.ratchet_tree_from_bytes(@types.ratchet_tree_to_bytes(tree)),
    tree,
  )
}

///|
test "PSK types (External + all Resumption usages) and all 7 tagged Proposals" {
  let psk_ext = @types.PreSharedKeyId::External(
    psk_id=b"ext-psk-1",
    psk_nonce=b"\x01\x02\x03\x04",
  )
  assert_eq(@types.PreSharedKeyId::from_bytes(psk_ext.to_bytes()), psk_ext)

  let usages : Array[UInt] = [1U, 2U, 3U]
  for i = 0; i < usages.length(); i = i + 1 {
    let psk_res = @types.PreSharedKeyId::Resumption(
      usage=usages[i],
      psk_group_id=b"prev-group",
      psk_epoch=42UL,
      psk_nonce=b"\x99\x88\x77\x66",
    )
    assert_eq(@types.PreSharedKeyId::from_bytes(psk_res.to_bytes()), psk_res)
  }
  // Invalid resumption usage rejected on encode and decode
  let bad_res = @types.PreSharedKeyId::Resumption(
    usage=4U,
    psk_group_id=b"g",
    psk_epoch=0UL,
    psk_nonce=b"",
  )
  assert_invalid_enum(() => bad_res.to_bytes())
  assert_invalid_enum(() => @types.PreSharedKeyId::from_bytes(b"\x02\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

  // All 7 full tagged Proposal variants
  let proposals : Array[@types.Proposal] = [
    Add(sample_key_package()),
    Update({
      ..sample_leaf_key_package(),
      leaf_node_source: @types.LeafNodeSource::Update,
      lifetime: None,
    }),
    Remove(9U),
    PreSharedKey(psk_ext),
    ReInit(
      group_id=b"new-group",
      version=@types.PROTOCOL_VERSION_MLS10,
      cipher_suite=@types.CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
      extensions=[
        { extension_type: @types.EXT_REQUIRED_CAPABILITIES, extension_data: b"\x00\x00\x00" },
      ],
    ),
    ExternalInit(b"\xCA\xFE\xBA\xBE"),
    GroupContextExtensions([
      { extension_type: @types.EXT_APPLICATION_ID, extension_data: b"ctx-ext" },
    ]),
  ]
  for i = 0; i < proposals.length(); i = i + 1 {
    let p = proposals[i]
    let encoded = p.to_bytes()
    assert_eq(@types.Proposal::from_bytes(encoded), p)
    let por = @types.ProposalOrRef::Proposal(p)
    assert_eq(@types.ProposalOrRef::from_bytes(por.to_bytes()), por)
  }

  let ref_por = @types.ProposalOrRef::Reference(b"\x11\x22\x33\x44")
  assert_eq(@types.ProposalOrRef::from_bytes(ref_por.to_bytes()), ref_por)

  let commit_no_path : @types.Commit = {
    proposals: [ref_por, @types.ProposalOrRef::Proposal(Remove(1U))],
    path: None,
  }
  assert_eq(@types.Commit::from_bytes(commit_no_path.to_bytes()), commit_no_path)
}

///|
test "framing structs: Sender, FramedContentTbs, AuthContent, Transcript, PublicMessage" {
  let ctx = sample_group_context()
  let senders : Array[(@types.Sender, Bool)] = [
    (@types.Sender::Member(2U), true),
    (@types.Sender::External(0U), false),
    (@types.Sender::NewMemberProposal, false),
    (@types.Sender::NewMemberCommit, true),
  ]

  for i = 0; i < senders.length(); i = i + 1 {
    let (sender, needs_ctx) = senders[i]
    assert_eq(@types.Sender::from_bytes(sender.to_bytes()), sender)

    let fc : @types.FramedContent = {
      group_id: b"gid",
      epoch: 12UL,
      sender,
      authenticated_data: b"aad",
      content: @types.FramedContentBody::Application(b"hello mls"),
    }
    assert_eq(@types.FramedContent::from_bytes(fc.to_bytes()), fc)

    let tbs : @types.FramedContentTbs = {
      version: @types.PROTOCOL_VERSION_MLS10,
      wire_format: @types.WireFormat::MlsPublicMessage,
      content: fc,
      context: if needs_ctx {
        Some(ctx)
      } else {
        None
      },
    }
    assert_eq(@types.FramedContentTbs::from_bytes(tbs.to_bytes()), tbs)

    // Mismatched context presence rejected
    let bad_tbs : @types.FramedContentTbs = {
      ..tbs,
      context: if needs_ctx {
        None
      } else {
        Some(ctx)
      },
    }
    assert_invalid_enum(() => bad_tbs.to_bytes())

    let auth : @types.FramedContentAuthData = {
      signature: b"\x01\x02\x03",
      confirmation_tag: None,
    }
    let ac : @types.AuthenticatedContent = {
      wire_format: @types.WireFormat::MlsPublicMessage,
      content: fc,
      auth,
    }
    assert_eq(@types.AuthenticatedContent::from_bytes(ac.to_bytes()), ac)

    let tbm : @types.AuthenticatedContentTbm = { content_tbs: tbs, auth }
    assert_eq(@types.AuthenticatedContentTbm::from_bytes(tbm.to_bytes()), tbm)

    let is_member = sender is @types.Sender::Member(_)
    let pm : @types.PublicMessage = {
      content: fc,
      auth,
      membership_tag: if is_member {
        Some(b"\xAA\xBB")
      } else {
        None
      },
    }
    assert_eq(@types.PublicMessage::from_bytes(pm.to_bytes()), pm)

    let bad_pm : @types.PublicMessage = {
      ..pm,
      membership_tag: if is_member {
        None
      } else {
        Some(b"\xAA\xBB")
      },
    }
    assert_invalid_enum(() => bad_pm.to_bytes())
  }

  // Transcript hash inputs
  let commit_fc : @types.FramedContent = {
    group_id: b"gid",
    epoch: 12UL,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit({ proposals: [], path: None }),
  }
  let cthi : @types.ConfirmedTranscriptHashInput = {
    wire_format: @types.WireFormat::MlsPrivateMessage,
    content: commit_fc,
    signature: b"\xDE\xAD",
  }
  assert_eq(
    @types.ConfirmedTranscriptHashInput::from_bytes(cthi.to_bytes()),
    cthi,
  )

  let ithi : @types.InterimTranscriptHashInput = {
    confirmation_tag: b"\xBE\xEF\x01\x02",
  }
  assert_eq(@types.InterimTranscriptHashInput::from_bytes(ithi.to_bytes()), ithi)

  // Commit auth requires confirmation_tag; non-commit forbids it
  let missing_tag : @types.FramedContentAuthData = {
    signature: b"\x01",
    confirmation_tag: None,
  }
  assert_invalid_enum(() => missing_tag.to_bytes(@types.ContentType::Commit))
  let extra_tag : @types.FramedContentAuthData = {
    signature: b"\x01",
    confirmation_tag: Some(b"\x02"),
  }
  assert_invalid_enum(() => extra_tag.to_bytes(@types.ContentType::Application))
  assert_invalid_enum(() => extra_tag.to_bytes(@types.ContentType::Proposal))
}

///|
test "PrivateMessageContent padding roundtrip and non-zero padding rejection" {
  let cases : Array[(@types.ContentType, @types.PrivateMessageContent)] = [
    (
      @types.ContentType::Application,
      {
        content: @types.FramedContentBody::Application(b"secret payload"),
        auth: { signature: b"\x01\x02\x03\x04", confirmation_tag: None },
        padding_len: 0,
      },
    ),
    (
      @types.ContentType::Proposal,
      {
        content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(3U)),
        auth: { signature: b"\x05\x06", confirmation_tag: None },
        padding_len: 1,
      },
    ),
    (
      @types.ContentType::Commit,
      {
        content: @types.FramedContentBody::Commit({ proposals: [], path: None }),
        auth: {
          signature: b"\x07\x08",
          confirmation_tag: Some(b"\x09\x0A\x0B\x0C"),
        },
        padding_len: 16,
      },
    ),
  ]

  for i = 0; i < cases.length(); i = i + 1 {
    let (ct, pmc) = cases[i]
    let encoded = pmc.to_bytes()
    let decoded = @types.PrivateMessageContent::from_bytes(encoded, ct)
    assert_eq(decoded, pmc)
    assert_eq(decoded.padding_len, pmc.padding_len)

    // Non-zero byte immediately after auth must be rejected
    let bad1 = @tls.bytes_concat([encoded, b"\x01"])
    assert_invalid_enum(() => @types.PrivateMessageContent::from_bytes(bad1, ct))

    // Non-zero byte surrounded by zero padding must be rejected
    let bad2 = @tls.bytes_concat([encoded, b"\x00\x00\xFF\x00"])
    assert_invalid_enum(() => @types.PrivateMessageContent::from_bytes(bad2, ct))
  }

  // Negative padding_len rejected on encode
  let neg_pad : @types.PrivateMessageContent = {
    content: @types.FramedContentBody::Application(b""),
    auth: { signature: b"", confirmation_tag: None },
    padding_len: -1,
  }
  assert_tls_err(@tls.TlsError::LengthMismatch, () => neg_pad.to_bytes())
}

///|
test "PrivateContentAad, MlsSenderData, MlsSenderDataAad roundtrip and validation" {
  let pca : @types.PrivateContentAad = {
    group_id: b"g1",
    epoch: 99UL,
    content_type: @types.ContentType::Application,
    authenticated_data: b"meta",
  }
  assert_eq(@types.PrivateContentAad::from_bytes(pca.to_bytes()), pca)

  let sd : @types.MlsSenderData = {
    leaf_index: 4U,
    generation: 17U,
    reuse_guard: b"\xDE\xAD\xBE\xEF",
  }
  let sd_bytes = sd.to_bytes()
  assert_eq(sd_bytes.length(), 12)
  assert_eq(@types.MlsSenderData::from_bytes(sd_bytes), sd)

  // reuse_guard length != 4 must fail on encode
  let bad_sd : @types.MlsSenderData = { ..sd, reuse_guard: b"\x01\x02\x03" }
  assert_tls_err(@tls.TlsError::LengthMismatch, () => bad_sd.to_bytes())

  let sda : @types.MlsSenderDataAad = {
    group_id: b"g1",
    epoch: 99UL,
    content_type: @types.ContentType::Commit,
  }
  assert_eq(@types.MlsSenderDataAad::from_bytes(sda.to_bytes()), sda)
}

///|
test "from_bytes rejects trailing garbage bytes across all decoders" {
  let v0 = official_message_vectors[0]

  // Append 0x00 trailing byte to valid official vectors and verify TrailingData
  let raw_welcome = append_trailing_byte(
    @tls.bytes_from_hex(v0.mls_welcome),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.MlsMessage::from_bytes(raw_welcome)
  })

  let raw_kp = append_trailing_byte(
    @tls.bytes_from_hex(v0.mls_key_package),
    b'\xAA',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.MlsMessage::from_bytes(raw_kp)
  })

  let raw_rt = append_trailing_byte(
    @tls.bytes_from_hex(v0.ratchet_tree),
    b'\x01',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.ratchet_tree_from_bytes(raw_rt)
  })

  let raw_gs = append_trailing_byte(
    @tls.bytes_from_hex(v0.group_secrets),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.GroupSecrets::from_bytes(raw_gs)
  })

  let raw_commit = append_trailing_byte(
    @tls.bytes_from_hex(v0.commit),
    b'\xFF',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.Commit::from_bytes(raw_commit)
  })

  let raw_add = append_trailing_byte(
    @tls.bytes_from_hex(v0.add_proposal),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.KeyPackage::from_bytes(raw_add)
  })
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.Proposal::body_from_bytes(@types.PROPOSAL_TYPE_ADD, raw_add)
  })

  let raw_upd = append_trailing_byte(
    @tls.bytes_from_hex(v0.update_proposal),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.LeafNode::from_bytes(raw_upd)
  })

  let raw_psk = append_trailing_byte(
    @tls.bytes_from_hex(v0.pre_shared_key_proposal),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.PreSharedKeyId::from_bytes(raw_psk)
  })

  let raw_priv = append_trailing_byte(
    @tls.bytes_from_hex(v0.private_message),
    b'\x00',
  )
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.MlsMessage::from_bytes(raw_priv)
  })

  let sd : @types.MlsSenderData = {
    leaf_index: 1U,
    generation: 2U,
    reuse_guard: b"\x01\x02\x03\x04",
  }
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.MlsSenderData::from_bytes(append_trailing_byte(sd.to_bytes(), b'\x00'))
  })

  let ext : @types.Extension = { extension_type: 1U, extension_data: b"x" }
  assert_tls_err(@tls.TlsError::TrailingData, () => {
    @types.Extension::from_bytes(append_trailing_byte(ext.to_bytes(), b'\x00'))
  })
}

///|
test "invalid enum discriminants and unsupported MlsMessage version rejected" {
  assert_invalid_enum(() => @types.ProtocolVersion::from_bytes(b"\x00\x00"))
  assert_invalid_enum(() => @types.ProtocolVersion::from_bytes(b"\x00\x02"))
  assert_invalid_enum(() => @types.WireFormat::from_bytes(b"\x00\x00"))
  assert_invalid_enum(() => @types.WireFormat::from_bytes(b"\x00\x06"))
  assert_invalid_enum(() => @types.ContentType::from_bytes(b"\x00"))
  assert_invalid_enum(() => @types.ContentType::from_bytes(b"\x04"))
  assert_invalid_enum(() => @types.LeafNodeSource::from_bytes(b"\x00"))
  assert_invalid_enum(() => @types.LeafNodeSource::from_bytes(b"\x04"))
  assert_invalid_enum(() => @types.Credential::from_bytes(b"\x00\x03\x00"))
  assert_invalid_enum(() => @types.Node::from_bytes(b"\x03"))
  assert_invalid_enum(() => @types.PskType::from_bytes(b"\x03"))
  assert_invalid_enum(() => @types.ResumptionPskUsage::from_bytes(b"\x00"))
  assert_invalid_enum(() => @types.ResumptionPskUsage::from_bytes(b"\x04"))
  assert_invalid_enum(() => @types.Proposal::from_bytes(b"\x00\x08"))
  assert_invalid_enum(() => @types.ProposalOrRef::from_bytes(b"\x03"))
  assert_invalid_enum(() => @types.Sender::from_bytes(b"\x05"))
  // Unsupported MlsMessage version (2 instead of 1)
  assert_invalid_enum(() => @types.MlsMessage::from_bytes(b"\x00\x02\x00\x01"))
}
