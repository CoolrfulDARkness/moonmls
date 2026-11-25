///|
fn hex_bytes(s : String) -> Bytes raise {
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
fn[T] assert_schedule_err(
  f : () -> T raise @schedule.ScheduleError,
  expected : @schedule.ScheduleError,
) -> Unit raise {
  try f() catch {
    e => assert_eq(e, expected)
  } noraise {
    _ => fail("expected ScheduleError \{expected}, but succeeded")
  }
}

///|
fn sample_group_context(cs : @cs.CipherSuite) -> @types.GroupContext raise {
  {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    group_id: hex_bytes("0102030405060708090a0b0c0d0e0f10"),
    epoch: 7UL,
    tree_hash: Bytes::make(32, b'\x11'),
    confirmed_transcript_hash: Bytes::make(32, b'\x22'),
    extensions: [],
  }
}

///|
fn sample_commit() -> @types.Commit {
  {
    proposals: [@types.ProposalOrRef::Reference(Bytes::make(32, b'\xaa'))],
    path: None,
  }
}

///|
test "ScheduleError Show formatting" {
  assert_eq(Show::to_string(@schedule.InvalidSignature), "InvalidSignature")
  assert_eq(
    Show::to_string(@schedule.InvalidMembershipTag),
    "InvalidMembershipTag",
  )
  assert_eq(
    Show::to_string(@schedule.InvalidConfirmationTag),
    "InvalidConfirmationTag",
  )
  assert_eq(
    Show::to_string(@schedule.MissingMembershipKey),
    "MissingMembershipKey",
  )
  assert_eq(
    Show::to_string(@schedule.MissingGroupContext),
    "MissingGroupContext",
  )
  assert_eq(Show::to_string(@schedule.InvalidReuseGuard), "InvalidReuseGuard")
  assert_eq(Show::to_string(@schedule.DecryptionFailed), "DecryptionFailed")
  assert_eq(Show::to_string(@schedule.InvalidWireFormat), "InvalidWireFormat")
  assert_eq(
    Show::to_string(@schedule.UnexpectedContentType),
    "UnexpectedContentType",
  )
  assert_eq(
    Show::to_string(@schedule.TlsError(@tls.UnexpectedEof)),
    "TlsError(UnexpectedEof)",
  )
  assert_eq(
    Show::to_string(@schedule.CryptoError(@crypto.InvalidNonceLength)),
    "CryptoError(InvalidNonceLength)",
  )
  assert_eq(
    Show::to_string(@schedule.CsError(@cs.VerificationFailed)),
    "CsError(VerificationFailed)",
  )
}

///|
test "PSK secret derivation with External and Resumption PSKs" {
  let cs1 = @cs.CipherSuite::from_id(1U)
  let cs3 = @cs.CipherSuite::from_id(3U)
  assert_eq(@schedule.compute_psk_secret(cs1, []), cs1.zero_secret())
  assert_eq(@schedule.compute_psk_secret(cs3, []), cs3.zero_secret())

  let psks : Array[(@types.PreSharedKeyId, Bytes)] = [
    (
      @types.PreSharedKeyId::External(
        psk_id=b"ext-psk-1",
        psk_nonce=Bytes::make(32, b'\x01'),
      ),
      Bytes::make(32, b'\xaa'),
    ),
    (
      @types.PreSharedKeyId::Resumption(
        usage=1U,
        psk_group_id=b"prev-group",
        psk_epoch=42UL,
        psk_nonce=Bytes::make(32, b'\x02'),
      ),
      Bytes::make(32, b'\xbb'),
    ),
  ]
  let sec1 = @schedule.compute_psk_secret(cs1, psks)
  let sec3 = @schedule.compute_psk_secret(cs3, psks)
  assert_eq(sec1.length(), 32)
  assert_eq(sec1, sec3) // CS1 and CS3 share HKDF-SHA256
  assert_true(sec1 != cs1.zero_secret())

  // Order matters (index is encoded in PSKLabel)
  let reversed : Array[(@types.PreSharedKeyId, Bytes)] = [psks[1], psks[0]]
  let sec_rev = @schedule.compute_psk_secret(cs1, reversed)
  assert_true(sec_rev != sec1)
}

///|
test "Key schedule welcome key/nonce and joiner equivalence" {
  for
    cs in [
      @cs.X25519Aes128GcmSha256Ed25519,
      @cs.X25519ChaCha20Poly1305Sha256Ed25519,
    ] {
    let prev_init = Bytes::make(32, b'\x10')
    let commit_sec = Bytes::make(32, b'\x20')
    let psk_sec = Bytes::make(32, b'\x30')
    let gc_bytes = sample_group_context(cs).to_bytes()

    let joiner = @schedule.derive_joiner_secret(
      cs, prev_init, commit_sec, gc_bytes,
    )
    let welcome = @schedule.derive_welcome_secret(cs, joiner, psk_sec)
    let (wk, wn) = @schedule.derive_welcome_key_nonce(cs, welcome)
    assert_eq(wk.length(), cs.aead_key_len())
    assert_eq(wn.length(), cs.aead_nonce_len())

    let from_joiner = @schedule.derive_epoch_secrets_from_joiner(
      cs, joiner, psk_sec, gc_bytes,
    )
    let direct = @schedule.derive_epoch_secrets(
      cs, prev_init, commit_sec, psk_sec, gc_bytes,
    )
    assert_eq(from_joiner, direct)
    assert_eq(direct.joiner_secret, joiner)
    assert_eq(direct.welcome_secret, welcome)
    assert_eq(direct.external_priv.length(), 32)
    assert_eq(direct.external_pub.length(), 32)

    let exp1 = @schedule.mls_exporter(
      cs,
      direct.exporter_secret,
      "app-label",
      b"ctx",
      48,
    )
    assert_eq(exp1.length(), 48)
    let exp2 = @schedule.mls_exporter(
      cs,
      direct.exporter_secret,
      "app-label",
      b"ctx2",
      48,
    )
    assert_true(exp1 != exp2)
  }
}

///|
test "Transcript hash and confirmation/membership tags" {
  let cs = @cs.X25519Aes128GcmSha256Ed25519
  let gc = sample_group_context(cs)
  let commit_content : @types.FramedContent = {
    group_id: gc.group_id,
    epoch: gc.epoch,
    sender: @types.Sender::Member(0U),
    authenticated_data: b"aad",
    content: @types.FramedContentBody::Commit(sample_commit()),
  }
  let input : @types.ConfirmedTranscriptHashInput = {
    wire_format: @types.WireFormat::MlsPublicMessage,
    content: commit_content,
    signature: Bytes::make(64, b'\x55'),
  }
  let confirmed = @schedule.compute_confirmed_transcript_hash(cs, b"", input)
  assert_eq(confirmed.length(), 32)

  // Manual check against RFC 9420 §8.2 formula
  assert_eq(confirmed, cs.hash(input.to_bytes()))

  let conf_key = Bytes::make(32, b'\x77')
  let conf_tag = @schedule.compute_confirmation_tag(cs, conf_key, confirmed)
  assert_true(
    @schedule.verify_confirmation_tag(cs, conf_key, confirmed, conf_tag),
  )
  assert_true(
    !@schedule.verify_confirmation_tag(
      cs,
      conf_key,
      confirmed,
      flip_byte(conf_tag, 0),
    ),
  )

  let interim = @schedule.compute_interim_transcript_hash(
    cs, confirmed, conf_tag,
  )
  let interim_manual = cs.hash(
    @tls.bytes_concat([confirmed, @tls.encode_opaque(conf_tag)]),
  )
  assert_eq(interim, interim_manual)

  // Non-Commit in ConfirmedTranscriptHashInput must be rejected
  let prop_input : @types.ConfirmedTranscriptHashInput = {
    wire_format: @types.WireFormat::MlsPublicMessage,
    content: {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(0U),
      authenticated_data: b"",
      content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(2U)),
    },
    signature: Bytes::make(64, b'\x55'),
  }
  assert_schedule_err(
    () => @schedule.compute_confirmed_transcript_hash(cs, interim, prop_input),
    @schedule.UnexpectedContentType,
  )
}

///|
test "PublicMessage protection roundtrip and security checks" {
  for
    cs in [
      @cs.X25519Aes128GcmSha256Ed25519,
      @cs.X25519ChaCha20Poly1305Sha256Ed25519,
    ] {
    let (sign_priv, sign_pub) = cs.signature_keypair_from_seed(
      Bytes::make(32, b'\x42'),
    )
    let gc = sample_group_context(cs)
    let mk = Bytes::make(32, b'\x99')

    // 1. Member Proposal roundtrip
    let prop_content : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(1U),
      authenticated_data: b"meta",
      content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(3U)),
    }
    let pub_prop = @schedule.protect_public_message(
      cs,
      sign_priv,
      Some(mk),
      prop_content,
      Some(gc),
      None,
    )
    assert_true(pub_prop.membership_tag is Some(_))
    let auth_prop = @schedule.unprotect_public_message(
      cs,
      sign_pub,
      Some(mk),
      pub_prop,
      Some(gc),
    )
    assert_eq(auth_prop.wire_format, @types.WireFormat::MlsPublicMessage)
    assert_eq(auth_prop.content, prop_content)
    assert_eq(auth_prop.auth, pub_prop.auth)

    // 2. Member Commit roundtrip
    let commit_content : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(1U),
      authenticated_data: b"",
      content: @types.FramedContentBody::Commit(sample_commit()),
    }
    let conf_tag = Bytes::make(32, b'\xcc')
    let pub_commit = @schedule.protect_public_message(
      cs,
      sign_priv,
      Some(mk),
      commit_content,
      Some(gc),
      Some(conf_tag),
    )
    let auth_commit = @schedule.unprotect_public_message(
      cs,
      sign_pub,
      Some(mk),
      pub_commit,
      Some(gc),
    )
    assert_eq(auth_commit.auth.confirmation_tag, Some(conf_tag))

    // 3. External Proposal (no GroupContext required, no membership_tag)
    let ext_prop : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::External(0U),
      authenticated_data: b"",
      content: @types.FramedContentBody::Proposal(@types.Proposal::Remove(2U)),
    }
    let pub_ext = @schedule.protect_public_message(
      cs,
      sign_priv,
      None,
      ext_prop,
      None,
      None,
    )
    assert_eq(pub_ext.membership_tag, None)
    let auth_ext = @schedule.unprotect_public_message(
      cs,
      sign_pub,
      None,
      pub_ext,
      None,
    )
    assert_eq(auth_ext.content, ext_prop)

    // 4. Error cases
    // Application data forbidden in PublicMessage
    let app_content : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(1U),
      authenticated_data: b"",
      content: @types.FramedContentBody::Application(b"secret"),
    }
    assert_schedule_err(
      () => {
        @schedule.protect_public_message(
          cs,
          sign_priv,
          Some(mk),
          app_content,
          Some(gc),
          None,
        )
      },
      @schedule.UnexpectedContentType,
    )

    // Missing membership key for Member
    assert_schedule_err(
      () => {
        @schedule.protect_public_message(
          cs,
          sign_priv,
          None,
          prop_content,
          Some(gc),
          None,
        )
      },
      @schedule.MissingMembershipKey,
    )
    assert_schedule_err(
      () => {
        @schedule.unprotect_public_message(
          cs,
          sign_pub,
          None,
          pub_prop,
          Some(gc),
        )
      },
      @schedule.MissingMembershipKey,
    )

    // Missing GroupContext for Member
    assert_schedule_err(
      () => {
        @schedule.protect_public_message(
          cs,
          sign_priv,
          Some(mk),
          prop_content,
          None,
          None,
        )
      },
      @schedule.MissingGroupContext,
    )

    // Missing confirmation_tag on Commit / unexpected confirmation_tag on Proposal
    assert_schedule_err(
      () => {
        @schedule.protect_public_message(
          cs,
          sign_priv,
          Some(mk),
          commit_content,
          Some(gc),
          None,
        )
      },
      @schedule.InvalidConfirmationTag,
    )
    assert_schedule_err(
      () => {
        @schedule.protect_public_message(
          cs,
          sign_priv,
          Some(mk),
          prop_content,
          Some(gc),
          Some(conf_tag),
        )
      },
      @schedule.InvalidConfirmationTag,
    )

    // Tampered membership tag
    let bad_tag_msg : @types.PublicMessage = {
      content: pub_prop.content,
      auth: pub_prop.auth,
      membership_tag: Some(flip_byte(pub_prop.membership_tag.unwrap(), 0)),
    }
    assert_schedule_err(
      () => {
        @schedule.unprotect_public_message(
          cs,
          sign_pub,
          Some(mk),
          bad_tag_msg,
          Some(gc),
        )
      },
      @schedule.InvalidMembershipTag,
    )

    // Tampered signature on External message (no membership_tag)
    let bad_sig_ext : @types.PublicMessage = {
      content: pub_ext.content,
      auth: {
        signature: flip_byte(pub_ext.auth.signature, 0),
        confirmation_tag: None,
      },
      membership_tag: None,
    }
    assert_schedule_err(
      () => {
        @schedule.unprotect_public_message(
          cs,
          sign_pub,
          None,
          bad_sig_ext,
          None,
        )
      },
      @schedule.InvalidSignature,
    )

    // Invalid wire format in sign_framed_content
    assert_schedule_err(
      () => {
        @schedule.sign_framed_content(
          cs,
          sign_priv,
          @types.WireFormat::MlsWelcome,
          prop_content,
          Some(gc),
        )
      },
      @schedule.InvalidWireFormat,
    )
  }
}

///|
test "PrivateMessage encryption/decryption roundtrip and tamper rejection" {
  for
    cs in [
      @cs.X25519Aes128GcmSha256Ed25519,
      @cs.X25519ChaCha20Poly1305Sha256Ed25519,
    ] {
    let (sign_priv, sign_pub) = cs.signature_keypair_from_seed(
      Bytes::make(32, b'\x33'),
    )
    let gc = sample_group_context(cs)
    let sender_data_secret = Bytes::make(32, b'\x5a')
    let content_key = Bytes::make(cs.aead_key_len(), b'\x6b')
    let content_nonce = Bytes::make(cs.aead_nonce_len(), b'\x7c')
    let sender_data : @types.MlsSenderData = {
      leaf_index: 2U,
      generation: 5U,
      reuse_guard: b"\xde\xad\xbe\xef",
    }

    // Application message with padding
    let app_content : @types.FramedContent = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      sender: @types.Sender::Member(2U),
      authenticated_data: b"header-aad",
      content: @types.FramedContentBody::Application(b"hello moonmls"),
    }
    let sig = @schedule.sign_framed_content(
      cs,
      sign_priv,
      @types.WireFormat::MlsPrivateMessage,
      app_content,
      Some(gc),
    )
    let auth : @types.FramedContentAuthData = {
      signature: sig,
      confirmation_tag: None,
    }
    let priv_msg = @schedule.encrypt_private_message_with_keys(
      cs, sender_data_secret, sender_data, content_key, content_nonce, app_content,
      auth, 13,
    )

    let dec_sd = @schedule.decrypt_sender_data(cs, sender_data_secret, priv_msg)
    assert_eq(dec_sd, sender_data)

    let dec_ac = @schedule.decrypt_private_message_with_keys(
      cs, sign_pub, gc, dec_sd, content_key, content_nonce, priv_msg,
    )
    assert_eq(dec_ac.wire_format, @types.WireFormat::MlsPrivateMessage)
    assert_eq(dec_ac.content, app_content)
    assert_eq(dec_ac.auth, auth)

    // Short ciphertext (< 32B) in derive_sender_data_key_nonce
    let (sk_short, sn_short) = @schedule.derive_sender_data_key_nonce(
      cs, sender_data_secret, b"short",
    )
    assert_eq(sk_short.length(), cs.aead_key_len())
    assert_eq(sn_short.length(), cs.aead_nonce_len())

    // Tampered ciphertext -> DecryptionFailed
    let bad_ct : @types.PrivateMessage = {
      group_id: priv_msg.group_id,
      epoch: priv_msg.epoch,
      content_type: priv_msg.content_type,
      authenticated_data: priv_msg.authenticated_data,
      encrypted_sender_data: priv_msg.encrypted_sender_data,
      ciphertext: flip_byte(priv_msg.ciphertext, 0),
    }
    assert_schedule_err(
      () => {
        @schedule.decrypt_private_message_with_keys(
          cs, sign_pub, gc, dec_sd, content_key, content_nonce, bad_ct,
        )
      },
      @schedule.DecryptionFailed,
    )
    // Changing ciphertext also changes ciphertext_sample so decrypt_sender_data fails
    assert_schedule_err(
      () => @schedule.decrypt_sender_data(cs, sender_data_secret, bad_ct),
      @schedule.DecryptionFailed,
    )

    // Tampered AAD -> DecryptionFailed
    let bad_aad : @types.PrivateMessage = {
      group_id: priv_msg.group_id,
      epoch: priv_msg.epoch,
      content_type: priv_msg.content_type,
      authenticated_data: b"tampered-aad",
      encrypted_sender_data: priv_msg.encrypted_sender_data,
      ciphertext: priv_msg.ciphertext,
    }
    assert_schedule_err(
      () => {
        @schedule.decrypt_private_message_with_keys(
          cs, sign_pub, gc, dec_sd, content_key, content_nonce, bad_aad,
        )
      },
      @schedule.DecryptionFailed,
    )

    // Invalid reuse_guard length -> InvalidReuseGuard
    let bad_rg : @types.MlsSenderData = {
      leaf_index: 2U,
      generation: 5U,
      reuse_guard: b"\x01\x02\x03",
    }
    assert_schedule_err(
      () => {
        @schedule.encrypt_private_message_with_keys(
          cs, sender_data_secret, bad_rg, content_key, content_nonce, app_content,
          auth, 0,
        )
      },
      @schedule.InvalidReuseGuard,
    )

    // Wrong signature key on decrypt -> InvalidSignature
    let (_, wrong_pub) = cs.signature_keypair_from_seed(
      Bytes::make(32, b'\x99'),
    )
    assert_schedule_err(
      () => {
        @schedule.decrypt_private_message_with_keys(
          cs, wrong_pub, gc, dec_sd, content_key, content_nonce, priv_msg,
        )
      },
      @schedule.InvalidSignature,
    )

    // Non-zero padding byte must be rejected by strict decoding
    let valid_pmc : @types.PrivateMessageContent = {
      content: app_content.content,
      auth,
      padding_len: 4,
    }
    let bad_padded_plain = flip_byte(
      valid_pmc.to_bytes(),
      valid_pmc.to_bytes().length() - 1,
    )
    let xored_nonce = Bytes::makei(content_nonce.length(), fn(i) {
      if i < 4 {
        (content_nonce[i].to_int() ^ sender_data.reuse_guard[i].to_int()).to_byte()
      } else {
        content_nonce[i]
      }
    })
    let aad : @types.PrivateContentAad = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      content_type: @types.ContentType::Application,
      authenticated_data: app_content.authenticated_data,
    }
    let forged_ct = cs.aead_seal(
      content_key,
      xored_nonce,
      aad.to_bytes(),
      bad_padded_plain,
    )
    let bad_pad_msg : @types.PrivateMessage = {
      group_id: gc.group_id,
      epoch: gc.epoch,
      content_type: @types.ContentType::Application,
      authenticated_data: app_content.authenticated_data,
      encrypted_sender_data: priv_msg.encrypted_sender_data,
      ciphertext: forged_ct,
    }
    try
      @schedule.decrypt_private_message_with_keys(
        cs, sign_pub, gc, dec_sd, content_key, content_nonce, bad_pad_msg,
      )
    catch {
      @schedule.TlsError(@tls.InvalidEnum(_)) => ()
      other =>
        fail(
          "expected TlsError(InvalidEnum) for non-zero padding, got \{other}",
        )
    } noraise {
      _ => fail("expected non-zero padding to be rejected")
    }
  }
}
