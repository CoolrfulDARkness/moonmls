///|
/// Builds `FramedContentTBS` (RFC 9420 §6.1), enforcing wire format and
/// `GroupContext` presence rules for `Member` / `NewMemberCommit` senders.
fn build_framed_content_tbs(
  wire_format : @types.WireFormat,
  content : @types.FramedContent,
  group_context : @types.GroupContext?,
) -> @types.FramedContentTbs raise ScheduleError {
  match wire_format {
    MlsPublicMessage | MlsPrivateMessage => ()
    MlsWelcome | MlsGroupInfo | MlsKeyPackage => raise InvalidWireFormat
  }
  let context : @types.GroupContext? = match content.sender {
    Member(_) | NewMemberCommit =>
      match group_context {
        Some(ctx) => Some(ctx)
        None => raise MissingGroupContext
      }
    External(_) | NewMemberProposal => None
  }
  { version: @types.PROTOCOL_VERSION_MLS10, wire_format, content, context, }
}

///|
/// Validates that `confirmation_tag` is present iff `content_type == Commit`.
fn validate_confirmation_tag_presence(
  content_type : @types.ContentType,
  confirmation_tag : Bytes?,
) -> Unit raise ScheduleError {
  match content_type {
    Commit => if confirmation_tag is None { raise InvalidConfirmationTag }
    Application | Proposal =>
      if confirmation_tag is Some(_) {
        raise InvalidConfirmationTag
      }
  }
}

///|
/// XORs the 4-byte `reuse_guard` into the first 4 bytes of `nonce`
/// (RFC 9420 §6.3.1).
fn apply_reuse_guard(
  cs : @cs.CipherSuite,
  nonce : Bytes,
  reuse_guard : Bytes,
) -> Bytes raise ScheduleError {
  if reuse_guard.length() != 4 {
    raise InvalidReuseGuard
  }
  if nonce.length() != cs.aead_nonce_len() {
    raise CryptoError(@crypto.CryptoError::InvalidNonceLength)
  }
  Bytes::makei(nonce.length(), fn(i) {
    if i < 4 {
      (nonce[i].to_int() ^ reuse_guard[i].to_int()).to_byte()
    } else {
      nonce[i]
    }
  })
}

///|
/// Signs a `FramedContent` using `SignWithLabel(..., "FramedContentTBS", tbs)`
/// (RFC 9420 §6.1).
pub fn sign_framed_content(
  cs : @cs.CipherSuite,
  sign_priv : Bytes,
  wire_format : @types.WireFormat,
  content : @types.FramedContent,
  group_context : @types.GroupContext?,
) -> Bytes raise ScheduleError {
  let tbs = build_framed_content_tbs(wire_format, content, group_context)
  let tbs_bytes = tbs.to_bytes() catch { e => raise TlsError(e) }
  cs.sign_with_label(sign_priv, "FramedContentTBS", tbs_bytes) catch {
    e => raise map_cs_error(e)
  }
}

///|
/// Verifies a `FramedContent` signature using
/// `VerifyWithLabel(..., "FramedContentTBS", tbs, signature)` (RFC 9420 §6.1).
pub fn verify_framed_content(
  cs : @cs.CipherSuite,
  sign_pub : Bytes,
  wire_format : @types.WireFormat,
  content : @types.FramedContent,
  group_context : @types.GroupContext?,
  signature : Bytes,
) -> Bool {
  let tbs = build_framed_content_tbs(wire_format, content, group_context) catch {
    _ => return false
  }
  let tbs_bytes = tbs.to_bytes() catch { _ => return false }
  cs.verify_with_label(sign_pub, "FramedContentTBS", tbs_bytes, signature)
}

///|
/// Signs and (for `Member` senders) MAC-protects a `FramedContent` into a
/// `PublicMessage` (RFC 9420 §6.2).
///
/// Rejects `Application` content with `UnexpectedContentType` per RFC 9420 §6.2.
pub fn protect_public_message(
  cs : @cs.CipherSuite,
  sign_priv : Bytes,
  membership_key : Bytes?,
  content : @types.FramedContent,
  group_context : @types.GroupContext?,
  confirmation_tag : Bytes?,
) -> @types.PublicMessage raise ScheduleError {
  let content_type = content.content.content_type()
  match content_type {
    Application => raise UnexpectedContentType
    Proposal | Commit => ()
  }
  validate_confirmation_tag_presence(content_type, confirmation_tag)
  let tbs = build_framed_content_tbs(
    @types.WireFormat::MlsPublicMessage,
    content,
    group_context,
  )
  let tbs_bytes = tbs.to_bytes() catch { e => raise TlsError(e) }
  let signature = cs.sign_with_label(sign_priv, "FramedContentTBS", tbs_bytes) catch {
    e => raise map_cs_error(e)
  }
  let auth : @types.FramedContentAuthData = { signature, confirmation_tag, }
  let membership_tag : Bytes? = match content.sender {
    Member(_) =>
      match membership_key {
        Some(mk) =>
          Some(compute_membership_tag(cs, mk, { content_tbs: tbs, auth, }))
        None => raise MissingMembershipKey
      }
    External(_) | NewMemberProposal | NewMemberCommit => None
  }
  { content, auth, membership_tag, }
}

///|
/// Verifies a `PublicMessage` (signature and, for `Member` senders,
/// `membership_tag`) and returns the resulting `AuthenticatedContent`
/// (RFC 9420 §6.2).
pub fn unprotect_public_message(
  cs : @cs.CipherSuite,
  sign_pub : Bytes,
  membership_key : Bytes?,
  msg : @types.PublicMessage,
  group_context : @types.GroupContext?,
) -> @types.AuthenticatedContent raise ScheduleError {
  let content_type = msg.content.content.content_type()
  match content_type {
    Application => raise UnexpectedContentType
    Proposal | Commit => ()
  }
  validate_confirmation_tag_presence(content_type, msg.auth.confirmation_tag)
  match group_context {
    Some(ctx) =>
      if msg.content.group_id != ctx.group_id || msg.content.epoch != ctx.epoch {
        raise GroupContextMismatch
      }
    None => ()
  }
  let tbs = build_framed_content_tbs(
    @types.WireFormat::MlsPublicMessage,
    msg.content,
    group_context,
  )
  match msg.content.sender {
    Member(_) => {
      let mk = match membership_key {
        Some(k) => k
        None => raise MissingMembershipKey
      }
      let tag = match msg.membership_tag {
        Some(t) => t
        None => raise InvalidMembershipTag
      }
      if !verify_membership_tag(
          cs,
          mk,
          { content_tbs: tbs, auth: msg.auth, },
          tag,
        ) {
        raise InvalidMembershipTag
      }
    }
    External(_) | NewMemberProposal | NewMemberCommit =>
      if msg.membership_tag is Some(_) {
        raise InvalidMembershipTag
      }
  }
  let tbs_bytes = tbs.to_bytes() catch { e => raise TlsError(e) }
  if !cs.verify_with_label(
      sign_pub,
      "FramedContentTBS",
      tbs_bytes,
      msg.auth.signature,
    ) {
    raise InvalidSignature
  }
  {
    wire_format: @types.WireFormat::MlsPublicMessage,
    content: msg.content,
    auth: msg.auth,
  }
}

///|
/// Derives `(sender_data_key, sender_data_nonce)` from `sender_data_secret` and
/// the first `min(len(ciphertext), KDF.Nh)` bytes of `ciphertext`
/// (RFC 9420 §6.3.2).
pub fn derive_sender_data_key_nonce(
  cs : @cs.CipherSuite,
  sender_data_secret : Bytes,
  ciphertext : Bytes,
) -> (Bytes, Bytes) raise ScheduleError {
  let nh = cs.secret_len()
  let sample_len = if ciphertext.length() < nh {
    ciphertext.length()
  } else {
    nh
  }
  let sample = @tls.bytes_slice(ciphertext, 0, sample_len) catch {
    e => raise TlsError(e)
  }
  let key = cs.expand_with_label(
    sender_data_secret,
    "key",
    sample,
    cs.aead_key_len(),
  ) catch {
    e => raise map_cs_error(e)
  }
  let nonce = cs.expand_with_label(
    sender_data_secret,
    "nonce",
    sample,
    cs.aead_nonce_len(),
  ) catch {
    e => raise map_cs_error(e)
  }
  (key, nonce)
}

///|
/// Encrypts a signed `FramedContent` and its `FramedContentAuthData` into a
/// `PrivateMessage` using pre-derived per-generation `(content_key, content_nonce)`
/// and epoch `sender_data_secret` (RFC 9420 §6.3.1 & §6.3.2).
pub fn encrypt_private_message_with_keys(
  cs : @cs.CipherSuite,
  sender_data_secret : Bytes,
  sender_data : @types.MlsSenderData,
  content_key : Bytes,
  content_nonce : Bytes,
  content : @types.FramedContent,
  auth : @types.FramedContentAuthData,
  padding_len : Int32,
) -> @types.PrivateMessage raise ScheduleError {
  match content.sender {
    Member(leaf_index) =>
      if leaf_index != sender_data.leaf_index {
        raise SenderMismatch
      }
    External(_) | NewMemberProposal | NewMemberCommit => raise InvalidWireFormat
  }
  let content_type = content.content.content_type()
  validate_confirmation_tag_presence(content_type, auth.confirmation_tag)
  let xored_nonce = apply_reuse_guard(
    cs,
    content_nonce,
    sender_data.reuse_guard,
  )
  let pmc : @types.PrivateMessageContent = {
    content: content.content,
    auth,
    padding_len,
  }
  let plaintext = pmc.to_bytes() catch { e => raise TlsError(e) }
  let content_aad_struct : @types.PrivateContentAad = {
    group_id: content.group_id,
    epoch: content.epoch,
    content_type,
    authenticated_data: content.authenticated_data,
  }
  let content_aad = content_aad_struct.to_bytes() catch {
    e => raise TlsError(e)
  }
  let ciphertext = cs.aead_seal(
    content_key, xored_nonce, content_aad, plaintext,
  ) catch {
    e => raise map_cs_error(e)
  }
  let (sd_key, sd_nonce) = derive_sender_data_key_nonce(
    cs, sender_data_secret, ciphertext,
  )
  let sd_aad_struct : @types.MlsSenderDataAad = {
    group_id: content.group_id,
    epoch: content.epoch,
    content_type,
  }
  let sd_aad = sd_aad_struct.to_bytes() catch { e => raise TlsError(e) }
  let sd_plain = sender_data.to_bytes() catch { e => raise TlsError(e) }
  let encrypted_sender_data = cs.aead_seal(sd_key, sd_nonce, sd_aad, sd_plain) catch {
    e => raise map_cs_error(e)
  }
  {
    group_id: content.group_id,
    epoch: content.epoch,
    content_type,
    authenticated_data: content.authenticated_data,
    encrypted_sender_data,
    ciphertext,
  }
}

///|
/// Decrypts `msg.encrypted_sender_data` to recover `MLSSenderData`
/// (RFC 9420 §6.3.2).
pub fn decrypt_sender_data(
  cs : @cs.CipherSuite,
  sender_data_secret : Bytes,
  msg : @types.PrivateMessage,
) -> @types.MlsSenderData raise ScheduleError {
  let (sd_key, sd_nonce) = derive_sender_data_key_nonce(
    cs,
    sender_data_secret,
    msg.ciphertext,
  )
  let sd_aad_struct : @types.MlsSenderDataAad = {
    group_id: msg.group_id,
    epoch: msg.epoch,
    content_type: msg.content_type,
  }
  let sd_aad = sd_aad_struct.to_bytes() catch { e => raise TlsError(e) }
  let sd_plain = cs.aead_open(
    sd_key,
    sd_nonce,
    sd_aad,
    msg.encrypted_sender_data,
  ) catch {
    e => raise map_cs_error(e)
  }
  @types.MlsSenderData::from_bytes(sd_plain) catch {
    e => raise TlsError(e)
  }
}

///|
/// Decrypts `msg.ciphertext` using pre-derived `(content_key, content_nonce)`
/// and `sender_data.reuse_guard`, strictly checks all-zero padding, and verifies
/// the sender's signature (RFC 9420 §6.3.1).
pub fn decrypt_private_message_with_keys(
  cs : @cs.CipherSuite,
  sign_pub : Bytes,
  group_context : @types.GroupContext,
  sender_data : @types.MlsSenderData,
  content_key : Bytes,
  content_nonce : Bytes,
  msg : @types.PrivateMessage,
) -> @types.AuthenticatedContent raise ScheduleError {
  if msg.group_id != group_context.group_id || msg.epoch != group_context.epoch {
    raise GroupContextMismatch
  }
  let xored_nonce = apply_reuse_guard(
    cs,
    content_nonce,
    sender_data.reuse_guard,
  )
  let content_aad_struct : @types.PrivateContentAad = {
    group_id: msg.group_id,
    epoch: msg.epoch,
    content_type: msg.content_type,
    authenticated_data: msg.authenticated_data,
  }
  let content_aad = content_aad_struct.to_bytes() catch {
    e => raise TlsError(e)
  }
  let plaintext = cs.aead_open(
    content_key,
    xored_nonce,
    content_aad,
    msg.ciphertext,
  ) catch {
    e => raise map_cs_error(e)
  }
  let pmc = @types.PrivateMessageContent::from_bytes(
    plaintext,
    msg.content_type,
  ) catch {
    e => raise TlsError(e)
  }
  let content : @types.FramedContent = {
    group_id: msg.group_id,
    epoch: msg.epoch,
    sender: @types.Sender::Member(sender_data.leaf_index),
    authenticated_data: msg.authenticated_data,
    content: pmc.content,
  }
  if !verify_framed_content(
      cs,
      sign_pub,
      @types.WireFormat::MlsPrivateMessage,
      content,
      Some(group_context),
      pmc.auth.signature,
    ) {
    raise InvalidSignature
  }
  {
    wire_format: @types.WireFormat::MlsPrivateMessage,
    content,
    auth: pmc.auth,
  }
}
