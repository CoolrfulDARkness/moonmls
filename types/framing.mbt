///|
/// Sender of an MLS framed message (`Sender`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum Sender {
  Member(UInt32)
  External(UInt32)
  NewMemberProposal
  NewMemberCommit
}

///|
pub fn Sender::encode(self : Sender, w : @tls.Writer) -> Unit {
  match self {
    Member(leaf_index) => {
      w.write_u8(b'\x01')
      w.write_u32(leaf_index)
    }
    External(sender_index) => {
      w.write_u8(b'\x02')
      w.write_u32(sender_index)
    }
    NewMemberProposal => w.write_u8(b'\x03')
    NewMemberCommit => w.write_u8(b'\x04')
  }
}

///|
pub fn Sender::to_bytes(self : Sender) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Sender::decode(r : @tls.Reader) -> Sender raise @tls.TlsError {
  let sender_type = r.read_u8()
  match sender_type {
    b'\x01' => Member(r.read_u32())
    b'\x02' => External(r.read_u32())
    b'\x03' => NewMemberProposal
    b'\x04' => NewMemberCommit
    _ => raise @tls.TlsError::InvalidEnum("invalid SenderType: \{sender_type}")
  }
}

///|
pub fn Sender::from_bytes(b : Bytes) -> Sender raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Sender::decode(r)
  r.ensure_empty()
  v
}

///|
/// Payload of a `FramedContent` or `PrivateMessageContent` (RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum FramedContentBody {
  Application(Bytes)
  Proposal(Proposal)
  Commit(Commit)
}

///|
pub fn FramedContentBody::content_type(self : FramedContentBody) -> ContentType {
  match self {
    Application(_) => ContentType::Application
    Proposal(_) => ContentType::Proposal
    Commit(_) => ContentType::Commit
  }
}

///|
/// Encodes the payload body without the `uint8 content_type` discriminant
/// (used in `PrivateMessageContent`).
pub fn FramedContentBody::encode_payload(
  self : FramedContentBody,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  match self {
    Application(data) => w.write_opaque(data)
    Proposal(p) => p.encode(w)
    Commit(c) => c.encode(w)
  }
}

///|
/// Decodes the payload body using an externally supplied `ContentType`
/// (used in `PrivateMessageContent`).
pub fn FramedContentBody::decode_payload(
  content_type : ContentType,
  r : @tls.Reader,
) -> FramedContentBody raise @tls.TlsError {
  match content_type {
    Application => Application(r.read_opaque())
    Proposal => Proposal(Proposal::decode(r))
    Commit => Commit(Commit::decode(r))
  }
}

///|
pub fn FramedContentBody::encode(
  self : FramedContentBody,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.content_type().encode(w)
  self.encode_payload(w)
}

///|
pub fn FramedContentBody::to_bytes(
  self : FramedContentBody,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn FramedContentBody::decode(
  r : @tls.Reader,
) -> FramedContentBody raise @tls.TlsError {
  let ct = ContentType::decode(r)
  FramedContentBody::decode_payload(ct, r)
}

///|
pub fn FramedContentBody::from_bytes(
  b : Bytes,
) -> FramedContentBody raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = FramedContentBody::decode(r)
  r.ensure_empty()
  v
}

///|
/// Framed MLS message content (`FramedContent`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) struct FramedContent {
  group_id : Bytes
  epoch : UInt64
  sender : Sender
  authenticated_data : Bytes
  content : FramedContentBody
}

///|
pub fn FramedContent::encode(
  self : FramedContent,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.group_id)
  w.write_u64(self.epoch)
  self.sender.encode(w)
  w.write_opaque(self.authenticated_data)
  self.content.encode(w)
}

///|
pub fn FramedContent::to_bytes(
  self : FramedContent,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn FramedContent::decode(
  r : @tls.Reader,
) -> FramedContent raise @tls.TlsError {
  let group_id = r.read_opaque()
  let epoch = r.read_u64()
  let sender = Sender::decode(r)
  let authenticated_data = r.read_opaque()
  let content = FramedContentBody::decode(r)
  { group_id, epoch, sender, authenticated_data, content, }
}

///|
pub fn FramedContent::from_bytes(
  b : Bytes,
) -> FramedContent raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = FramedContent::decode(r)
  r.ensure_empty()
  v
}

///|
/// Authentication data attached to a `FramedContent` (`FramedContentAuthData`, RFC 9420 §6.1).
/// `confirmation_tag` is present on the wire if and only if `content_type == Commit`.
#derive(Eq, Debug)
pub(all) struct FramedContentAuthData {
  signature : Bytes
  confirmation_tag : Bytes?
}

///|
pub fn FramedContentAuthData::encode(
  self : FramedContentAuthData,
  w : @tls.Writer,
  content_type : ContentType,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.signature)
  match content_type {
    Commit =>
      match self.confirmation_tag {
        Some(tag) => w.write_opaque(tag)
        None =>
          raise @tls.TlsError::InvalidEnum(
            "Commit FramedContentAuthData requires confirmation_tag",
          )
      }
    Application | Proposal =>
      if self.confirmation_tag is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "non-Commit FramedContentAuthData must not have confirmation_tag",
        )
      }
  }
}

///|
pub fn FramedContentAuthData::to_bytes(
  self : FramedContentAuthData,
  content_type : ContentType,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w, content_type)
  w.to_bytes()
}

///|
pub fn FramedContentAuthData::decode(
  r : @tls.Reader,
  content_type : ContentType,
) -> FramedContentAuthData raise @tls.TlsError {
  let signature = r.read_opaque()
  let confirmation_tag : Bytes? = match content_type {
    Commit => Some(r.read_opaque())
    Application | Proposal => None
  }
  { signature, confirmation_tag, }
}

///|
pub fn FramedContentAuthData::from_bytes(
  b : Bytes,
  content_type : ContentType,
) -> FramedContentAuthData raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = FramedContentAuthData::decode(r, content_type)
  r.ensure_empty()
  v
}

///|
/// Signature input for framed messages (`FramedContentTBS`, RFC 9420 §6.1).
/// `context` is encoded if and only if `content.sender` is `Member` or `NewMemberCommit`.
#derive(Eq, Debug)
pub(all) struct FramedContentTbs {
  version : UInt32
  wire_format : WireFormat
  content : FramedContent
  context : GroupContext?
}

///|
pub fn FramedContentTbs::encode(
  self : FramedContentTbs,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.version)
  self.wire_format.encode(w)
  self.content.encode(w)
  match self.content.sender {
    Member(_) | NewMemberCommit =>
      match self.context {
        Some(ctx) => ctx.encode(w)
        None =>
          raise @tls.TlsError::InvalidEnum(
            "Member/NewMemberCommit FramedContentTBS requires GroupContext",
          )
      }
    External(_) | NewMemberProposal =>
      if self.context is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "External/NewMemberProposal FramedContentTBS must not have GroupContext",
        )
      }
  }
}

///|
pub fn FramedContentTbs::to_bytes(
  self : FramedContentTbs,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn FramedContentTbs::decode(
  r : @tls.Reader,
) -> FramedContentTbs raise @tls.TlsError {
  let version = r.read_u16()
  let wire_format = WireFormat::decode(r)
  let content = FramedContent::decode(r)
  let context : GroupContext? = match content.sender {
    Member(_) | NewMemberCommit => Some(GroupContext::decode(r))
    External(_) | NewMemberProposal => None
  }
  { version, wire_format, content, context, }
}

///|
pub fn FramedContentTbs::from_bytes(
  b : Bytes,
) -> FramedContentTbs raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = FramedContentTbs::decode(r)
  r.ensure_empty()
  v
}

///|
/// Authenticated framed content (`AuthenticatedContent`, RFC 9420 §6.1).
#derive(Eq, Debug)
pub(all) struct AuthenticatedContent {
  wire_format : WireFormat
  content : FramedContent
  auth : FramedContentAuthData
}

///|
pub fn AuthenticatedContent::encode(
  self : AuthenticatedContent,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.wire_format.encode(w)
  self.content.encode(w)
  self.auth.encode(w, self.content.content.content_type())
}

///|
pub fn AuthenticatedContent::to_bytes(
  self : AuthenticatedContent,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn AuthenticatedContent::decode(
  r : @tls.Reader,
) -> AuthenticatedContent raise @tls.TlsError {
  let wire_format = WireFormat::decode(r)
  let content = FramedContent::decode(r)
  let auth = FramedContentAuthData::decode(r, content.content.content_type())
  { wire_format, content, auth, }
}

///|
pub fn AuthenticatedContent::from_bytes(
  b : Bytes,
) -> AuthenticatedContent raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = AuthenticatedContent::decode(r)
  r.ensure_empty()
  v
}

///|
/// Membership MAC input (`AuthenticatedContentTBM`, RFC 9420 §6.2).
#derive(Eq, Debug)
pub(all) struct AuthenticatedContentTbm {
  content_tbs : FramedContentTbs
  auth : FramedContentAuthData
}

///|
pub fn AuthenticatedContentTbm::encode(
  self : AuthenticatedContentTbm,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.content_tbs.encode(w)
  self.auth.encode(w, self.content_tbs.content.content.content_type())
}

///|
pub fn AuthenticatedContentTbm::to_bytes(
  self : AuthenticatedContentTbm,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn AuthenticatedContentTbm::decode(
  r : @tls.Reader,
) -> AuthenticatedContentTbm raise @tls.TlsError {
  let content_tbs = FramedContentTbs::decode(r)
  let auth = FramedContentAuthData::decode(
    r,
    content_tbs.content.content.content_type(),
  )
  { content_tbs, auth, }
}

///|
pub fn AuthenticatedContentTbm::from_bytes(
  b : Bytes,
) -> AuthenticatedContentTbm raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = AuthenticatedContentTbm::decode(r)
  r.ensure_empty()
  v
}

///|
/// Confirmed transcript hash input (`ConfirmedTranscriptHashInput`, RFC 9420 §8.2).
#derive(Eq, Debug)
pub(all) struct ConfirmedTranscriptHashInput {
  wire_format : WireFormat
  content : FramedContent
  signature : Bytes
}

///|
pub fn ConfirmedTranscriptHashInput::encode(
  self : ConfirmedTranscriptHashInput,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.wire_format.encode(w)
  self.content.encode(w)
  w.write_opaque(self.signature)
}

///|
pub fn ConfirmedTranscriptHashInput::to_bytes(
  self : ConfirmedTranscriptHashInput,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ConfirmedTranscriptHashInput::decode(
  r : @tls.Reader,
) -> ConfirmedTranscriptHashInput raise @tls.TlsError {
  let wire_format = WireFormat::decode(r)
  let content = FramedContent::decode(r)
  let signature = r.read_opaque()
  { wire_format, content, signature, }
}

///|
pub fn ConfirmedTranscriptHashInput::from_bytes(
  b : Bytes,
) -> ConfirmedTranscriptHashInput raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ConfirmedTranscriptHashInput::decode(r)
  r.ensure_empty()
  v
}

///|
/// Interim transcript hash input (`InterimTranscriptHashInput`, RFC 9420 §8.2).
#derive(Eq, Debug)
pub(all) struct InterimTranscriptHashInput {
  confirmation_tag : Bytes
}

///|
pub fn InterimTranscriptHashInput::encode(
  self : InterimTranscriptHashInput,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.confirmation_tag)
}

///|
pub fn InterimTranscriptHashInput::to_bytes(
  self : InterimTranscriptHashInput,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn InterimTranscriptHashInput::decode(
  r : @tls.Reader,
) -> InterimTranscriptHashInput raise @tls.TlsError {
  let confirmation_tag = r.read_opaque()
  { confirmation_tag, }
}

///|
pub fn InterimTranscriptHashInput::from_bytes(
  b : Bytes,
) -> InterimTranscriptHashInput raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = InterimTranscriptHashInput::decode(r)
  r.ensure_empty()
  v
}

///|
/// Unencrypted authenticated message (`PublicMessage`, RFC 9420 §6.2).
/// `membership_tag` is encoded if and only if `content.sender` is `Member`.
#derive(Eq, Debug)
pub(all) struct PublicMessage {
  content : FramedContent
  auth : FramedContentAuthData
  membership_tag : Bytes?
}

///|
pub fn PublicMessage::encode(
  self : PublicMessage,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.content.encode(w)
  self.auth.encode(w, self.content.content.content_type())
  match self.content.sender {
    Member(_) =>
      match self.membership_tag {
        Some(tag) => w.write_opaque(tag)
        None =>
          raise @tls.TlsError::InvalidEnum(
            "Member PublicMessage requires membership_tag",
          )
      }
    External(_) | NewMemberProposal | NewMemberCommit =>
      if self.membership_tag is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "non-Member PublicMessage must not have membership_tag",
        )
      }
  }
}

///|
pub fn PublicMessage::to_bytes(
  self : PublicMessage,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PublicMessage::decode(
  r : @tls.Reader,
) -> PublicMessage raise @tls.TlsError {
  let content = FramedContent::decode(r)
  let auth = FramedContentAuthData::decode(r, content.content.content_type())
  let membership_tag : Bytes? = match content.sender {
    Member(_) => Some(r.read_opaque())
    External(_) | NewMemberProposal | NewMemberCommit => None
  }
  { content, auth, membership_tag, }
}

///|
pub fn PublicMessage::from_bytes(
  b : Bytes,
) -> PublicMessage raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PublicMessage::decode(r)
  r.ensure_empty()
  v
}

///|
/// Encrypted MLS message (`PrivateMessage`, RFC 9420 §6.3).
#derive(Eq, Debug)
pub(all) struct PrivateMessage {
  group_id : Bytes
  epoch : UInt64
  content_type : ContentType
  authenticated_data : Bytes
  encrypted_sender_data : Bytes
  ciphertext : Bytes
}

///|
pub fn PrivateMessage::encode(
  self : PrivateMessage,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.group_id)
  w.write_u64(self.epoch)
  self.content_type.encode(w)
  w.write_opaque(self.authenticated_data)
  w.write_opaque(self.encrypted_sender_data)
  w.write_opaque(self.ciphertext)
}

///|
pub fn PrivateMessage::to_bytes(
  self : PrivateMessage,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PrivateMessage::decode(
  r : @tls.Reader,
) -> PrivateMessage raise @tls.TlsError {
  let group_id = r.read_opaque()
  let epoch = r.read_u64()
  let content_type = ContentType::decode(r)
  let authenticated_data = r.read_opaque()
  let encrypted_sender_data = r.read_opaque()
  let ciphertext = r.read_opaque()
  {
    group_id,
    epoch,
    content_type,
    authenticated_data,
    encrypted_sender_data,
    ciphertext,
  }
}

///|
pub fn PrivateMessage::from_bytes(
  b : Bytes,
) -> PrivateMessage raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PrivateMessage::decode(r)
  r.ensure_empty()
  v
}

///|
/// Plaintext payload inside a `PrivateMessage` (`PrivateMessageContent`, RFC 9420 §6.3.1).
/// All trailing padding bytes MUST be `0x00`.
#derive(Eq, Debug)
pub(all) struct PrivateMessageContent {
  content : FramedContentBody
  auth : FramedContentAuthData
  padding_len : Int32
}

///|
pub fn PrivateMessageContent::encode(
  self : PrivateMessageContent,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  if self.padding_len < 0 {
    raise @tls.TlsError::LengthMismatch
  }
  self.content.encode_payload(w)
  self.auth.encode(w, self.content.content_type())
  for i = 0; i < self.padding_len; i = i + 1 {
    w.write_u8(b'\x00')
  }
}

///|
pub fn PrivateMessageContent::to_bytes(
  self : PrivateMessageContent,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PrivateMessageContent::decode(
  r : @tls.Reader,
  content_type : ContentType,
) -> PrivateMessageContent raise @tls.TlsError {
  let content = FramedContentBody::decode_payload(content_type, r)
  let auth = FramedContentAuthData::decode(r, content_type)
  let mut padding_len = 0
  while !r.is_empty() {
    let b = r.read_u8()
    if b != b'\x00' {
      raise @tls.TlsError::InvalidEnum(
        "non-zero padding byte in PrivateMessageContent: \{b}",
      )
    }
    padding_len += 1
  }
  { content, auth, padding_len, }
}

///|
pub fn PrivateMessageContent::from_bytes(
  b : Bytes,
  content_type : ContentType,
) -> PrivateMessageContent raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PrivateMessageContent::decode(r, content_type)
  r.ensure_empty()
  v
}

///|
/// Associated data for `PrivateMessage` content AEAD (`PrivateContentAAD`, RFC 9420 §6.3.1).
#derive(Eq, Debug)
pub(all) struct PrivateContentAad {
  group_id : Bytes
  epoch : UInt64
  content_type : ContentType
  authenticated_data : Bytes
}

///|
pub fn PrivateContentAad::encode(
  self : PrivateContentAad,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.group_id)
  w.write_u64(self.epoch)
  self.content_type.encode(w)
  w.write_opaque(self.authenticated_data)
}

///|
pub fn PrivateContentAad::to_bytes(
  self : PrivateContentAad,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn PrivateContentAad::decode(
  r : @tls.Reader,
) -> PrivateContentAad raise @tls.TlsError {
  let group_id = r.read_opaque()
  let epoch = r.read_u64()
  let content_type = ContentType::decode(r)
  let authenticated_data = r.read_opaque()
  { group_id, epoch, content_type, authenticated_data, }
}

///|
pub fn PrivateContentAad::from_bytes(
  b : Bytes,
) -> PrivateContentAad raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = PrivateContentAad::decode(r)
  r.ensure_empty()
  v
}

///|
/// Encrypted sender metadata inside a `PrivateMessage` (`MLSSenderData`, RFC 9420 §6.3.2).
/// `reuse_guard` is fixed at 4 bytes.
#derive(Eq, Debug)
pub(all) struct MlsSenderData {
  leaf_index : UInt32
  generation : UInt32
  reuse_guard : Bytes
}

///|
pub fn MlsSenderData::encode(
  self : MlsSenderData,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  if self.reuse_guard.length() != 4 {
    raise @tls.TlsError::LengthMismatch
  }
  w.write_u32(self.leaf_index)
  w.write_u32(self.generation)
  w.write_raw(self.reuse_guard)
}

///|
pub fn MlsSenderData::to_bytes(
  self : MlsSenderData,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn MlsSenderData::decode(
  r : @tls.Reader,
) -> MlsSenderData raise @tls.TlsError {
  let leaf_index = r.read_u32()
  let generation = r.read_u32()
  let reuse_guard = r.read_fixed(4)
  { leaf_index, generation, reuse_guard, }
}

///|
pub fn MlsSenderData::from_bytes(
  b : Bytes,
) -> MlsSenderData raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = MlsSenderData::decode(r)
  r.ensure_empty()
  v
}

///|
/// Associated data for `MLSSenderData` AEAD (`MLSSenderDataAAD`, RFC 9420 §6.3.2).
#derive(Eq, Debug)
pub(all) struct MlsSenderDataAad {
  group_id : Bytes
  epoch : UInt64
  content_type : ContentType
}

///|
pub fn MlsSenderDataAad::encode(
  self : MlsSenderDataAad,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.group_id)
  w.write_u64(self.epoch)
  self.content_type.encode(w)
}

///|
pub fn MlsSenderDataAad::to_bytes(
  self : MlsSenderDataAad,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn MlsSenderDataAad::decode(
  r : @tls.Reader,
) -> MlsSenderDataAad raise @tls.TlsError {
  let group_id = r.read_opaque()
  let epoch = r.read_u64()
  let content_type = ContentType::decode(r)
  { group_id, epoch, content_type, }
}

///|
pub fn MlsSenderDataAad::from_bytes(
  b : Bytes,
) -> MlsSenderDataAad raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = MlsSenderDataAad::decode(r)
  r.ensure_empty()
  v
}

///|
/// Payload body of a top-level `MlsMessage` (RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum MlsMessageBody {
  PublicMessage(PublicMessage)
  PrivateMessage(PrivateMessage)
  Welcome(Welcome)
  GroupInfo(GroupInfo)
  KeyPackage(KeyPackage)
}

///|
pub fn MlsMessageBody::wire_format(self : MlsMessageBody) -> WireFormat {
  match self {
    PublicMessage(_) => WireFormat::MlsPublicMessage
    PrivateMessage(_) => WireFormat::MlsPrivateMessage
    Welcome(_) => WireFormat::MlsWelcome
    GroupInfo(_) => WireFormat::MlsGroupInfo
    KeyPackage(_) => WireFormat::MlsKeyPackage
  }
}

///|
/// Top-level MLS wire message envelope (`MLSMessage`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) struct MlsMessage {
  version : UInt32
  body : MlsMessageBody
}

///|
pub fn MlsMessage::public_message(msg : PublicMessage) -> MlsMessage {
  { version: PROTOCOL_VERSION_MLS10, body: PublicMessage(msg), }
}

///|
pub fn MlsMessage::private_message(msg : PrivateMessage) -> MlsMessage {
  { version: PROTOCOL_VERSION_MLS10, body: PrivateMessage(msg), }
}

///|
pub fn MlsMessage::welcome(w : Welcome) -> MlsMessage {
  { version: PROTOCOL_VERSION_MLS10, body: Welcome(w), }
}

///|
pub fn MlsMessage::group_info(gi : GroupInfo) -> MlsMessage {
  { version: PROTOCOL_VERSION_MLS10, body: GroupInfo(gi), }
}

///|
pub fn MlsMessage::key_package(kp : KeyPackage) -> MlsMessage {
  { version: PROTOCOL_VERSION_MLS10, body: KeyPackage(kp), }
}

///|
pub fn MlsMessage::wire_format(self : MlsMessage) -> WireFormat {
  self.body.wire_format()
}

///|
pub fn MlsMessage::encode(
  self : MlsMessage,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.version)
  self.body.wire_format().encode(w)
  match self.body {
    PublicMessage(m) => m.encode(w)
    PrivateMessage(m) => m.encode(w)
    Welcome(m) => m.encode(w)
    GroupInfo(m) => m.encode(w)
    KeyPackage(m) => m.encode(w)
  }
}

///|
pub fn MlsMessage::to_bytes(self : MlsMessage) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn MlsMessage::decode(r : @tls.Reader) -> MlsMessage raise @tls.TlsError {
  let version = r.read_u16()
  if version != PROTOCOL_VERSION_MLS10 {
    raise @tls.TlsError::InvalidEnum(
      "unsupported MlsMessage version: \{version}",
    )
  }
  let wf = WireFormat::decode(r)
  let body : MlsMessageBody = match wf {
    MlsPublicMessage => PublicMessage(PublicMessage::decode(r))
    MlsPrivateMessage => PrivateMessage(PrivateMessage::decode(r))
    MlsWelcome => Welcome(Welcome::decode(r))
    MlsGroupInfo => GroupInfo(GroupInfo::decode(r))
    MlsKeyPackage => KeyPackage(KeyPackage::decode(r))
  }
  { version, body, }
}

///|
pub fn MlsMessage::from_bytes(b : Bytes) -> MlsMessage raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = MlsMessage::decode(r)
  r.ensure_empty()
  v
}
