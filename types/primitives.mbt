///|
/// MLS 1.0 protocol version identifier (`mls10 = 1`, RFC 9420 §6).
pub const PROTOCOL_VERSION_MLS10 : UInt32 = 1U

///|
/// Cipher suite identifier (`uint16`, RFC 9420 §17.1).
pub type CipherSuiteId = UInt32

///|
/// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (`0x0001`).
pub const CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519 : UInt32 = 0x0001U

///|
/// MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (`0x0002`).
pub const CIPHER_SUITE_MLS_128_DHKEMP256_AES128GCM_SHA256_P256 : UInt32 = 0x0002U

///|
/// MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (`0x0003`).
pub const CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519 : UInt32 = 0x0003U

///|
/// MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 (`0x0004`).
pub const CIPHER_SUITE_MLS_256_DHKEMX448_AES256GCM_SHA512_ED448 : UInt32 = 0x0004U

///|
/// MLS_256_DHKEMP521_AES256GCM_SHA512_P521 (`0x0005`).
pub const CIPHER_SUITE_MLS_256_DHKEMP521_AES256GCM_SHA512_P521 : UInt32 = 0x0005U

///|
/// MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 (`0x0006`).
pub const CIPHER_SUITE_MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448 : UInt32 = 0x0006U

///|
/// MLS_256_DHKEMP384_AES256GCM_SHA384_P384 (`0x0007`).
pub const CIPHER_SUITE_MLS_256_DHKEMP384_AES256GCM_SHA384_P384 : UInt32 = 0x0007U

///|
/// Standard RFC 9420 §17.3 extension type constants.
pub const EXT_APPLICATION_ID : UInt32 = 1U

///|
pub const EXT_RATCHET_TREE : UInt32 = 2U

///|
pub const EXT_REQUIRED_CAPABILITIES : UInt32 = 3U

///|
pub const EXT_EXTERNAL_PUB : UInt32 = 4U

///|
pub const EXT_EXTERNAL_SENDERS : UInt32 = 5U

///|
/// Standard RFC 9420 §5.3 credential type constants.
pub const CREDENTIAL_TYPE_BASIC : UInt32 = 1U

///|
pub const CREDENTIAL_TYPE_X509 : UInt32 = 2U

///|
/// Standard RFC 9420 §12.1 proposal type constants.
pub const PROPOSAL_TYPE_ADD : UInt32 = 1U

///|
pub const PROPOSAL_TYPE_UPDATE : UInt32 = 2U

///|
pub const PROPOSAL_TYPE_REMOVE : UInt32 = 3U

///|
pub const PROPOSAL_TYPE_PSK : UInt32 = 4U

///|
pub const PROPOSAL_TYPE_REINIT : UInt32 = 5U

///|
pub const PROPOSAL_TYPE_EXTERNAL_INIT : UInt32 = 6U

///|
pub const PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS : UInt32 = 7U

///|
/// MLS protocol version (`uint16`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum ProtocolVersion {
  Mls10
}

///|
pub fn ProtocolVersion::to_u16(self : ProtocolVersion) -> UInt32 {
  match self {
    Mls10 => PROTOCOL_VERSION_MLS10
  }
}

///|
pub fn ProtocolVersion::from_u16(
  value : UInt32,
) -> ProtocolVersion raise @tls.TlsError {
  match value {
    1U => Mls10
    _ => raise @tls.TlsError::InvalidEnum("invalid ProtocolVersion: \{value}")
  }
}

///|
pub fn ProtocolVersion::encode(self : ProtocolVersion, w : @tls.Writer) -> Unit {
  w.write_u16(self.to_u16())
}

///|
pub fn ProtocolVersion::to_bytes(self : ProtocolVersion) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ProtocolVersion::decode(
  r : @tls.Reader,
) -> ProtocolVersion raise @tls.TlsError {
  ProtocolVersion::from_u16(r.read_u16())
}

///|
pub fn ProtocolVersion::from_bytes(
  b : Bytes,
) -> ProtocolVersion raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ProtocolVersion::decode(r)
  r.ensure_empty()
  v
}

///|
/// MLS wire format discriminant (`uint16`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum WireFormat {
  MlsPublicMessage
  MlsPrivateMessage
  MlsWelcome
  MlsGroupInfo
  MlsKeyPackage
}

///|
pub fn WireFormat::to_u16(self : WireFormat) -> UInt32 {
  match self {
    MlsPublicMessage => 1U
    MlsPrivateMessage => 2U
    MlsWelcome => 3U
    MlsGroupInfo => 4U
    MlsKeyPackage => 5U
  }
}

///|
pub fn WireFormat::from_u16(value : UInt32) -> WireFormat raise @tls.TlsError {
  match value {
    1U => MlsPublicMessage
    2U => MlsPrivateMessage
    3U => MlsWelcome
    4U => MlsGroupInfo
    5U => MlsKeyPackage
    _ => raise @tls.TlsError::InvalidEnum("invalid WireFormat: \{value}")
  }
}

///|
pub fn WireFormat::encode(self : WireFormat, w : @tls.Writer) -> Unit {
  w.write_u16(self.to_u16())
}

///|
pub fn WireFormat::to_bytes(self : WireFormat) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn WireFormat::decode(r : @tls.Reader) -> WireFormat raise @tls.TlsError {
  WireFormat::from_u16(r.read_u16())
}

///|
pub fn WireFormat::from_bytes(b : Bytes) -> WireFormat raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = WireFormat::decode(r)
  r.ensure_empty()
  v
}

///|
/// MLS framed content type (`uint8`, RFC 9420 §6).
#derive(Eq, Debug)
pub(all) enum ContentType {
  Application
  Proposal
  Commit
}

///|
pub fn ContentType::to_u8(self : ContentType) -> Byte {
  match self {
    Application => b'\x01'
    Proposal => b'\x02'
    Commit => b'\x03'
  }
}

///|
pub fn ContentType::from_u8(value : Byte) -> ContentType raise @tls.TlsError {
  match value {
    b'\x01' => Application
    b'\x02' => Proposal
    b'\x03' => Commit
    _ => raise @tls.TlsError::InvalidEnum("invalid ContentType: \{value}")
  }
}

///|
pub fn ContentType::encode(self : ContentType, w : @tls.Writer) -> Unit {
  w.write_u8(self.to_u8())
}

///|
pub fn ContentType::to_bytes(self : ContentType) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ContentType::decode(r : @tls.Reader) -> ContentType raise @tls.TlsError {
  ContentType::from_u8(r.read_u8())
}

///|
pub fn ContentType::from_bytes(b : Bytes) -> ContentType raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ContentType::decode(r)
  r.ensure_empty()
  v
}

///|
/// Origin of a `LeafNode` (`uint8`, RFC 9420 §7.2).
#derive(Eq, Debug)
pub(all) enum LeafNodeSource {
  KeyPackage
  Update
  Commit
}

///|
pub fn LeafNodeSource::to_u8(self : LeafNodeSource) -> Byte {
  match self {
    KeyPackage => b'\x01'
    Update => b'\x02'
    Commit => b'\x03'
  }
}

///|
pub fn LeafNodeSource::from_u8(
  value : Byte,
) -> LeafNodeSource raise @tls.TlsError {
  match value {
    b'\x01' => KeyPackage
    b'\x02' => Update
    b'\x03' => Commit
    _ => raise @tls.TlsError::InvalidEnum("invalid LeafNodeSource: \{value}")
  }
}

///|
pub fn LeafNodeSource::encode(self : LeafNodeSource, w : @tls.Writer) -> Unit {
  w.write_u8(self.to_u8())
}

///|
pub fn LeafNodeSource::to_bytes(self : LeafNodeSource) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn LeafNodeSource::decode(
  r : @tls.Reader,
) -> LeafNodeSource raise @tls.TlsError {
  LeafNodeSource::from_u8(r.read_u8())
}

///|
pub fn LeafNodeSource::from_bytes(
  b : Bytes,
) -> LeafNodeSource raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = LeafNodeSource::decode(r)
  r.ensure_empty()
  v
}

///|
/// Generic MLS extension (`Extension`, RFC 9420 §13.4).
#derive(Eq, Debug)
pub(all) struct Extension {
  extension_type : UInt32
  extension_data : Bytes
}

///|
pub fn Extension::encode(
  self : Extension,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.extension_type)
  w.write_opaque(self.extension_data)
}

///|
pub fn Extension::to_bytes(self : Extension) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Extension::decode(r : @tls.Reader) -> Extension raise @tls.TlsError {
  let extension_type = r.read_u16()
  let extension_data = r.read_opaque()
  { extension_type, extension_data, }
}

///|
pub fn Extension::from_bytes(b : Bytes) -> Extension raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Extension::decode(r)
  r.ensure_empty()
  v
}

///|
fn encode_extensions(
  exts : Array[Extension],
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_vec(sub => {
    for i = 0; i < exts.length(); i = i + 1 {
      exts[i].encode(sub)
    }
  })
}

///|
fn decode_extensions(r : @tls.Reader) -> Array[Extension] raise @tls.TlsError {
  r.read_vec(sub => Extension::decode(sub))
}

///|
fn encode_u16_vec(
  items : Array[UInt32],
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_vec(sub => {
    for i = 0; i < items.length(); i = i + 1 {
      sub.write_u16(items[i])
    }
  })
}

///|
fn decode_u16_vec(r : @tls.Reader) -> Array[UInt32] raise @tls.TlsError {
  r.read_vec(sub => sub.read_u16())
}

///|
fn encode_u32_vec(
  items : Array[UInt32],
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_vec(sub => {
    for i = 0; i < items.length(); i = i + 1 {
      sub.write_u32(items[i])
    }
  })
}

///|
fn decode_u32_vec(r : @tls.Reader) -> Array[UInt32] raise @tls.TlsError {
  r.read_vec(sub => sub.read_u32())
}

///|
/// MLS member credential (`Credential`, RFC 9420 §5.3).
#derive(Eq, Debug)
pub(all) enum Credential {
  Basic(Bytes)
  X509(Array[Bytes])
}

///|
pub fn Credential::credential_type(self : Credential) -> UInt32 {
  match self {
    Basic(_) => CREDENTIAL_TYPE_BASIC
    X509(_) => CREDENTIAL_TYPE_X509
  }
}

///|
pub fn Credential::encode(
  self : Credential,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  match self {
    Basic(identity) => {
      w.write_u16(CREDENTIAL_TYPE_BASIC)
      w.write_opaque(identity)
    }
    X509(certificates) => {
      w.write_u16(CREDENTIAL_TYPE_X509)
      w.write_vec(sub => {
        for i = 0; i < certificates.length(); i = i + 1 {
          sub.write_opaque(certificates[i])
        }
      })
    }
  }
}

///|
pub fn Credential::to_bytes(self : Credential) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Credential::decode(r : @tls.Reader) -> Credential raise @tls.TlsError {
  let credential_type = r.read_u16()
  match credential_type {
    1U => Basic(r.read_opaque())
    2U => X509(r.read_vec(sub => sub.read_opaque()))
    _ =>
      raise @tls.TlsError::InvalidEnum(
        "invalid CredentialType: \{credential_type}",
      )
  }
}

///|
pub fn Credential::from_bytes(b : Bytes) -> Credential raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Credential::decode(r)
  r.ensure_empty()
  v
}

///|
/// Supported MLS capabilities advertised in a `LeafNode` (RFC 9420 §7.2).
#derive(Eq, Debug)
pub(all) struct Capabilities {
  versions : Array[UInt32]
  cipher_suites : Array[UInt32]
  extensions : Array[UInt32]
  proposals : Array[UInt32]
  credentials : Array[UInt32]
}

///|
pub fn Capabilities::encode(
  self : Capabilities,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  encode_u16_vec(self.versions, w)
  encode_u16_vec(self.cipher_suites, w)
  encode_u16_vec(self.extensions, w)
  encode_u16_vec(self.proposals, w)
  encode_u16_vec(self.credentials, w)
}

///|
pub fn Capabilities::to_bytes(self : Capabilities) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Capabilities::decode(
  r : @tls.Reader,
) -> Capabilities raise @tls.TlsError {
  let versions = decode_u16_vec(r)
  let cipher_suites = decode_u16_vec(r)
  let extensions = decode_u16_vec(r)
  let proposals = decode_u16_vec(r)
  let credentials = decode_u16_vec(r)
  { versions, cipher_suites, extensions, proposals, credentials, }
}

///|
pub fn Capabilities::from_bytes(b : Bytes) -> Capabilities raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Capabilities::decode(r)
  r.ensure_empty()
  v
}

///|
/// Validity window of a `KeyPackage` `LeafNode` (`Lifetime`, RFC 9420 §7.2).
#derive(Eq, Debug)
pub(all) struct Lifetime {
  not_before : UInt64
  not_after : UInt64
}

///|
pub fn Lifetime::encode(self : Lifetime, w : @tls.Writer) -> Unit {
  w.write_u64(self.not_before)
  w.write_u64(self.not_after)
}

///|
pub fn Lifetime::to_bytes(self : Lifetime) -> Bytes {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Lifetime::decode(r : @tls.Reader) -> Lifetime raise @tls.TlsError {
  let not_before = r.read_u64()
  let not_after = r.read_u64()
  { not_before, not_after, }
}

///|
pub fn Lifetime::from_bytes(b : Bytes) -> Lifetime raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Lifetime::decode(r)
  r.ensure_empty()
  v
}
