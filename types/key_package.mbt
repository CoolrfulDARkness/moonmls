///|
/// Unsigned body of a `KeyPackage` (`KeyPackageTBS`, RFC 9420 §10).
#derive(Eq, Debug)
pub(all) struct KeyPackageTbs {
  version : UInt32
  cipher_suite : UInt32
  init_key : Bytes
  leaf_node : LeafNode
  extensions : Array[Extension]
}

///|
pub fn KeyPackageTbs::encode(
  self : KeyPackageTbs,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.version)
  w.write_u16(self.cipher_suite)
  w.write_opaque(self.init_key)
  self.leaf_node.encode(w)
  encode_extensions(self.extensions, w)
}

///|
pub fn KeyPackageTbs::to_bytes(
  self : KeyPackageTbs,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn KeyPackageTbs::decode(
  r : @tls.Reader,
) -> KeyPackageTbs raise @tls.TlsError {
  let version = r.read_u16()
  let cipher_suite = r.read_u16()
  let init_key = r.read_opaque()
  let leaf_node = LeafNode::decode(r)
  let extensions = decode_extensions(r)
  { version, cipher_suite, init_key, leaf_node, extensions, }
}

///|
pub fn KeyPackageTbs::from_bytes(
  b : Bytes,
) -> KeyPackageTbs raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = KeyPackageTbs::decode(r)
  r.ensure_empty()
  v
}

///|
/// Signed `KeyPackage` (RFC 9420 §10).
#derive(Eq, Debug)
pub(all) struct KeyPackage {
  version : UInt32
  cipher_suite : UInt32
  init_key : Bytes
  leaf_node : LeafNode
  extensions : Array[Extension]
  signature : Bytes
}

///|
pub fn KeyPackage::to_tbs(self : KeyPackage) -> KeyPackageTbs {
  {
    version: self.version,
    cipher_suite: self.cipher_suite,
    init_key: self.init_key,
    leaf_node: self.leaf_node,
    extensions: self.extensions,
  }
}

///|
pub fn KeyPackage::encode_tbs(self : KeyPackage) -> Bytes raise @tls.TlsError {
  self.to_tbs().to_bytes()
}

///|
pub fn KeyPackage::encode(
  self : KeyPackage,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.to_tbs().encode(w)
  w.write_opaque(self.signature)
}

///|
pub fn KeyPackage::to_bytes(self : KeyPackage) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn KeyPackage::decode(r : @tls.Reader) -> KeyPackage raise @tls.TlsError {
  let tbs = KeyPackageTbs::decode(r)
  let signature = r.read_opaque()
  {
    version: tbs.version,
    cipher_suite: tbs.cipher_suite,
    init_key: tbs.init_key,
    leaf_node: tbs.leaf_node,
    extensions: tbs.extensions,
    signature,
  }
}

///|
pub fn KeyPackage::from_bytes(b : Bytes) -> KeyPackage raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = KeyPackage::decode(r)
  r.ensure_empty()
  v
}

///|
/// Group state summary (`GroupContext`, RFC 9420 §8.1).
#derive(Eq, Debug)
pub(all) struct GroupContext {
  version : UInt32
  cipher_suite : UInt32
  group_id : Bytes
  epoch : UInt64
  tree_hash : Bytes
  confirmed_transcript_hash : Bytes
  extensions : Array[Extension]
}

///|
pub fn GroupContext::encode(
  self : GroupContext,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.version)
  w.write_u16(self.cipher_suite)
  w.write_opaque(self.group_id)
  w.write_u64(self.epoch)
  w.write_opaque(self.tree_hash)
  w.write_opaque(self.confirmed_transcript_hash)
  encode_extensions(self.extensions, w)
}

///|
pub fn GroupContext::to_bytes(self : GroupContext) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn GroupContext::decode(
  r : @tls.Reader,
) -> GroupContext raise @tls.TlsError {
  let version = r.read_u16()
  let cipher_suite = r.read_u16()
  let group_id = r.read_opaque()
  let epoch = r.read_u64()
  let tree_hash = r.read_opaque()
  let confirmed_transcript_hash = r.read_opaque()
  let extensions = decode_extensions(r)
  {
    version,
    cipher_suite,
    group_id,
    epoch,
    tree_hash,
    confirmed_transcript_hash,
    extensions,
  }
}

///|
pub fn GroupContext::from_bytes(b : Bytes) -> GroupContext raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = GroupContext::decode(r)
  r.ensure_empty()
  v
}

///|
/// Unsigned body of a `GroupInfo` (`GroupInfoTBS`, RFC 9420 §12.4.3).
#derive(Eq, Debug)
pub(all) struct GroupInfoTbs {
  group_context : GroupContext
  extensions : Array[Extension]
  confirmation_tag : Bytes
  signer : UInt32
}

///|
pub fn GroupInfoTbs::encode(
  self : GroupInfoTbs,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.group_context.encode(w)
  encode_extensions(self.extensions, w)
  w.write_opaque(self.confirmation_tag)
  w.write_u32(self.signer)
}

///|
pub fn GroupInfoTbs::to_bytes(self : GroupInfoTbs) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn GroupInfoTbs::decode(
  r : @tls.Reader,
) -> GroupInfoTbs raise @tls.TlsError {
  let group_context = GroupContext::decode(r)
  let extensions = decode_extensions(r)
  let confirmation_tag = r.read_opaque()
  let signer = r.read_u32()
  { group_context, extensions, confirmation_tag, signer, }
}

///|
pub fn GroupInfoTbs::from_bytes(b : Bytes) -> GroupInfoTbs raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = GroupInfoTbs::decode(r)
  r.ensure_empty()
  v
}

///|
/// Signed `GroupInfo` (RFC 9420 §12.4.3).
#derive(Eq, Debug)
pub(all) struct GroupInfo {
  group_context : GroupContext
  extensions : Array[Extension]
  confirmation_tag : Bytes
  signer : UInt32
  signature : Bytes
}

///|
pub fn GroupInfo::to_tbs(self : GroupInfo) -> GroupInfoTbs {
  {
    group_context: self.group_context,
    extensions: self.extensions,
    confirmation_tag: self.confirmation_tag,
    signer: self.signer,
  }
}

///|
pub fn GroupInfo::encode_tbs(self : GroupInfo) -> Bytes raise @tls.TlsError {
  self.to_tbs().to_bytes()
}

///|
pub fn GroupInfo::encode(
  self : GroupInfo,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.to_tbs().encode(w)
  w.write_opaque(self.signature)
}

///|
pub fn GroupInfo::to_bytes(self : GroupInfo) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn GroupInfo::decode(r : @tls.Reader) -> GroupInfo raise @tls.TlsError {
  let tbs = GroupInfoTbs::decode(r)
  let signature = r.read_opaque()
  {
    group_context: tbs.group_context,
    extensions: tbs.extensions,
    confirmation_tag: tbs.confirmation_tag,
    signer: tbs.signer,
    signature,
  }
}

///|
pub fn GroupInfo::from_bytes(b : Bytes) -> GroupInfo raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = GroupInfo::decode(r)
  r.ensure_empty()
  v
}

///|
/// Secrets encrypted to a new member in a `Welcome` (`GroupSecrets`, RFC 9420 §12.4.3.1).
#derive(Eq, Debug)
pub(all) struct GroupSecrets {
  joiner_secret : Bytes
  path_secret : Bytes?
  psks : Array[PreSharedKeyId]
}

///|
pub fn GroupSecrets::encode(
  self : GroupSecrets,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.joiner_secret)
  w.write_optional(self.path_secret, (sub, ps) => sub.write_opaque(ps))
  w.write_vec(sub => {
    for i = 0; i < self.psks.length(); i = i + 1 {
      self.psks[i].encode(sub)
    }
  })
}

///|
pub fn GroupSecrets::to_bytes(self : GroupSecrets) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn GroupSecrets::decode(
  r : @tls.Reader,
) -> GroupSecrets raise @tls.TlsError {
  let joiner_secret = r.read_opaque()
  let path_secret = r.read_optional(sub => sub.read_opaque())
  let psks = r.read_vec(sub => PreSharedKeyId::decode(sub))
  { joiner_secret, path_secret, psks, }
}

///|
pub fn GroupSecrets::from_bytes(b : Bytes) -> GroupSecrets raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = GroupSecrets::decode(r)
  r.ensure_empty()
  v
}

///|
/// Per-recipient encrypted `GroupSecrets` entry (`EncryptedGroupSecrets`, RFC 9420 §12.4.3.1).
#derive(Eq, Debug)
pub(all) struct EncryptedGroupSecrets {
  new_member : Bytes
  encrypted_group_secrets : HpkeCiphertext
}

///|
pub fn EncryptedGroupSecrets::encode(
  self : EncryptedGroupSecrets,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.new_member)
  self.encrypted_group_secrets.encode(w)
}

///|
pub fn EncryptedGroupSecrets::to_bytes(
  self : EncryptedGroupSecrets,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn EncryptedGroupSecrets::decode(
  r : @tls.Reader,
) -> EncryptedGroupSecrets raise @tls.TlsError {
  let new_member = r.read_opaque()
  let encrypted_group_secrets = HpkeCiphertext::decode(r)
  { new_member, encrypted_group_secrets, }
}

///|
pub fn EncryptedGroupSecrets::from_bytes(
  b : Bytes,
) -> EncryptedGroupSecrets raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = EncryptedGroupSecrets::decode(r)
  r.ensure_empty()
  v
}

///|
/// Group invitation message (`Welcome`, RFC 9420 §12.4.3.1).
#derive(Eq, Debug)
pub(all) struct Welcome {
  cipher_suite : UInt32
  secrets : Array[EncryptedGroupSecrets]
  encrypted_group_info : Bytes
}

///|
pub fn Welcome::encode(
  self : Welcome,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.cipher_suite)
  w.write_vec(sub => {
    for i = 0; i < self.secrets.length(); i = i + 1 {
      self.secrets[i].encode(sub)
    }
  })
  w.write_opaque(self.encrypted_group_info)
}

///|
pub fn Welcome::to_bytes(self : Welcome) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Welcome::decode(r : @tls.Reader) -> Welcome raise @tls.TlsError {
  let cipher_suite = r.read_u16()
  let secrets = r.read_vec(sub => EncryptedGroupSecrets::decode(sub))
  let encrypted_group_info = r.read_opaque()
  { cipher_suite, secrets, encrypted_group_info, }
}

///|
pub fn Welcome::from_bytes(b : Bytes) -> Welcome raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Welcome::decode(r)
  r.ensure_empty()
  v
}
