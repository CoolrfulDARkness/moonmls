///|
/// Direct-path node update (`UpdatePathNode`, RFC 9420 §7.6).
#derive(Eq, Debug)
pub(all) struct UpdatePathNode {
  encryption_key : Bytes
  encrypted_path_secret : Array[HpkeCiphertext]
}

///|
pub fn UpdatePathNode::encode(
  self : UpdatePathNode,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.encryption_key)
  w.write_vec(sub => {
    for i = 0; i < self.encrypted_path_secret.length(); i = i + 1 {
      self.encrypted_path_secret[i].encode(sub)
    }
  })
}

///|
pub fn UpdatePathNode::to_bytes(
  self : UpdatePathNode,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn UpdatePathNode::decode(
  r : @tls.Reader,
) -> UpdatePathNode raise @tls.TlsError {
  let encryption_key = r.read_opaque()
  let encrypted_path_secret = r.read_vec(sub => HpkeCiphertext::decode(sub))
  { encryption_key, encrypted_path_secret, }
}

///|
pub fn UpdatePathNode::from_bytes(
  b : Bytes,
) -> UpdatePathNode raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = UpdatePathNode::decode(r)
  r.ensure_empty()
  v
}

///|
/// Commit update path (`UpdatePath`, RFC 9420 §7.6).
#derive(Eq, Debug)
pub(all) struct UpdatePath {
  leaf_node : LeafNode
  nodes : Array[UpdatePathNode]
}

///|
pub fn UpdatePath::encode(
  self : UpdatePath,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.leaf_node.encode(w)
  w.write_vec(sub => {
    for i = 0; i < self.nodes.length(); i = i + 1 {
      self.nodes[i].encode(sub)
    }
  })
}

///|
pub fn UpdatePath::to_bytes(self : UpdatePath) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn UpdatePath::decode(r : @tls.Reader) -> UpdatePath raise @tls.TlsError {
  let leaf_node = LeafNode::decode(r)
  let nodes = r.read_vec(sub => UpdatePathNode::decode(sub))
  { leaf_node, nodes, }
}

///|
pub fn UpdatePath::from_bytes(b : Bytes) -> UpdatePath raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = UpdatePath::decode(r)
  r.ensure_empty()
  v
}

///|
/// MLS proposal (`Proposal`, RFC 9420 §12.1).
#derive(Eq, Debug)
pub(all) enum Proposal {
  Add(KeyPackage)
  Update(LeafNode)
  Remove(UInt32)
  PreSharedKey(PreSharedKeyId)
  ReInit(
    group_id~ : Bytes,
    version~ : UInt32,
    cipher_suite~ : UInt32,
    extensions~ : Array[Extension],
  )
  ExternalInit(Bytes)
  GroupContextExtensions(Array[Extension])
}

///|
pub fn Proposal::proposal_type(self : Proposal) -> UInt32 {
  match self {
    Add(_) => PROPOSAL_TYPE_ADD
    Update(_) => PROPOSAL_TYPE_UPDATE
    Remove(_) => PROPOSAL_TYPE_REMOVE
    PreSharedKey(_) => PROPOSAL_TYPE_PSK
    ReInit(..) => PROPOSAL_TYPE_REINIT
    ExternalInit(_) => PROPOSAL_TYPE_EXTERNAL_INIT
    GroupContextExtensions(_) => PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS
  }
}

///|
/// Encodes only the inner proposal struct body without the `uint16 proposal_type` prefix.
pub fn Proposal::encode_body(
  self : Proposal,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  match self {
    Add(kp) => kp.encode(w)
    Update(leaf) => leaf.encode(w)
    Remove(removed) => w.write_u32(removed)
    PreSharedKey(psk) => psk.encode(w)
    ReInit(group_id~, version~, cipher_suite~, extensions~) => {
      w.write_opaque(group_id)
      w.write_u16(version)
      w.write_u16(cipher_suite)
      encode_extensions(extensions, w)
    }
    ExternalInit(kem_output) => w.write_opaque(kem_output)
    GroupContextExtensions(extensions) => encode_extensions(extensions, w)
  }
}

///|
pub fn Proposal::body_to_bytes(self : Proposal) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode_body(w)
  w.to_bytes()
}

///|
/// Decodes an inner proposal struct body given its `proposal_type` discriminant.
pub fn Proposal::decode_body(
  proposal_type : UInt32,
  r : @tls.Reader,
) -> Proposal raise @tls.TlsError {
  match proposal_type {
    1U => Add(KeyPackage::decode(r))
    2U => Update(LeafNode::decode(r))
    3U => Remove(r.read_u32())
    4U => PreSharedKey(PreSharedKeyId::decode(r))
    5U => {
      let group_id = r.read_opaque()
      let version = r.read_u16()
      let cipher_suite = r.read_u16()
      let extensions = decode_extensions(r)
      ReInit(group_id~, version~, cipher_suite~, extensions~)
    }
    6U => ExternalInit(r.read_opaque())
    7U => GroupContextExtensions(decode_extensions(r))
    _ =>
      raise @tls.TlsError::InvalidEnum("invalid ProposalType: \{proposal_type}")
  }
}

///|
pub fn Proposal::body_from_bytes(
  proposal_type : UInt32,
  b : Bytes,
) -> Proposal raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Proposal::decode_body(proposal_type, r)
  r.ensure_empty()
  v
}

///|
pub fn Proposal::encode(
  self : Proposal,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_u16(self.proposal_type())
  self.encode_body(w)
}

///|
pub fn Proposal::to_bytes(self : Proposal) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Proposal::decode(r : @tls.Reader) -> Proposal raise @tls.TlsError {
  let proposal_type = r.read_u16()
  Proposal::decode_body(proposal_type, r)
}

///|
pub fn Proposal::from_bytes(b : Bytes) -> Proposal raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Proposal::decode(r)
  r.ensure_empty()
  v
}

///|
/// Inline proposal or proposal hash reference (`ProposalOrRef`, RFC 9420 §12.4).
#derive(Eq, Debug)
pub(all) enum ProposalOrRef {
  Proposal(Proposal)
  Reference(Bytes)
}

///|
pub fn ProposalOrRef::encode(
  self : ProposalOrRef,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  match self {
    Proposal(p) => {
      w.write_u8(b'\x01')
      p.encode(w)
    }
    Reference(ref_bytes) => {
      w.write_u8(b'\x02')
      w.write_opaque(ref_bytes)
    }
  }
}

///|
pub fn ProposalOrRef::to_bytes(
  self : ProposalOrRef,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ProposalOrRef::decode(
  r : @tls.Reader,
) -> ProposalOrRef raise @tls.TlsError {
  let tag = r.read_u8()
  match tag {
    b'\x01' => Proposal(Proposal::decode(r))
    b'\x02' => Reference(r.read_opaque())
    _ => raise @tls.TlsError::InvalidEnum("invalid ProposalOrRefType: \{tag}")
  }
}

///|
pub fn ProposalOrRef::from_bytes(
  b : Bytes,
) -> ProposalOrRef raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ProposalOrRef::decode(r)
  r.ensure_empty()
  v
}

///|
/// MLS commit message body (`Commit`, RFC 9420 §12.4).
#derive(Eq, Debug)
pub(all) struct Commit {
  proposals : Array[ProposalOrRef]
  path : UpdatePath?
}

///|
pub fn Commit::encode(
  self : Commit,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_vec(sub => {
    for i = 0; i < self.proposals.length(); i = i + 1 {
      self.proposals[i].encode(sub)
    }
  })
  w.write_optional(self.path, (sub, p) => p.encode(sub))
}

///|
pub fn Commit::to_bytes(self : Commit) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Commit::decode(r : @tls.Reader) -> Commit raise @tls.TlsError {
  let proposals = r.read_vec(sub => ProposalOrRef::decode(sub))
  let path = r.read_optional(sub => UpdatePath::decode(sub))
  { proposals, path, }
}

///|
pub fn Commit::from_bytes(b : Bytes) -> Commit raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Commit::decode(r)
  r.ensure_empty()
  v
}
