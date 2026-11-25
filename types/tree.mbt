///|
/// Leaf node in the MLS ratchet tree (`LeafNode`, RFC 9420 §7.2).
#derive(Eq, Debug)
pub(all) struct LeafNode {
  encryption_key : Bytes
  signature_key : Bytes
  credential : Credential
  capabilities : Capabilities
  leaf_node_source : LeafNodeSource
  lifetime : Lifetime?
  parent_hash : Bytes?
  extensions : Array[Extension]
  signature : Bytes
}

///|
fn LeafNode::encode_body_before_sig(
  self : LeafNode,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.encryption_key)
  w.write_opaque(self.signature_key)
  self.credential.encode(w)
  self.capabilities.encode(w)
  self.leaf_node_source.encode(w)
  match self.leaf_node_source {
    KeyPackage => {
      if self.parent_hash is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "KeyPackage LeafNode must not have parent_hash",
        )
      }
      match self.lifetime {
        Some(lt) => lt.encode(w)
        None =>
          raise @tls.TlsError::InvalidEnum(
            "KeyPackage LeafNode requires lifetime",
          )
      }
    }
    Update => {
      if self.lifetime is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "Update LeafNode must not have lifetime",
        )
      }
      if self.parent_hash is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "Update LeafNode must not have parent_hash",
        )
      }
    }
    Commit => {
      if self.lifetime is Some(_) {
        raise @tls.TlsError::InvalidEnum(
          "Commit LeafNode must not have lifetime",
        )
      }
      match self.parent_hash {
        Some(ph) => w.write_opaque(ph)
        None =>
          raise @tls.TlsError::InvalidEnum(
            "Commit LeafNode requires parent_hash",
          )
      }
    }
  }
  encode_extensions(self.extensions, w)
}

///|
/// Encodes `LeafNodeTBS` (RFC 9420 §7.2) for signing or verification.
/// Appends `group_id<V>` and `leaf_index` (uint32) when `leaf_node_source`
/// is `Update` or `Commit`.
pub fn LeafNode::encode_tbs(
  self : LeafNode,
  group_id : Bytes?,
  leaf_index : UInt32?,
) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode_body_before_sig(w)
  match self.leaf_node_source {
    KeyPackage => ()
    Update | Commit =>
      match (group_id, leaf_index) {
        (Some(gid), Some(idx)) => {
          w.write_opaque(gid)
          w.write_u32(idx)
        }
        _ =>
          raise @tls.TlsError::InvalidEnum(
            "Update/Commit LeafNodeTBS requires group_id and leaf_index",
          )
      }
  }
  w.to_bytes()
}

///|
pub fn LeafNode::encode(
  self : LeafNode,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  self.encode_body_before_sig(w)
  w.write_opaque(self.signature)
}

///|
pub fn LeafNode::to_bytes(self : LeafNode) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn LeafNode::decode(r : @tls.Reader) -> LeafNode raise @tls.TlsError {
  let encryption_key = r.read_opaque()
  let signature_key = r.read_opaque()
  let credential = Credential::decode(r)
  let capabilities = Capabilities::decode(r)
  let leaf_node_source = LeafNodeSource::decode(r)
  let (lifetime, parent_hash) : (Lifetime?, Bytes?) = match leaf_node_source {
    KeyPackage => (Some(Lifetime::decode(r)), None)
    Update => (None, None)
    Commit => (None, Some(r.read_opaque()))
  }
  let extensions = decode_extensions(r)
  let signature = r.read_opaque()
  {
    encryption_key,
    signature_key,
    credential,
    capabilities,
    leaf_node_source,
    lifetime,
    parent_hash,
    extensions,
    signature,
  }
}

///|
pub fn LeafNode::from_bytes(b : Bytes) -> LeafNode raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = LeafNode::decode(r)
  r.ensure_empty()
  v
}

///|
/// Parent node in the MLS ratchet tree (`ParentNode`, RFC 9420 §7.1).
#derive(Eq, Debug)
pub(all) struct ParentNode {
  encryption_key : Bytes
  parent_hash : Bytes
  unmerged_leaves : Array[UInt32]
}

///|
pub fn ParentNode::encode(
  self : ParentNode,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_opaque(self.encryption_key)
  w.write_opaque(self.parent_hash)
  encode_u32_vec(self.unmerged_leaves, w)
}

///|
pub fn ParentNode::to_bytes(self : ParentNode) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn ParentNode::decode(r : @tls.Reader) -> ParentNode raise @tls.TlsError {
  let encryption_key = r.read_opaque()
  let parent_hash = r.read_opaque()
  let unmerged_leaves = decode_u32_vec(r)
  { encryption_key, parent_hash, unmerged_leaves, }
}

///|
pub fn ParentNode::from_bytes(b : Bytes) -> ParentNode raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = ParentNode::decode(r)
  r.ensure_empty()
  v
}

///|
/// Ratchet tree node (`Node`, RFC 9420 §7.1).
#derive(Eq, Debug)
pub(all) enum Node {
  Leaf(LeafNode)
  Parent(ParentNode)
}

///|
pub fn Node::encode(self : Node, w : @tls.Writer) -> Unit raise @tls.TlsError {
  match self {
    Leaf(leaf) => {
      w.write_u8(b'\x01')
      leaf.encode(w)
    }
    Parent(parent) => {
      w.write_u8(b'\x02')
      parent.encode(w)
    }
  }
}

///|
pub fn Node::to_bytes(self : Node) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  self.encode(w)
  w.to_bytes()
}

///|
pub fn Node::decode(r : @tls.Reader) -> Node raise @tls.TlsError {
  let node_type = r.read_u8()
  match node_type {
    b'\x01' => Leaf(LeafNode::decode(r))
    b'\x02' => Parent(ParentNode::decode(r))
    _ => raise @tls.TlsError::InvalidEnum("invalid NodeType: \{node_type}")
  }
}

///|
pub fn Node::from_bytes(b : Bytes) -> Node raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = Node::decode(r)
  r.ensure_empty()
  v
}

///|
/// Ratchet tree representation (`optional<Node> ratchet_tree<V>`, RFC 9420 §12.4.3.3).
pub type RatchetTree = Array[Node?]

///|
pub fn encode_ratchet_tree(
  tree : RatchetTree,
  w : @tls.Writer,
) -> Unit raise @tls.TlsError {
  w.write_vec(sub => {
    for i = 0; i < tree.length(); i = i + 1 {
      sub.write_optional(tree[i], (s, node) => node.encode(s))
    }
  })
}

///|
pub fn ratchet_tree_to_bytes(tree : RatchetTree) -> Bytes raise @tls.TlsError {
  let w = @tls.Writer::new()
  encode_ratchet_tree(tree, w)
  w.to_bytes()
}

///|
pub fn decode_ratchet_tree(r : @tls.Reader) -> RatchetTree raise @tls.TlsError {
  r.read_vec(sub => sub.read_optional(s => Node::decode(s)))
}

///|
pub fn ratchet_tree_from_bytes(b : Bytes) -> RatchetTree raise @tls.TlsError {
  let r = @tls.Reader::new(b)
  let v = decode_ratchet_tree(r)
  r.ensure_empty()
  v
}
