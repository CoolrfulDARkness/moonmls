///|
/// Validates ratchet tree structure per RFC 9420 §7.1, §7.4, and §12.4.3.1:
/// - Even indices hold only `LeafNode` or `None`; odd indices hold only `ParentNode` or `None`.
/// - Every `unmerged_leaves` entry on a parent node is a non-blank descendant leaf with no duplicates.
/// - All `encryption_key` values across all non-blank nodes are unique.
/// - All `signature_key` values across all non-blank leaf nodes are unique.
pub fn RatchetTreeState::validate_tree_structure(
  self : RatchetTreeState,
) -> Unit raise TreeError {
  if self.nodes.length() == 0 {
    raise EmptyTree
  }
  let n_nodes = self.n_nodes()
  let n_leaves = self.n_leaves()
  let seen_enc_keys : Map[Bytes, Bool] = Map([])
  let seen_sig_keys : Map[Bytes, Bool] = Map([])
  for node_idx = 0U; node_idx < n_nodes; node_idx = node_idx + 1U {
    let idx = node_idx.reinterpret_as_int()
    if @treemath.is_leaf(node_idx) {
      match self.nodes[idx] {
        None => ()
        Some(@types.Node::Parent(_)) => raise UnexpectedNodeType(node_idx)
        Some(@types.Node::Leaf(leaf)) => {
          if seen_enc_keys.contains(leaf.encryption_key) {
            raise DuplicateKey
          }
          seen_enc_keys.set(leaf.encryption_key, true)
          if seen_sig_keys.contains(leaf.signature_key) {
            raise DuplicateKey
          }
          seen_sig_keys.set(leaf.signature_key, true)
        }
      }
    } else {
      match self.nodes[idx] {
        None => ()
        Some(@types.Node::Leaf(_)) => raise UnexpectedNodeType(node_idx)
        Some(@types.Node::Parent(parent)) => {
          if seen_enc_keys.contains(parent.encryption_key) {
            raise DuplicateKey
          }
          seen_enc_keys.set(parent.encryption_key, true)
          let (min_leaf, max_leaf) = @treemath.subtree_range(node_idx)
          let seen_uls : Map[UInt32, Bool] = Map([])
          for i = 0; i < parent.unmerged_leaves.length(); i = i + 1 {
            let u = parent.unmerged_leaves[i]
            if u < min_leaf || u > max_leaf || u >= n_leaves {
              raise InvalidUnmergedLeaf
            }
            if seen_uls.contains(u) {
              raise InvalidUnmergedLeaf
            }
            seen_uls.set(u, true)
            let u_node = @treemath.leaf_to_node(u).reinterpret_as_int()
            if !(self.nodes[u_node] is Some(@types.Node::Leaf(_))) {
              raise InvalidUnmergedLeaf
            }
          }
        }
      }
    }
  }
}

///|
fn RatchetTreeState::node_parent_hash(
  self : RatchetTreeState,
  node_idx : UInt32,
) -> Bytes? raise TreeError {
  if node_idx >= self.n_nodes() {
    raise OutOfBounds(node_idx)
  }
  match self.nodes[node_idx.reinterpret_as_int()] {
    None => None
    Some(@types.Node::Parent(parent)) => Some(parent.parent_hash)
    Some(@types.Node::Leaf(leaf)) =>
      match leaf.leaf_node_source {
        @types.LeafNodeSource::Commit => leaf.parent_hash
        _ => None
      }
  }
}

///|
fn RatchetTreeState::count_parent_hash_matches(
  self : RatchetTreeState,
  child_idx : UInt32,
  expected_ph : Bytes,
  unmerged_leaves : Array[UInt32],
) -> Int32 raise TreeError {
  let res = self.resolution(child_idx)
  let mut matches = 0
  for i = 0; i < res.length(); i = i + 1 {
    let r_node = res[i]
    if @treemath.is_leaf(r_node) && contains_uint(unmerged_leaves, r_node >> 1) {
      continue
    }
    match self.node_parent_hash(r_node) {
      Some(ph) => if ph == expected_ph { matches += 1 }
      None => ()
    }
  }
  matches
}

///|
/// Validates RFC 9420 §7.9.2 parent-hash tree coverage: for every non-blank
/// parent node `P`, exactly one node in the resolution of `left(P)` (matching
/// `ParentHash(P, left(P))`) or `right(P)` (matching `ParentHash(P, right(P))`),
/// excluding `P.unmerged_leaves`, must carry the matching `parent_hash`.
pub fn RatchetTreeState::validate_parent_hashes(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
) -> Unit raise TreeError {
  if self.nodes.length() == 0 {
    raise EmptyTree
  }
  let n_nodes = self.n_nodes()
  for node_idx = 1U; node_idx < n_nodes; node_idx = node_idx + 2U {
    match self.get_parent(node_idx) {
      None => ()
      Some(parent) => {
        let l = match @treemath.left(node_idx) {
          Some(v) => v
          None => raise UnexpectedNodeType(node_idx)
        }
        let r = match @treemath.right(node_idx) {
          Some(v) => v
          None => raise UnexpectedNodeType(node_idx)
        }
        let left_ph = self.compute_parent_hash(cs, node_idx, l)
        let right_ph = self.compute_parent_hash(cs, node_idx, r)
        let left_matches = self.count_parent_hash_matches(
          l,
          left_ph,
          parent.unmerged_leaves,
        )
        let right_matches = self.count_parent_hash_matches(
          r,
          right_ph,
          parent.unmerged_leaves,
        )
        if left_matches + right_matches != 1 {
          raise InvalidParentHash
        }
      }
    }
  }
}

///|
/// Verifies a single leaf node's signature per RFC 9420 §7.2 (`"LeafNodeTBS"`).
pub fn verify_leaf_signature(
  cs : @cs.CipherSuite,
  leaf : @types.LeafNode,
  group_id : Bytes,
  leaf_idx : UInt32,
) -> Unit raise TreeError {
  let tbs = try {
    match leaf.leaf_node_source {
      @types.LeafNodeSource::KeyPackage => leaf.encode_tbs(None, None)
      @types.LeafNodeSource::Update | @types.LeafNodeSource::Commit =>
        leaf.encode_tbs(Some(group_id), Some(leaf_idx))
    }
  } catch {
    e => raise TlsError(e)
  }
  if !cs.verify_with_label(
      leaf.signature_key,
      "LeafNodeTBS",
      tbs,
      leaf.signature,
    ) {
    raise InvalidLeafSignature(leaf_idx)
  }
}

///|
/// Validates the Ed25519 signatures on all non-blank leaves in the tree
/// per RFC 9420 §7.2 & §12.4.3.1.
pub fn RatchetTreeState::validate_leaf_signatures(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  group_id : Bytes,
) -> Unit raise TreeError {
  let n_leaves = self.n_leaves()
  for leaf_idx = 0U; leaf_idx < n_leaves; leaf_idx = leaf_idx + 1U {
    match self.get_leaf(leaf_idx) {
      None => ()
      Some(leaf) => verify_leaf_signature(cs, leaf, group_id, leaf_idx)
    }
  }
}
