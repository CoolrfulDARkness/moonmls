///|
/// Mutable state machine for an RFC 9420 §7 Ratchet Tree.
/// Internally always maintains a full power-of-two binary tree width (`2 * 2^k - 1` nodes).
pub struct RatchetTreeState {
  mut nodes : Array[@types.Node?]
}

///|
fn next_power_of_two(n : UInt32) -> UInt32 {
  if n <= 1U {
    return 1U
  }
  if n >= 0x40000000U {
    return 0x40000000U
  }
  let mut p = 1U
  while p < n {
    p = p << 1
  }
  p
}

///|
fn clone_parent(p : @types.ParentNode) -> @types.ParentNode {
  let uls : Array[UInt32] = Array::makei(p.unmerged_leaves.length(), fn(i) {
    p.unmerged_leaves[i]
  })
  {
    encryption_key: p.encryption_key,
    parent_hash: p.parent_hash,
    unmerged_leaves: uls,
  }
}

///|
fn clone_node(node : @types.Node?) -> @types.Node? {
  match node {
    None => None
    Some(@types.Node::Leaf(leaf)) => Some(@types.Node::Leaf(leaf))
    Some(@types.Node::Parent(parent)) =>
      Some(@types.Node::Parent(clone_parent(parent)))
  }
}

///|
fn contains_uint(arr : Array[UInt32], target : UInt32) -> Bool {
  for i = 0; i < arr.length(); i = i + 1 {
    if arr[i] == target {
      return true
    }
  }
  false
}

///|
/// Creates a single-leaf ratchet tree containing `leaf` at leaf index 0.
pub fn RatchetTreeState::new(leaf : @types.LeafNode) -> RatchetTreeState {
  { nodes: [Some(@types.Node::Leaf(leaf))], }
}

///|
/// Constructs a `RatchetTreeState` from a node array (which may have trailing
/// blank nodes trimmed per RFC 9420 §12.4.3.3). Automatically pads to the full
/// power-of-two tree width `node_width(next_power_of_two(leaf_count))`.
pub fn RatchetTreeState::from_nodes(
  nodes : Array[@types.Node?],
) -> RatchetTreeState raise TreeError {
  let len = nodes.length()
  if len == 0 {
    raise EmptyTree
  }
  if len % 2 == 0 {
    raise InvalidTreeSize(len)
  }
  let raw_leaves = @treemath.leaf_count(len.reinterpret_as_uint())
  let full_leaves = next_power_of_two(raw_leaves)
  let full_width = @treemath.node_width(full_leaves).reinterpret_as_int()
  let padded : Array[@types.Node?] = Array::makei(full_width, fn(i) {
    if i < len {
      clone_node(nodes[i])
    } else {
      None
    }
  })
  { nodes: padded, }
}

///|
/// Returns a cloned copy of the full padded node array.
pub fn RatchetTreeState::to_nodes(
  self : RatchetTreeState,
) -> Array[@types.Node?] {
  Array::makei(self.nodes.length(), fn(i) { clone_node(self.nodes[i]) })
}

///|
/// Returns the node array with trailing blank (`None`) nodes stripped
/// per RFC 9420 §12.4.3.3.
pub fn RatchetTreeState::to_trimmed_nodes(
  self : RatchetTreeState,
) -> Array[@types.Node?] {
  let mut end = self.nodes.length()
  while end > 0 && self.nodes[end - 1] is None {
    end -= 1
  }
  Array::makei(end, fn(i) { clone_node(self.nodes[i]) })
}

///|
/// Returns a deep clone of this `RatchetTreeState`.
pub fn RatchetTreeState::clone(self : RatchetTreeState) -> RatchetTreeState {
  { nodes: self.to_nodes(), }
}

///|
/// Returns the number of leaf slots in the full power-of-two ratchet tree.
pub fn RatchetTreeState::n_leaves(self : RatchetTreeState) -> UInt32 {
  @treemath.leaf_count(self.nodes.length().reinterpret_as_uint())
}

///|
/// Returns the number of node slots in the full power-of-two ratchet tree.
pub fn RatchetTreeState::n_nodes(self : RatchetTreeState) -> UInt32 {
  self.nodes.length().reinterpret_as_uint()
}

///|
/// Returns the node at `node_idx`, or raises `OutOfBounds`.
pub fn RatchetTreeState::get_node(
  self : RatchetTreeState,
  node_idx : UInt32,
) -> @types.Node? raise TreeError {
  if node_idx >= self.n_nodes() {
    raise OutOfBounds(node_idx)
  }
  self.nodes[node_idx.reinterpret_as_int()]
}

///|
/// Returns the leaf node at `leaf_idx`, or `None` if blank.
/// Raises `OutOfBounds` if `leaf_idx >= n_leaves` or `UnexpectedNodeType` if a parent node occupies the leaf slot.
pub fn RatchetTreeState::get_leaf(
  self : RatchetTreeState,
  leaf_idx : UInt32,
) -> @types.LeafNode? raise TreeError {
  if leaf_idx >= self.n_leaves() {
    raise OutOfBounds(leaf_idx)
  }
  let node_idx = @treemath.leaf_to_node(leaf_idx)
  match self.nodes[node_idx.reinterpret_as_int()] {
    None => None
    Some(@types.Node::Leaf(leaf)) => Some(leaf)
    Some(@types.Node::Parent(_)) => raise UnexpectedNodeType(node_idx)
  }
}

///|
/// Returns the parent node at `node_idx`, or `None` if blank.
/// Raises `OutOfBounds` if out of range or `UnexpectedNodeType` if `node_idx` is a leaf index or holds a leaf node.
pub fn RatchetTreeState::get_parent(
  self : RatchetTreeState,
  node_idx : UInt32,
) -> @types.ParentNode? raise TreeError {
  if node_idx >= self.n_nodes() {
    raise OutOfBounds(node_idx)
  }
  if @treemath.is_leaf(node_idx) {
    raise UnexpectedNodeType(node_idx)
  }
  match self.nodes[node_idx.reinterpret_as_int()] {
    None => None
    Some(@types.Node::Parent(parent)) => Some(parent)
    Some(@types.Node::Leaf(_)) => raise UnexpectedNodeType(node_idx)
  }
}

///|
/// Finds the first non-blank leaf index whose `signature_key` equals `sig_key`.
pub fn RatchetTreeState::find_leaf_by_sig_key(
  self : RatchetTreeState,
  sig_key : Bytes,
) -> UInt32? {
  let n = self.n_leaves()
  for leaf_idx = 0U; leaf_idx < n; leaf_idx = leaf_idx + 1U {
    let node_idx = @treemath.leaf_to_node(leaf_idx).reinterpret_as_int()
    match self.nodes[node_idx] {
      Some(@types.Node::Leaf(leaf)) =>
        if leaf.signature_key == sig_key {
          return Some(leaf_idx)
        }
      _ => ()
    }
  }
  None
}

///|
/// Returns the ascending list of all non-blank leaf indices in the tree.
pub fn RatchetTreeState::active_leaf_indices(
  self : RatchetTreeState,
) -> Array[UInt32] {
  let out : Array[UInt32] = []
  let n = self.n_leaves()
  for leaf_idx = 0U; leaf_idx < n; leaf_idx = leaf_idx + 1U {
    let node_idx = @treemath.leaf_to_node(leaf_idx).reinterpret_as_int()
    if self.nodes[node_idx] is Some(@types.Node::Leaf(_)) {
      out.push(leaf_idx)
    }
  }
  out
}

///|
/// Computes the resolution of `node_idx` as node indices (RFC 9420 §4.1.2).
/// - Non-blank leaf: `[node_idx]`
/// - Blank leaf: `[]`
/// - Non-blank parent: `[node_idx] + unmerged_leaves.map(leaf_to_node)`
/// - Blank parent: `resolution(left) + resolution(right)`
pub fn RatchetTreeState::resolution(
  self : RatchetTreeState,
  node_idx : UInt32,
) -> Array[UInt32] raise TreeError {
  if node_idx >= self.n_nodes() {
    raise OutOfBounds(node_idx)
  }
  let idx = node_idx.reinterpret_as_int()
  if @treemath.is_leaf(node_idx) {
    match self.nodes[idx] {
      None => []
      Some(@types.Node::Leaf(_)) => [node_idx]
      Some(@types.Node::Parent(_)) => raise UnexpectedNodeType(node_idx)
    }
  } else {
    match self.nodes[idx] {
      Some(@types.Node::Parent(parent)) => {
        let out : Array[UInt32] = Array(
          capacity=1 + parent.unmerged_leaves.length(),
        )
        out.push(node_idx)
        for i = 0; i < parent.unmerged_leaves.length(); i = i + 1 {
          out.push(@treemath.leaf_to_node(parent.unmerged_leaves[i]))
        }
        out
      }
      Some(@types.Node::Leaf(_)) => raise UnexpectedNodeType(node_idx)
      None => {
        let l = match @treemath.left(node_idx) {
          Some(v) => v
          None => raise OutOfBounds(node_idx)
        }
        let r = match @treemath.right(node_idx) {
          Some(v) => v
          None => raise OutOfBounds(node_idx)
        }
        let left_res = self.resolution(l)
        let right_res = self.resolution(r)
        let out : Array[UInt32] = Array(
          capacity=left_res.length() + right_res.length(),
        )
        for i = 0; i < left_res.length(); i = i + 1 {
          out.push(left_res[i])
        }
        for i = 0; i < right_res.length(); i = i + 1 {
          out.push(right_res[i])
        }
        out
      }
    }
  }
}

///|
/// Computes the filtered direct path of `leaf_idx` as `(direct_path_node, copath_node)`
/// pairs (RFC 9420 §4.1.2 / §7.6), retaining only entries whose copath node has a
/// non-empty resolution.
pub fn RatchetTreeState::filtered_direct_path(
  self : RatchetTreeState,
  leaf_idx : UInt32,
) -> Array[(UInt32, UInt32)] raise TreeError {
  let n_leaves = self.n_leaves()
  if leaf_idx >= n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let leaf_node = @treemath.leaf_to_node(leaf_idx)
  let dp = @treemath.direct_path(leaf_node, n_leaves)
  let cp = @treemath.copath(leaf_node, n_leaves)
  let out : Array[(UInt32, UInt32)] = []
  for i = 0; i < dp.length(); i = i + 1 {
    let copath_node = cp[i]
    if self.resolution(copath_node).length() > 0 {
      out.push((dp[i], copath_node))
    }
  }
  out
}

///|
fn RatchetTreeState::node_hash_excluding(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  node_idx : UInt32,
  excluded_leaves : Array[UInt32],
) -> Bytes raise TreeError {
  if node_idx >= self.n_nodes() {
    raise OutOfBounds(node_idx)
  }
  let idx = node_idx.reinterpret_as_int()
  let w = @tls.Writer::new()
  if @treemath.is_leaf(node_idx) {
    let leaf_idx = node_idx >> 1
    let opt_leaf : @types.LeafNode? = if contains_uint(
        excluded_leaves, leaf_idx,
      ) {
      None
    } else {
      match self.nodes[idx] {
        None => None
        Some(@types.Node::Leaf(leaf)) => Some(leaf)
        Some(@types.Node::Parent(_)) => raise UnexpectedNodeType(node_idx)
      }
    }
    w.write_u8(b'\x01')
    w.write_u32(leaf_idx)
    w.write_optional(opt_leaf, (sub, leaf) => leaf.encode(sub)) catch {
      e => raise TlsError(e)
    }
    cs.hash(w.to_bytes())
  } else {
    let opt_parent : @types.ParentNode? = match self.nodes[idx] {
      None => None
      Some(@types.Node::Parent(parent)) =>
        if excluded_leaves.length() == 0 {
          Some(parent)
        } else {
          let filtered_uls : Array[UInt32] = []
          for i = 0; i < parent.unmerged_leaves.length(); i = i + 1 {
            let u = parent.unmerged_leaves[i]
            if !contains_uint(excluded_leaves, u) {
              filtered_uls.push(u)
            }
          }
          Some({
            encryption_key: parent.encryption_key,
            parent_hash: parent.parent_hash,
            unmerged_leaves: filtered_uls,
          })
        }
      Some(@types.Node::Leaf(_)) => raise UnexpectedNodeType(node_idx)
    }
    let l = match @treemath.left(node_idx) {
      Some(v) => v
      None => raise OutOfBounds(node_idx)
    }
    let r = match @treemath.right(node_idx) {
      Some(v) => v
      None => raise OutOfBounds(node_idx)
    }
    let left_hash = self.node_hash_excluding(cs, l, excluded_leaves)
    let right_hash = self.node_hash_excluding(cs, r, excluded_leaves)
    w.write_u8(b'\x02')
    try {
      w.write_optional(opt_parent, (sub, p) => p.encode(sub))
      w.write_opaque(left_hash)
      w.write_opaque(right_hash)
    } catch {
      e => raise TlsError(e)
    }
    cs.hash(w.to_bytes())
  }
}

///|
/// Computes the RFC 9420 §7.8 tree hash of the subtree rooted at `node_idx`.
pub fn RatchetTreeState::node_hash(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  node_idx : UInt32,
) -> Bytes raise TreeError {
  self.node_hash_excluding(cs, node_idx, [])
}

///|
/// Computes the RFC 9420 §7.8 tree hash of the entire ratchet tree (root hash).
pub fn RatchetTreeState::tree_hash(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
) -> Bytes raise TreeError {
  if self.nodes.length() == 0 {
    raise EmptyTree
  }
  self.node_hash(cs, @treemath.root(self.n_leaves()))
}

///|
fn encode_and_hash_parent_hash_input(
  cs : @cs.CipherSuite,
  encryption_key : Bytes,
  parent_hash : Bytes,
  original_sibling_tree_hash : Bytes,
) -> Bytes raise TreeError {
  let w = @tls.Writer::new()
  try {
    w.write_opaque(encryption_key)
    w.write_opaque(parent_hash)
    w.write_opaque(original_sibling_tree_hash)
  } catch {
    e => raise TlsError(e)
  }
  cs.hash(w.to_bytes())
}

///|
/// Computes the RFC 9420 §7.9 parent hash of non-blank parent `parent_idx` with
/// respect to `original_child_idx` (must be either `left(parent_idx)` or
/// `right(parent_idx)`). The sibling subtree's original tree hash is computed
/// excluding `parent.unmerged_leaves`.
pub fn RatchetTreeState::compute_parent_hash(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  parent_idx : UInt32,
  original_child_idx : UInt32,
) -> Bytes raise TreeError {
  let parent = match self.get_parent(parent_idx) {
    Some(p) => p
    None => raise InvalidParentHash
  }
  let l = match @treemath.left(parent_idx) {
    Some(v) => v
    None => raise UnexpectedNodeType(parent_idx)
  }
  let r = match @treemath.right(parent_idx) {
    Some(v) => v
    None => raise UnexpectedNodeType(parent_idx)
  }
  let sibling_idx = if original_child_idx == l {
    r
  } else if original_child_idx == r {
    l
  } else {
    raise InvalidParentHash
  }
  let orig_sibling_hash = self.node_hash_excluding(
    cs,
    sibling_idx,
    parent.unmerged_leaves,
  )
  encode_and_hash_parent_hash_input(
    cs,
    parent.encryption_key,
    parent.parent_hash,
    orig_sibling_hash,
  )
}

///|
fn insert_sorted_unique(arr : Array[UInt32], val : UInt32) -> Array[UInt32] {
  let out : Array[UInt32] = Array(capacity=arr.length() + 1)
  let mut inserted = false
  for i = 0; i < arr.length(); i = i + 1 {
    let cur = arr[i]
    if cur == val {
      inserted = true
      out.push(cur)
    } else if !inserted && val < cur {
      out.push(val)
      out.push(cur)
      inserted = true
    } else {
      out.push(cur)
    }
  }
  if !inserted {
    out.push(val)
  }
  out
}

///|
/// Applies an RFC 9420 §12.1.1 Add operation.
/// Reuses the leftmost blank leaf (updating `unmerged_leaves` on non-blank
/// ancestors), or doubles the tree size and places `leaf` at the old `n_leaves`.
/// Returns the assigned leaf index.
pub fn RatchetTreeState::add_leaf(
  self : RatchetTreeState,
  leaf : @types.LeafNode,
) -> UInt32 raise TreeError {
  if self.nodes.length() == 0 {
    raise EmptyTree
  }
  let old_n_leaves = self.n_leaves()
  let mut blank_slot : UInt32? = None
  for leaf_idx = 0U; leaf_idx < old_n_leaves; leaf_idx = leaf_idx + 1U {
    let node_idx = @treemath.leaf_to_node(leaf_idx).reinterpret_as_int()
    if self.nodes[node_idx] is None {
      blank_slot = Some(leaf_idx)
      break
    }
  }
  match blank_slot {
    Some(leaf_idx) => {
      let leaf_node_idx = @treemath.leaf_to_node(leaf_idx)
      self.nodes[leaf_node_idx.reinterpret_as_int()] = Some(
        @types.Node::Leaf(leaf),
      )
      let dp = @treemath.direct_path(leaf_node_idx, old_n_leaves)
      for i = 0; i < dp.length(); i = i + 1 {
        let p_idx = dp[i].reinterpret_as_int()
        match self.nodes[p_idx] {
          Some(@types.Node::Parent(parent)) => {
            let new_uls = insert_sorted_unique(parent.unmerged_leaves, leaf_idx)
            self.nodes[p_idx] = Some(
              @types.Node::Parent({
                encryption_key: parent.encryption_key,
                parent_hash: parent.parent_hash,
                unmerged_leaves: new_uls,
              }),
            )
          }
          Some(@types.Node::Leaf(_)) => raise UnexpectedNodeType(dp[i])
          None => ()
        }
      }
      leaf_idx
    }
    None => {
      if old_n_leaves >= 0x40000000U {
        raise InvalidTreeSize(self.nodes.length())
      }
      let new_n_leaves = old_n_leaves << 1
      let new_width = @treemath.node_width(new_n_leaves).reinterpret_as_int()
      while self.nodes.length() < new_width {
        self.nodes.push(None)
      }
      let new_leaf_idx = old_n_leaves
      let new_node_idx = @treemath.leaf_to_node(new_leaf_idx).reinterpret_as_int()
      self.nodes[new_node_idx] = Some(@types.Node::Leaf(leaf))
      new_leaf_idx
    }
  }
}

///|
/// Applies an RFC 9420 §12.1.2 Update operation: replaces `leaf_idx` and blanks
/// all intermediate nodes on its direct path.
pub fn RatchetTreeState::update_leaf(
  self : RatchetTreeState,
  leaf_idx : UInt32,
  leaf : @types.LeafNode,
) -> Unit raise TreeError {
  let n_leaves = self.n_leaves()
  if leaf_idx >= n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let leaf_node_idx = @treemath.leaf_to_node(leaf_idx)
  if self.nodes[leaf_node_idx.reinterpret_as_int()] is None {
    raise BlankLeaf(leaf_idx)
  }
  self.nodes[leaf_node_idx.reinterpret_as_int()] = Some(@types.Node::Leaf(leaf))
  let dp = @treemath.direct_path(leaf_node_idx, n_leaves)
  for i = 0; i < dp.length(); i = i + 1 {
    self.nodes[dp[i].reinterpret_as_int()] = None
  }
}

///|
fn RatchetTreeState::right_subtree_is_blank(self : RatchetTreeState) -> Bool {
  let n_leaves = self.n_leaves()
  if n_leaves <= 1U {
    return false
  }
  let root_idx = @treemath.root(n_leaves).reinterpret_as_int()
  for i = root_idx + 1; i < self.nodes.length(); i = i + 1 {
    if self.nodes[i] is Some(_) {
      return false
    }
  }
  true
}

///|
/// Applies an RFC 9420 §12.1.3 Remove operation: blanks `leaf_idx` and all nodes
/// on its direct path, then repeatedly halves the tree while the right subtree
/// is completely blank and the tree has at least 2 leaves.
pub fn RatchetTreeState::remove_leaf(
  self : RatchetTreeState,
  leaf_idx : UInt32,
) -> Unit raise TreeError {
  let n_leaves = self.n_leaves()
  if leaf_idx >= n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let leaf_node_idx = @treemath.leaf_to_node(leaf_idx)
  if self.nodes[leaf_node_idx.reinterpret_as_int()] is None {
    raise BlankLeaf(leaf_idx)
  }
  self.nodes[leaf_node_idx.reinterpret_as_int()] = None
  let dp = @treemath.direct_path(leaf_node_idx, n_leaves)
  for i = 0; i < dp.length(); i = i + 1 {
    self.nodes[dp[i].reinterpret_as_int()] = None
  }
  while self.n_leaves() > 1U && self.right_subtree_is_blank() {
    let half_leaves = self.n_leaves() >> 1
    let new_width = @treemath.node_width(half_leaves).reinterpret_as_int()
    let shrunk : Array[@types.Node?] = Array::makei(new_width, fn(i) {
      self.nodes[i]
    })
    self.nodes = shrunk
  }
}

///|
/// Applies a tree-modifying `Proposal` (`Add`, `Update`, or `Remove`) to this
/// ratchet tree. Returns `Some(added_leaf_idx)` for `Add`, or `None` otherwise.
pub fn RatchetTreeState::apply_proposal(
  self : RatchetTreeState,
  sender_leaf : UInt32,
  proposal : @types.Proposal,
) -> UInt32? raise TreeError {
  match proposal {
    @types.Proposal::Add(kp) => Some(self.add_leaf(kp.leaf_node))
    @types.Proposal::Update(leaf) => {
      self.update_leaf(sender_leaf, leaf)
      None
    }
    @types.Proposal::Remove(removed) => {
      self.remove_leaf(removed)
      None
    }
    _ => None
  }
}
