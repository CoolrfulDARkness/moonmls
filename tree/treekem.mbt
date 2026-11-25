///|
/// Output of `prepare_update_path_tree`: contains the newly signed commit leaf,
/// derived leaf and path node key pairs, path secrets, commit secret, and the
/// updated tree hash.
#derive(Eq, Debug)
pub(all) struct PreparedUpdatePath {
  leaf_node : @types.LeafNode
  leaf_enc_priv : Bytes
  path_node_keys : Array[(UInt32, Bytes, Bytes)]
  path_secrets : Array[(UInt32, Bytes)]
  commit_secret : Bytes
  tree_hash : Bytes
}

///|
fn RatchetTreeState::filtered_resolution(
  self : RatchetTreeState,
  node_idx : UInt32,
  exclude_leaves : Array[UInt32],
) -> Array[UInt32] raise TreeError {
  let raw = self.resolution(node_idx)
  if exclude_leaves.length() == 0 {
    return raw
  }
  let out : Array[UInt32] = []
  for i = 0; i < raw.length(); i = i + 1 {
    let n = raw[i]
    if @treemath.is_leaf(n) && contains_uint(exclude_leaves, n >> 1) {
      continue
    }
    out.push(n)
  }
  out
}

///|
fn RatchetTreeState::node_encryption_key(
  self : RatchetTreeState,
  node_idx : UInt32,
) -> Bytes raise TreeError {
  match self.get_node(node_idx) {
    Some(@types.Node::Leaf(leaf)) => leaf.encryption_key
    Some(@types.Node::Parent(parent)) => parent.encryption_key
    None => raise PathMismatch
  }
}

///|
/// Merges an incoming `UpdatePath` from `sender_leaf` into the ratchet tree
/// (RFC 9420 §7.6, §7.9, §12.4.2):
/// - Verifies `update_path.nodes.length()` matches `filtered_direct_path(sender_leaf)`
///   and each `encrypted_path_secret.length()` matches the copath resolution
///   excluding `exclude_leaves`.
/// - Blanks the sender's full direct path, populates the filtered direct path
///   parent nodes from root downward while computing each `parent_hash`, and
///   verifies `update_path.leaf_node` has `Commit` source, matching `parent_hash`,
///   and a valid signature.
/// - Atomic: leaves `self` unchanged if any check fails.
pub fn RatchetTreeState::merge_update_path_nodes(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  sender_leaf : UInt32,
  update_path : @types.UpdatePath,
  group_id : Bytes,
  exclude_leaves : Array[UInt32],
) -> Unit raise TreeError {
  let n_leaves = self.n_leaves()
  if sender_leaf >= n_leaves {
    raise OutOfBounds(sender_leaf)
  }
  let work = self.clone()
  let fdp = work.filtered_direct_path(sender_leaf)
  if update_path.nodes.length() != fdp.length() {
    raise PathMismatch
  }
  for i = 0; i < fdp.length(); i = i + 1 {
    let (_d_node, c_node) = fdp[i]
    let expected_res = work.filtered_resolution(c_node, exclude_leaves)
    if update_path.nodes[i].encrypted_path_secret.length() !=
      expected_res.length() {
      raise PathMismatch
    }
  }
  // Blank full direct path of sender
  let leaf_node_idx = @treemath.leaf_to_node(sender_leaf)
  let dp = @treemath.direct_path(leaf_node_idx, n_leaves)
  for i = 0; i < dp.length(); i = i + 1 {
    work.nodes[dp[i].reinterpret_as_int()] = None
  }
  // Fill filtered direct path from top (root-most) to bottom (leaf-most)
  let k = fdp.length()
  let mut cur_ph = b""
  for rev = 0; rev < k; rev = rev + 1 {
    let i = k - 1 - rev
    let (d_node, c_node) = fdp[i]
    let enc_key = update_path.nodes[i].encryption_key
    work.nodes[d_node.reinterpret_as_int()] = Some(
      @types.Node::Parent({
        encryption_key: enc_key,
        parent_hash: cur_ph,
        unmerged_leaves: [],
      }),
    )
    let sibling_hash = work.node_hash(cs, c_node)
    cur_ph = encode_and_hash_parent_hash_input(
      cs, enc_key, cur_ph, sibling_hash,
    )
  }
  // Verify leaf_node source, parent_hash, and signature
  let leaf = update_path.leaf_node
  match leaf.leaf_node_source {
    @types.LeafNodeSource::Commit =>
      match leaf.parent_hash {
        Some(ph) => if ph != cur_ph { raise InvalidParentHash }
        None => raise InvalidParentHash
      }
    _ => raise InvalidParentHash
  }
  verify_leaf_signature(cs, leaf, group_id, sender_leaf)
  work.nodes[leaf_node_idx.reinterpret_as_int()] = Some(@types.Node::Leaf(leaf))
  self.nodes = work.nodes
}

///|
/// Step 1 of RFC 9420 §12.4.1 UpdatePath creation:
/// Derives the sender's new leaf encryption key pair and all filtered direct path
/// node key pairs and path secrets from `leaf_secret`, updates the ratchet tree
/// with parent hashes, signs the new `Commit` `LeafNode`, and computes the
/// resulting `tree_hash`.
/// Atomic: leaves `self` unchanged on error.
pub fn RatchetTreeState::prepare_update_path_tree(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  sender_leaf : UInt32,
  new_leaf_base : @types.LeafNode,
  sign_priv : Bytes,
  group_id : Bytes,
  leaf_secret : Bytes,
) -> PreparedUpdatePath raise TreeError {
  let n_leaves = self.n_leaves()
  if sender_leaf >= n_leaves {
    raise OutOfBounds(sender_leaf)
  }
  let work = self.clone()
  let fdp = work.filtered_direct_path(sender_leaf)
  let k = fdp.length()
  // Derive leaf keypair from leaf_secret
  let leaf_node_secret = cs.derive_secret(leaf_secret, "node") catch {
    e => raise CsError(e)
  }
  let (leaf_enc_priv, leaf_enc_pub) = cs.kem_keypair_from_ikm(leaf_node_secret) catch {
    e => raise CsError(e)
  }
  let mut cur_path_secret = cs.derive_secret(leaf_secret, "path") catch {
    e => raise CsError(e)
  }
  let path_node_keys : Array[(UInt32, Bytes, Bytes)] = Array(capacity=k)
  let path_secrets : Array[(UInt32, Bytes)] = Array(capacity=k)
  for i = 0; i < k; i = i + 1 {
    let (d_node, _c_node) = fdp[i]
    let node_secret = cs.derive_secret(cur_path_secret, "node") catch {
      e => raise CsError(e)
    }
    let (sk, pk) = cs.kem_keypair_from_ikm(node_secret) catch {
      e => raise CsError(e)
    }
    path_node_keys.push((d_node, sk, pk))
    path_secrets.push((d_node, cur_path_secret))
    cur_path_secret = cs.derive_secret(cur_path_secret, "path") catch {
      e => raise CsError(e)
    }
  }
  let commit_secret = cur_path_secret
  // Blank full direct path
  let leaf_node_idx = @treemath.leaf_to_node(sender_leaf)
  let dp = @treemath.direct_path(leaf_node_idx, n_leaves)
  for i = 0; i < dp.length(); i = i + 1 {
    work.nodes[dp[i].reinterpret_as_int()] = None
  }
  // Populate filtered direct path top-down with parent_hash
  let mut cur_ph = b""
  for rev = 0; rev < k; rev = rev + 1 {
    let i = k - 1 - rev
    let (d_node, c_node) = fdp[i]
    let (_, _, pk) = path_node_keys[i]
    work.nodes[d_node.reinterpret_as_int()] = Some(
      @types.Node::Parent({
        encryption_key: pk,
        parent_hash: cur_ph,
        unmerged_leaves: [],
      }),
    )
    let sibling_hash = work.node_hash(cs, c_node)
    cur_ph = encode_and_hash_parent_hash_input(cs, pk, cur_ph, sibling_hash)
  }
  // Construct and sign Commit LeafNode
  let unsigned_leaf : @types.LeafNode = {
    encryption_key: leaf_enc_pub,
    signature_key: new_leaf_base.signature_key,
    credential: new_leaf_base.credential,
    capabilities: new_leaf_base.capabilities,
    leaf_node_source: @types.LeafNodeSource::Commit,
    lifetime: None,
    parent_hash: Some(cur_ph),
    extensions: new_leaf_base.extensions,
    signature: b"",
  }
  let tbs = unsigned_leaf.encode_tbs(Some(group_id), Some(sender_leaf)) catch {
    e => raise TlsError(e)
  }
  let sig = cs.sign_with_label(sign_priv, "LeafNodeTBS", tbs) catch {
    e => raise CsError(e)
  }
  let signed_leaf : @types.LeafNode = {
    encryption_key: unsigned_leaf.encryption_key,
    signature_key: unsigned_leaf.signature_key,
    credential: unsigned_leaf.credential,
    capabilities: unsigned_leaf.capabilities,
    leaf_node_source: unsigned_leaf.leaf_node_source,
    lifetime: unsigned_leaf.lifetime,
    parent_hash: unsigned_leaf.parent_hash,
    extensions: unsigned_leaf.extensions,
    signature: sig,
  }
  work.nodes[leaf_node_idx.reinterpret_as_int()] = Some(
    @types.Node::Leaf(signed_leaf),
  )
  let new_tree_hash = work.tree_hash(cs)
  self.nodes = work.nodes
  {
    leaf_node: signed_leaf,
    leaf_enc_priv,
    path_node_keys,
    path_secrets,
    commit_secret,
    tree_hash: new_tree_hash,
  }
}

///|
/// Step 2 of RFC 9420 §12.4.1 UpdatePath creation:
/// Encrypts each `path_secret` in `prepared` to the copath resolution nodes
/// (excluding `exclude_leaves`) using `EncryptWithLabel("UpdatePathNode", group_context_bytes, path_secret)`.
/// `group_context_bytes` MUST be the serialized provisional `GroupContext`
/// containing the updated `tree_hash`.
pub fn RatchetTreeState::encrypt_path_secrets(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  sender_leaf : UInt32,
  prepared : PreparedUpdatePath,
  group_context_bytes : Bytes,
  exclude_leaves : Array[UInt32],
  rng : @crypto.DeterministicRng,
) -> @types.UpdatePath raise TreeError {
  let fdp = self.filtered_direct_path(sender_leaf)
  if prepared.path_node_keys.length() != fdp.length() ||
    prepared.path_secrets.length() != fdp.length() {
    raise PathMismatch
  }
  let path_nodes : Array[@types.UpdatePathNode] = Array(capacity=fdp.length())
  for i = 0; i < fdp.length(); i = i + 1 {
    let (d_node, c_node) = fdp[i]
    let (key_node, _sk, pk) = prepared.path_node_keys[i]
    let (sec_node, path_secret) = prepared.path_secrets[i]
    if key_node != d_node || sec_node != d_node {
      raise PathMismatch
    }
    let recipients = self.filtered_resolution(c_node, exclude_leaves)
    let ciphertexts : Array[@types.HpkeCiphertext] = Array(
      capacity=recipients.length(),
    )
    for j = 0; j < recipients.length(); j = j + 1 {
      let r_pk = self.node_encryption_key(recipients[j])
      let (kem_output, ciphertext) = cs.encrypt_with_label(
        r_pk, "UpdatePathNode", group_context_bytes, path_secret, rng,
      ) catch {
        e => raise CsError(e)
      }
      ciphertexts.push({ kem_output, ciphertext, })
    }
    path_nodes.push({ encryption_key: pk, encrypted_path_secret: ciphertexts, })
  }
  { leaf_node: prepared.leaf_node, nodes: path_nodes, }
}

///|
/// Derives all node private keys `(node_idx, sk)` and the `commit_secret` along
/// `filtered_direct_path(sender_leaf)` starting from `start_node` with
/// `start_path_secret` (RFC 9420 §7.5 / §12.4.2 / §12.4.3.1).
/// Verifies every derived public key against the corresponding parent node in
/// the tree, raising `PathMismatch` on mismatch.
pub fn RatchetTreeState::derive_path_secrets_from(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  sender_leaf : UInt32,
  start_node : UInt32,
  start_path_secret : Bytes,
) -> (Array[(UInt32, Bytes)], Bytes) raise TreeError {
  let fdp = self.filtered_direct_path(sender_leaf)
  let mut start_idx = -1
  for i = 0; i < fdp.length(); i = i + 1 {
    if fdp[i].0 == start_node {
      start_idx = i
      break
    }
  }
  if start_idx < 0 {
    raise NoCommonAncestor
  }
  let derived_keys : Array[(UInt32, Bytes)] = []
  let mut cur_secret = start_path_secret
  for i = start_idx; i < fdp.length(); i = i + 1 {
    let d_node = fdp[i].0
    let node_secret = cs.derive_secret(cur_secret, "node") catch {
      e => raise CsError(e)
    }
    let (sk, pk) = cs.kem_keypair_from_ikm(node_secret) catch {
      e => raise CsError(e)
    }
    let expected_pk = self.node_encryption_key(d_node)
    if pk != expected_pk {
      raise PathMismatch
    }
    derived_keys.push((d_node, sk))
    cur_secret = cs.derive_secret(cur_secret, "path") catch {
      e => raise CsError(e)
    }
  }
  (derived_keys, cur_secret)
}

///|
/// Decrypts an incoming `UpdatePath` from `sender_leaf` for receiver `my_leaf`
/// (RFC 9420 §12.4.2), using `get_priv_key` to look up the receiver's private
/// encryption key for its resolution node in the copath.
/// Returns `(derived_node_priv_keys, commit_secret)`.
pub fn RatchetTreeState::decrypt_update_path(
  self : RatchetTreeState,
  cs : @cs.CipherSuite,
  sender_leaf : UInt32,
  my_leaf : UInt32,
  update_path : @types.UpdatePath,
  group_context_bytes : Bytes,
  exclude_leaves : Array[UInt32],
  get_priv_key : (UInt32) -> Bytes?,
) -> (Array[(UInt32, Bytes)], Bytes) raise TreeError {
  let n_leaves = self.n_leaves()
  if sender_leaf >= n_leaves {
    raise OutOfBounds(sender_leaf)
  }
  if my_leaf >= n_leaves {
    raise OutOfBounds(my_leaf)
  }
  if sender_leaf == my_leaf {
    raise NoCommonAncestor
  }
  let sender_node = @treemath.leaf_to_node(sender_leaf)
  let my_node = @treemath.leaf_to_node(my_leaf)
  let lca = @treemath.common_ancestor(sender_node, my_node)
  let fdp = self.filtered_direct_path(sender_leaf)
  if update_path.nodes.length() != fdp.length() {
    raise PathMismatch
  }
  let mut lca_idx = -1
  for i = 0; i < fdp.length(); i = i + 1 {
    if fdp[i].0 == lca {
      lca_idx = i
      break
    }
  }
  if lca_idx < 0 {
    raise NoCommonAncestor
  }
  let (_, c_node) = fdp[lca_idx]
  let recipients = self.filtered_resolution(c_node, exclude_leaves)
  let path_node = update_path.nodes[lca_idx]
  if path_node.encrypted_path_secret.length() != recipients.length() {
    raise PathMismatch
  }
  // Match lowest node on receiver's inclusive direct path present in recipients.
  // Checking bottom-up ensures an unmerged leaf picks its own leaf node rather
  // than an ancestor parent whose unmerged_leaves contains it.
  let my_dp = @treemath.direct_path(my_node, n_leaves)
  let my_inclusive_path : Array[UInt32] = Array(capacity=1 + my_dp.length())
  my_inclusive_path.push(my_node)
  for i = 0; i < my_dp.length(); i = i + 1 {
    my_inclusive_path.push(my_dp[i])
  }
  let mut target_pos = -1
  let mut target_node = 0U
  for p_i = 0; p_i < my_inclusive_path.length(); p_i = p_i + 1 {
    let candidate = my_inclusive_path[p_i]
    for r_i = 0; r_i < recipients.length(); r_i = r_i + 1 {
      if recipients[r_i] == candidate {
        target_pos = r_i
        target_node = candidate
        break
      }
    }
    if target_pos >= 0 {
      break
    }
  }
  if target_pos < 0 {
    raise NoCommonAncestor
  }
  let priv_key = match get_priv_key(target_node) {
    Some(sk) => sk
    None => raise PathMismatch
  }
  let ct = path_node.encrypted_path_secret[target_pos]
  let path_secret = cs.decrypt_with_label(
    priv_key,
    "UpdatePathNode",
    group_context_bytes,
    ct.kem_output,
    ct.ciphertext,
  ) catch {
    e => raise CsError(e)
  }
  self.derive_path_secrets_from(cs, sender_leaf, lca, path_secret)
}
