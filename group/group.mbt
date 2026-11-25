///|
/// Output of committing proposals and advancing the group to the next epoch.
#derive(Eq, Debug)
pub(all) struct CommitOutput {
  commit_msg : @types.PrivateMessage
  welcome : @types.Welcome?
  new_epoch : UInt64
}

///|
/// Result of processing an incoming `PrivateMessage`.
#derive(Eq, Debug)
pub(all) enum ProcessedMessage {
  Application(UInt32, Bytes, Bytes)
  Proposal(UInt32, @types.Proposal)
  Commit(UInt32, UInt64)
}

///|
priv struct PendingProposal {
  proposal_ref : Bytes
  sender_leaf : UInt32
  proposal : @types.Proposal
}

///|
/// Active-epoch secrets retained in memory after `SecretTree` initialization.
/// One-shot root secrets (`encryption_secret`, `epoch_secret`, `joiner_secret`,
/// `welcome_secret`, `external_secret`) are intentionally discarded for
/// intra-epoch forward secrecy.
priv struct ActiveEpochSecrets {
  sender_data_secret : Bytes
  exporter_secret : Bytes
  epoch_authenticator : Bytes
  init_secret : Bytes
}

///|
fn ActiveEpochSecrets::from_epoch_secrets(
  s : @schedule.EpochSecrets,
) -> ActiveEpochSecrets {
  {
    sender_data_secret: s.sender_data_secret,
    exporter_secret: s.exporter_secret,
    epoch_authenticator: s.epoch_authenticator,
    init_secret: s.init_secret,
  }
}

///|
/// Full Sans-I/O RFC 9420 MLS Group state machine.
pub struct MlsGroup {
  priv cs : @cs.CipherSuite
  priv mut group_context : @types.GroupContext
  priv mut interim_transcript_hash : Bytes
  priv mut tree : @tree.RatchetTreeState
  priv mut secrets : ActiveEpochSecrets
  priv mut secret_tree : @tree.SecretTree
  priv my_leaf : UInt32
  priv signature_priv : Bytes
  priv mut node_priv_keys : Map[UInt32, Bytes]
  priv mut pending_proposals : Array[PendingProposal]
  priv mut pending_update_privs : Map[Bytes, Bytes]
  priv mut active : Bool
}

///|
const MAX_EPOCH : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
fn clone_u32_bytes_map(src : Map[UInt32, Bytes]) -> Map[UInt32, Bytes] {
  let dst : Map[UInt32, Bytes] = Map([])
  src.each(fn(k, v) { dst.set(k, v) })
  dst
}

///|
fn credential_identity_bytes(cred : @types.Credential) -> Bytes {
  match cred {
    @types.Credential::Basic(id) => id
    @types.Credential::X509(certs) =>
      if certs.length() > 0 {
        certs[0]
      } else {
        b""
      }
  }
}

///|
fn extract_ratchet_tree_extension(
  extensions : Array[@types.Extension],
) -> @types.RatchetTree? raise GroupError {
  for i = 0; i < extensions.length(); i = i + 1 {
    if extensions[i].extension_type == @types.EXT_RATCHET_TREE {
      let nodes = @types.ratchet_tree_from_bytes(extensions[i].extension_data) catch {
        e => raise TlsError(e)
      }
      return Some(nodes)
    }
  }
  None
}

///|
fn find_my_leaf(
  tree : @tree.RatchetTreeState,
  target_leaf : @types.LeafNode,
) -> UInt32? {
  let n = tree.n_leaves()
  for leaf_idx = 0U; leaf_idx < n; leaf_idx = leaf_idx + 1U {
    let opt = tree.get_leaf(leaf_idx) catch { _ => None }
    match opt {
      Some(leaf) => if leaf == target_leaf { return Some(leaf_idx) }
      None => ()
    }
  }
  None
}

///|
fn lookup_path_secret(
  path_secrets : Array[(UInt32, Bytes)],
  node_idx : UInt32,
) -> Bytes? {
  for i = 0; i < path_secrets.length(); i = i + 1 {
    if path_secrets[i].0 == node_idx {
      return Some(path_secrets[i].1)
    }
  }
  None
}

///|
fn prune_stale_priv_keys(
  tree : @tree.RatchetTreeState,
  keys : Map[UInt32, Bytes],
) -> Unit {
  let to_remove : Array[UInt32] = []
  let n_nodes = tree.n_nodes()
  keys.each(fn(node_idx, _sk) {
    if node_idx >= n_nodes {
      to_remove.push(node_idx)
    } else {
      let opt = tree.get_node(node_idx) catch { _ => None }
      if opt is None {
        to_remove.push(node_idx)
      }
    }
  })
  for i = 0; i < to_remove.length(); i = i + 1 {
    keys.remove(to_remove[i])
  }
}

///|
/// Creates a new single-member MLS group at epoch 0 using a freshly generated
/// `KeyPackageBundle` for `identity`.
pub fn MlsGroup::create(
  cs : @cs.CipherSuite,
  group_id : Bytes,
  identity : Bytes,
  rng : @crypto.DeterministicRng,
) -> MlsGroup raise GroupError {
  let bundle = KeyPackageBundle::generate(cs, identity, rng)
  MlsGroup::create_from_bundle(cs, group_id, bundle, rng)
}

///|
/// Creates a new single-member MLS group at epoch 0 from an existing
/// `KeyPackageBundle` (RFC 9420 §11).
pub fn MlsGroup::create_from_bundle(
  cs : @cs.CipherSuite,
  group_id : Bytes,
  bundle : KeyPackageBundle,
  rng : @crypto.DeterministicRng,
) -> MlsGroup raise GroupError {
  verify_key_package(cs, bundle.key_package)
  let tree = @tree.RatchetTreeState::new(bundle.key_package.leaf_node)
  let tree_hash = tree.tree_hash(cs) catch { e => raise TreeError(e) }
  let group_context : @types.GroupContext = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    group_id,
    epoch: 0UL,
    tree_hash,
    confirmed_transcript_hash: b"",
    extensions: [],
  }
  let gc_bytes = group_context.to_bytes() catch { e => raise TlsError(e) }
  let init_joiner = rng.next_bytes(cs.secret_len())
  let secrets = @schedule.derive_epoch_secrets_from_joiner(
    cs,
    init_joiner,
    cs.zero_secret(),
    gc_bytes,
  ) catch {
    e => raise ScheduleError(e)
  }
  let secret_tree = @tree.SecretTree::new(
    cs,
    secrets.encryption_secret,
    tree.n_leaves(),
  )
  let active_secrets = ActiveEpochSecrets::from_epoch_secrets(secrets)
  let node_priv_keys : Map[UInt32, Bytes] = Map([])
  node_priv_keys.set(@treemath.leaf_to_node(0U), bundle.encryption_priv)
  {
    cs,
    group_context,
    interim_transcript_hash: b"",
    tree,
    secrets: active_secrets,
    secret_tree,
    my_leaf: 0U,
    signature_priv: bundle.signature_priv,
    node_priv_keys,
    pending_proposals: [],
    pending_update_privs: Map([]),
    active: true,
  }
}

///|
/// Joins an existing MLS group from a `Welcome` message (RFC 9420 §12.4.3.1),
/// validating the ratchet tree, parent hashes, leaf signatures, `GroupInfo`
/// signature, `tree_hash`, and `confirmation_tag`, and recovering all private
/// keys along the joiner's path.
pub fn MlsGroup::from_welcome(
  cs : @cs.CipherSuite,
  welcome : @types.Welcome,
  bundle : KeyPackageBundle,
  external_tree : @types.RatchetTree?,
) -> MlsGroup raise GroupError {
  let (group_secrets, group_info, psk_secret) = decrypt_welcome_payload(
    cs,
    welcome,
    bundle.init_priv,
    bundle.key_package,
  )
  if group_info.group_context.epoch == MAX_EPOCH {
    raise InvalidCommit("epoch overflow: cannot join group at maximum epoch")
  }
  if has_duplicate_extension_types(group_info.extensions) {
    raise InvalidCommit("duplicate extension_type in GroupInfo")
  }
  let tree_nodes = match extract_ratchet_tree_extension(group_info.extensions) {
    Some(nodes) => nodes
    None =>
      match external_tree {
        Some(nodes) => nodes
        None => raise MissingRatchetTree
      }
  }
  if tree_nodes.length() > 0 && tree_nodes[tree_nodes.length() - 1] is None {
    raise InvalidCommit(
      "ratchet_tree must not contain trailing blank nodes (RFC 9420 §12.4.3.3)",
    )
  }
  let tree = @tree.RatchetTreeState::from_nodes(tree_nodes) catch {
    e => raise TreeError(e)
  }
  tree.validate_tree_structure() catch {
    e => raise TreeError(e)
  }
  tree.validate_parent_hashes(cs) catch {
    e => raise TreeError(e)
  }
  tree.validate_leaf_signatures(cs, group_info.group_context.group_id) catch {
    e => raise TreeError(e)
  }
  let computed_tree_hash = tree.tree_hash(cs) catch { e => raise TreeError(e) }
  if computed_tree_hash != group_info.group_context.tree_hash {
    raise TreeHashMismatch
  }
  let signer_leaf_opt = tree.get_leaf(group_info.signer) catch {
    _ => raise UnknownSender(group_info.signer)
  }
  let signer_leaf = match signer_leaf_opt {
    Some(l) => l
    None => raise UnknownSender(group_info.signer)
  }
  let gi_tbs = group_info.encode_tbs() catch { e => raise TlsError(e) }
  if !cs.verify_with_label(
      signer_leaf.signature_key,
      "GroupInfoTBS",
      gi_tbs,
      group_info.signature,
    ) {
    raise InvalidGroupInfoSignature
  }
  let gc_bytes = group_info.group_context.to_bytes() catch {
    e => raise TlsError(e)
  }
  let secrets = @schedule.derive_epoch_secrets_from_joiner(
    cs,
    group_secrets.joiner_secret,
    psk_secret,
    gc_bytes,
  ) catch {
    e => raise ScheduleError(e)
  }
  if !@schedule.verify_confirmation_tag(
      cs,
      secrets.confirmation_key,
      group_info.group_context.confirmed_transcript_hash,
      group_info.confirmation_tag,
    ) {
    raise ConfirmationTagMismatch
  }
  let my_leaf = match find_my_leaf(tree, bundle.key_package.leaf_node) {
    Some(idx) => idx
    None =>
      raise InvalidKeyPackage("joiner leaf node not found in ratchet tree")
  }
  let node_priv_keys : Map[UInt32, Bytes] = Map([])
  node_priv_keys.set(@treemath.leaf_to_node(my_leaf), bundle.encryption_priv)
  match group_secrets.path_secret {
    Some(ps) => {
      if group_info.signer == my_leaf {
        raise InvalidCommit("Welcome signer cannot be the joiner")
      }
      let lca = @treemath.common_ancestor(
        @treemath.leaf_to_node(group_info.signer),
        @treemath.leaf_to_node(my_leaf),
      )
      let (derived_keys, _commit_secret) = tree.derive_path_secrets_from(
        cs,
        group_info.signer,
        lca,
        ps,
      ) catch {
        e => raise TreeError(e)
      }
      for i = 0; i < derived_keys.length(); i = i + 1 {
        let (node_idx, sk) = derived_keys[i]
        node_priv_keys.set(node_idx, sk)
      }
    }
    None => {
      // RFC 9420 §12.4.3.1: when path_secret is absent, my_leaf must appear in
      // unmerged_leaves of every non-blank parent on direct_path(my_leaf).
      let dp = @treemath.direct_path(
        @treemath.leaf_to_node(my_leaf),
        tree.n_leaves(),
      )
      for i = 0; i < dp.length(); i = i + 1 {
        let p_opt = tree.get_parent(dp[i]) catch { e => raise TreeError(e) }
        match p_opt {
          Some(parent) =>
            if !contains_u32(parent.unmerged_leaves, my_leaf) {
              raise TreeError(@tree.TreeError::InvalidUnmergedLeaf)
            }
          None => ()
        }
      }
    }
  }
  let interim_transcript_hash = @schedule.compute_interim_transcript_hash(
    cs,
    group_info.group_context.confirmed_transcript_hash,
    group_info.confirmation_tag,
  ) catch {
    e => raise ScheduleError(e)
  }
  let secret_tree = @tree.SecretTree::new(
    cs,
    secrets.encryption_secret,
    tree.n_leaves(),
  )
  let active_secrets = ActiveEpochSecrets::from_epoch_secrets(secrets)
  {
    cs,
    group_context: group_info.group_context,
    interim_transcript_hash,
    tree,
    secrets: active_secrets,
    secret_tree,
    my_leaf,
    signature_priv: bundle.signature_priv,
    node_priv_keys,
    pending_proposals: [],
    pending_update_privs: Map([]),
    active: true,
  }
}

///|
fn MlsGroup::ensure_active(self : MlsGroup) -> Unit raise GroupError {
  if !self.active {
    raise MemberRemoved
  }
}

///|
fn MlsGroup::validate_update_leaf(
  self : MlsGroup,
  sender_leaf : UInt32,
  leaf : @types.LeafNode,
) -> Unit raise GroupError {
  match leaf.leaf_node_source {
    @types.LeafNodeSource::Update => ()
    _ => raise InvalidProposal("Update leaf_node_source must be Update")
  }
  if leaf.lifetime is Some(_) {
    raise InvalidProposal("Update leaf_node must not have lifetime")
  }
  if leaf.parent_hash is Some(_) {
    raise InvalidProposal("Update leaf_node must not have parent_hash")
  }
  @tree.validate_x25519_public_key(leaf.encryption_key) catch {
    _ => raise InvalidProposal("invalid or low-order Update encryption_key")
  }
  if leaf.signature_key.length() != 32 {
    raise InvalidProposal("invalid Update signature_key length")
  }
  if !contains_u32(leaf.capabilities.versions, @types.PROTOCOL_VERSION_MLS10) ||
    !contains_u32(leaf.capabilities.cipher_suites, self.cs.id()) ||
    !contains_u32(
      leaf.capabilities.credentials,
      leaf.credential.credential_type(),
    ) {
    raise InvalidProposal("Update leaf_node capabilities incompatible")
  }
  if has_duplicate_extension_types(leaf.extensions) {
    raise InvalidProposal("Update leaf_node has duplicate extension_type")
  }
  let cur_opt = self.tree.get_leaf(sender_leaf) catch {
    _ => raise UnknownSender(sender_leaf)
  }
  let cur_leaf = match cur_opt {
    Some(l) => l
    None => raise UnknownSender(sender_leaf)
  }
  if leaf.encryption_key == cur_leaf.encryption_key {
    raise InvalidProposal("Update leaf_node must rotate encryption_key")
  }
  @tree.verify_leaf_signature(
    self.cs,
    leaf,
    self.group_context.group_id,
    sender_leaf,
  ) catch {
    e => raise TreeError(e)
  }
}

///|
fn MlsGroup::validate_incoming_proposal(
  self : MlsGroup,
  sender_leaf : UInt32,
  proposal : @types.Proposal,
) -> Unit raise GroupError {
  match proposal {
    @types.Proposal::Add(kp) => verify_key_package(self.cs, kp)
    @types.Proposal::Update(leaf) =>
      self.validate_update_leaf(sender_leaf, leaf)
    @types.Proposal::Remove(target_leaf) => {
      if target_leaf == sender_leaf {
        raise CannotRemoveSelf
      }
      let target_opt = self.tree.get_leaf(target_leaf) catch {
        e => raise TreeError(e)
      }
      if target_opt is None {
        raise InvalidProposal("cannot remove blank leaf")
      }
    }
    _ => raise InvalidProposal("unsupported proposal type")
  }
}

///|
fn MlsGroup::send_proposal(
  self : MlsGroup,
  proposal : @types.Proposal,
  rng : @crypto.DeterministicRng,
) -> @types.PrivateMessage raise GroupError {
  self.ensure_active()
  let framed_content : @types.FramedContent = {
    group_id: self.group_context.group_id,
    epoch: self.group_context.epoch,
    sender: @types.Sender::Member(self.my_leaf),
    authenticated_data: b"",
    content: @types.FramedContentBody::Proposal(proposal),
  }
  let signature = @schedule.sign_framed_content(
    self.cs,
    self.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    framed_content,
    Some(self.group_context),
  ) catch {
    e => raise ScheduleError(e)
  }
  let auth : @types.FramedContentAuthData = {
    signature,
    confirmation_tag: None,
  }
  let auth_content : @types.AuthenticatedContent = {
    wire_format: @types.WireFormat::MlsPrivateMessage,
    content: framed_content,
    auth,
  }
  let ac_bytes = auth_content.to_bytes() catch { e => raise TlsError(e) }
  let proposal_ref = self.cs.make_proposal_ref(ac_bytes) catch {
    e => raise CsError(e)
  }
  let reuse_guard = rng.next_bytes(4)
  let (generation, key, nonce) = self.secret_tree.next_handshake_key_nonce(
    self.my_leaf,
  ) catch {
    e => raise TreeError(e)
  }
  let sender_data : @types.MlsSenderData = {
    leaf_index: self.my_leaf,
    generation,
    reuse_guard,
  }
  let msg = @schedule.encrypt_private_message_with_keys(
    self.cs,
    self.secrets.sender_data_secret,
    sender_data,
    key,
    nonce,
    framed_content,
    auth,
    0,
  ) catch {
    e => raise ScheduleError(e)
  }
  if self.find_pending_proposal(proposal_ref) is None {
    self.pending_proposals.push({
      proposal_ref,
      sender_leaf: self.my_leaf,
      proposal,
    })
  }
  msg
}

///|
/// Verifies `kp` and creates a `PrivateMessage` carrying an `Add` proposal.
pub fn MlsGroup::propose_add(
  self : MlsGroup,
  kp : @types.KeyPackage,
  rng : @crypto.DeterministicRng,
) -> @types.PrivateMessage raise GroupError {
  self.ensure_active()
  verify_key_package(self.cs, kp)
  self.send_proposal(@types.Proposal::Add(kp), rng)
}

///|
/// Rotates this member's leaf encryption key, caches the new private key until
/// committed, and creates a `PrivateMessage` carrying an `Update` proposal.
pub fn MlsGroup::propose_update(
  self : MlsGroup,
  rng : @crypto.DeterministicRng,
) -> @types.PrivateMessage raise GroupError {
  self.ensure_active()
  let cur_opt = self.tree.get_leaf(self.my_leaf) catch {
    e => raise TreeError(e)
  }
  let cur_leaf = match cur_opt {
    Some(l) => l
    None => raise MemberRemoved
  }
  let enc_ikm = rng.next_bytes(32)
  let (new_enc_priv, new_enc_pub) = self.cs.kem_keypair_from_ikm(enc_ikm) catch {
    e => raise CsError(e)
  }
  let unsigned_leaf : @types.LeafNode = {
    encryption_key: new_enc_pub,
    signature_key: cur_leaf.signature_key,
    credential: cur_leaf.credential,
    capabilities: cur_leaf.capabilities,
    leaf_node_source: @types.LeafNodeSource::Update,
    lifetime: None,
    parent_hash: None,
    extensions: cur_leaf.extensions,
    signature: b"",
  }
  let tbs = unsigned_leaf.encode_tbs(
    Some(self.group_context.group_id),
    Some(self.my_leaf),
  ) catch {
    e => raise TlsError(e)
  }
  let sig = self.cs.sign_with_label(self.signature_priv, "LeafNodeTBS", tbs) catch {
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
  let msg = self.send_proposal(@types.Proposal::Update(signed_leaf), rng)
  self.pending_update_privs.set(new_enc_pub, new_enc_priv)
  msg
}

///|
/// Creates a `PrivateMessage` carrying a `Remove` proposal for `target_leaf`.
/// Rejects removing oneself (`CannotRemoveSelf`) or a blank/out-of-bounds leaf.
pub fn MlsGroup::propose_remove(
  self : MlsGroup,
  target_leaf : UInt32,
  rng : @crypto.DeterministicRng,
) -> @types.PrivateMessage raise GroupError {
  self.ensure_active()
  if target_leaf == self.my_leaf {
    raise CannotRemoveSelf
  }
  let target_opt = self.tree.get_leaf(target_leaf) catch {
    e => raise TreeError(e)
  }
  if target_opt is None {
    raise InvalidProposal("cannot remove blank leaf")
  }
  self.send_proposal(@types.Proposal::Remove(target_leaf), rng)
}

///|
/// Validates and applies a resolved list of `(sender_leaf, Proposal)` pairs onto
/// `work_tree` in RFC 9420 §12.4.2 order (Updates -> Removes -> Adds).
/// Returns `(added_members, exclude_leaves, my_updated_leaf_opt, has_update_or_remove)`.
fn apply_commit_proposals(
  cs : @cs.CipherSuite,
  group_id : Bytes,
  committer_leaf : UInt32,
  my_leaf : UInt32,
  work_tree : @tree.RatchetTreeState,
  resolved : Array[(UInt32, @types.Proposal)],
) -> (Array[(UInt32, @types.KeyPackage)], Array[UInt32], @types.LeafNode?, Bool) raise GroupError {
  let updates : Array[(UInt32, @types.LeafNode)] = []
  let removes : Array[UInt32] = []
  let adds : Array[@types.KeyPackage] = []
  let updated_senders : Map[UInt32, Bool] = Map([])
  let removed_targets : Map[UInt32, Bool] = Map([])
  for i = 0; i < resolved.length(); i = i + 1 {
    let (sender_leaf, prop) = resolved[i]
    match prop {
      @types.Proposal::Update(leaf) => {
        if sender_leaf == committer_leaf {
          raise InvalidCommit("committer cannot include own Update proposal")
        }
        if updated_senders.contains(sender_leaf) {
          raise InvalidCommit("duplicate Update proposal for same sender")
        }
        match leaf.leaf_node_source {
          @types.LeafNodeSource::Update => ()
          _ => raise InvalidProposal("Update leaf_node_source must be Update")
        }
        if leaf.lifetime is Some(_) || leaf.parent_hash is Some(_) {
          raise InvalidProposal("Update leaf_node has forbidden fields")
        }
        let cur_opt = work_tree.get_leaf(sender_leaf) catch {
          _ => raise UnknownSender(sender_leaf)
        }
        match cur_opt {
          Some(cur) =>
            if leaf.encryption_key == cur.encryption_key {
              raise InvalidProposal(
                "Update leaf_node must rotate encryption_key",
              )
            }
          None => raise UnknownSender(sender_leaf)
        }
        @tree.verify_leaf_signature(cs, leaf, group_id, sender_leaf) catch {
          e => raise TreeError(e)
        }
        updated_senders.set(sender_leaf, true)
        updates.push((sender_leaf, leaf))
      }
      @types.Proposal::Remove(target_leaf) => {
        if target_leaf == committer_leaf {
          raise CannotRemoveSelf
        }
        if removed_targets.contains(target_leaf) {
          raise InvalidCommit("duplicate Remove proposal for same leaf")
        }
        let target_opt = work_tree.get_leaf(target_leaf) catch {
          e => raise TreeError(e)
        }
        if target_opt is None {
          raise InvalidProposal("cannot remove blank leaf")
        }
        removed_targets.set(target_leaf, true)
        removes.push(target_leaf)
      }
      @types.Proposal::Add(kp) => {
        verify_key_package(cs, kp)
        adds.push(kp)
      }
      _ => raise InvalidProposal("unsupported proposal type in Commit")
    }
  }
  // Reject leaves that have both Update and Remove in the same Commit
  for i = 0; i < removes.length(); i = i + 1 {
    if updated_senders.contains(removes[i]) {
      raise InvalidCommit("leaf has both Update and Remove in same Commit")
    }
  }
  let mut my_updated_leaf : @types.LeafNode? = None
  // 1. Apply Updates
  for i = 0; i < updates.length(); i = i + 1 {
    let (sender_leaf, leaf) = updates[i]
    work_tree.update_leaf(sender_leaf, leaf) catch {
      e => raise TreeError(e)
    }
    if sender_leaf == my_leaf {
      my_updated_leaf = Some(leaf)
    }
  }
  // 2. Apply Removes
  for i = 0; i < removes.length(); i = i + 1 {
    work_tree.remove_leaf(removes[i]) catch {
      e => raise TreeError(e)
    }
  }
  // 3. Apply Adds (checking no duplicate init_key across adds)
  let added_members : Array[(UInt32, @types.KeyPackage)] = []
  let exclude_leaves : Array[UInt32] = []
  let seen_init_keys : Map[Bytes, Bool] = Map([])
  for i = 0; i < adds.length(); i = i + 1 {
    let kp = adds[i]
    if seen_init_keys.contains(kp.init_key) {
      raise InvalidKeyPackage("duplicate init_key in Commit Add proposals")
    }
    seen_init_keys.set(kp.init_key, true)
    let added_leaf_idx = work_tree.add_leaf(kp.leaf_node) catch {
      e => raise TreeError(e)
    }
    added_members.push((added_leaf_idx, kp))
    exclude_leaves.push(added_leaf_idx)
  }
  work_tree.validate_tree_structure() catch {
    e => raise TreeError(e)
  }
  let has_update_or_remove = updates.length() > 0 || removes.length() > 0
  (added_members, exclude_leaves, my_updated_leaf, has_update_or_remove)
}

///|
/// Commits all pending proposals (excluding redundant self-`Update` proposals
/// per RFC 9420 §12.2) plus `extra_proposals`, generates a fresh `UpdatePath`,
/// signs and encrypts the Commit `PrivateMessage`, optionally generates a
/// `Welcome` message for newly added members, and atomically advances the local
/// group state to `epoch + 1`.
pub fn MlsGroup::commit(
  self : MlsGroup,
  extra_proposals : Array[@types.Proposal],
  rng : @crypto.DeterministicRng,
) -> CommitOutput raise GroupError {
  self.ensure_active()
  if self.group_context.epoch == MAX_EPOCH {
    raise InvalidCommit("epoch overflow: cannot advance past UInt64 max")
  }
  let proposal_or_refs : Array[@types.ProposalOrRef] = []
  let resolved : Array[(UInt32, @types.Proposal)] = []
  // Pre-scan extra_proposals (which remain strictly validated) so pending
  // proposals do not conflict with explicitly requested Removes or Adds.
  let extra_removed_targets : Map[UInt32, Bool] = Map([])
  let extra_add_init_keys : Map[Bytes, Bool] = Map([])
  let extra_add_enc_keys : Map[Bytes, Bool] = Map([])
  let extra_add_sig_keys : Map[Bytes, Bool] = Map([])
  for i = 0; i < extra_proposals.length(); i = i + 1 {
    match extra_proposals[i] {
      @types.Proposal::Remove(target) =>
        if target != self.my_leaf {
          let opt = self.tree.get_leaf(target) catch { _ => None }
          if opt is Some(_) {
            extra_removed_targets.set(target, true)
          }
        }
      @types.Proposal::Add(kp) => {
        extra_add_init_keys.set(kp.init_key, true)
        extra_add_enc_keys.set(kp.leaf_node.encryption_key, true)
        extra_add_sig_keys.set(kp.leaf_node.signature_key, true)
      }
      _ => ()
    }
  }
  // Deterministic RFC 9420 §12.4.1 conflict filtering over self.pending_proposals:
  // Pass 1: Removes (skip self, blank leaves, duplicates)
  let n_pending = self.pending_proposals.length()
  let selected_pending : Array[Bool] = Array::make(n_pending, false)
  let selected_removes : Map[UInt32, Bool] = Map([])
  let effective_removes : Array[UInt32] = []
  extra_removed_targets.each(fn(t, _v) { effective_removes.push(t) })
  for i = 0; i < n_pending; i = i + 1 {
    let pp = self.pending_proposals[i]
    match pp.proposal {
      @types.Proposal::Remove(target) => {
        if target == self.my_leaf ||
          selected_removes.contains(target) ||
          extra_removed_targets.contains(target) {
          continue
        }
        let target_opt = self.tree.get_leaf(target) catch { _ => None }
        if target_opt is None {
          continue
        }
        selected_removes.set(target, true)
        effective_removes.push(target)
        selected_pending[i] = true
      }
      _ => ()
    }
  }
  // Build preview tree after selected Removes so Update/Add key checks exclude removed leaves
  let mut preview_tree = self.tree.clone()
  for i = 0; i < effective_removes.length(); i = i + 1 {
    preview_tree.remove_leaf(effective_removes[i]) catch {
      _ => ()
    }
  }
  // Pass 2: Updates (skip committer's own Update, removed senders, duplicate senders, invalid leaves)
  let updated_senders : Map[UInt32, Bool] = Map([])
  for i = 0; i < n_pending; i = i + 1 {
    let pp = self.pending_proposals[i]
    match pp.proposal {
      @types.Proposal::Update(leaf) => {
        if pp.sender_leaf == self.my_leaf ||
          updated_senders.contains(pp.sender_leaf) ||
          selected_removes.contains(pp.sender_leaf) ||
          extra_removed_targets.contains(pp.sender_leaf) {
          continue
        }
        let valid_upd = try {
          self.validate_update_leaf(pp.sender_leaf, leaf)
          true
        } catch {
          _ => false
        }
        if !valid_upd {
          continue
        }
        let trial = preview_tree.clone()
        let tree_ok = try {
          trial.update_leaf(pp.sender_leaf, leaf)
          trial.validate_tree_structure()
          true
        } catch {
          _ => false
        }
        if !tree_ok {
          continue
        }
        preview_tree = trial
        updated_senders.set(pp.sender_leaf, true)
        selected_pending[i] = true
      }
      _ => ()
    }
  }
  // Pass 3: Adds (skip invalid KeyPackages or key conflicts with remaining tree / prior Adds)
  let seen_init_keys : Map[Bytes, Bool] = Map([])
  extra_add_init_keys.each(fn(k, _v) { seen_init_keys.set(k, true) })
  for i = 0; i < n_pending; i = i + 1 {
    let pp = self.pending_proposals[i]
    match pp.proposal {
      @types.Proposal::Add(kp) => {
        let valid_kp = try {
          verify_key_package(self.cs, kp)
          true
        } catch {
          _ => false
        }
        if !valid_kp ||
          seen_init_keys.contains(kp.init_key) ||
          extra_add_enc_keys.contains(kp.leaf_node.encryption_key) ||
          extra_add_sig_keys.contains(kp.leaf_node.signature_key) {
          continue
        }
        let trial = preview_tree.clone()
        let tree_ok = try {
          let _ = trial.add_leaf(kp.leaf_node)
          trial.validate_tree_structure()
          true
        } catch {
          _ => false
        }
        if !tree_ok {
          continue
        }
        preview_tree = trial
        seen_init_keys.set(kp.init_key, true)
        selected_pending[i] = true
      }
      _ => ()
    }
  }
  // Emit surviving pending proposals in deterministic arrival order
  for i = 0; i < n_pending; i = i + 1 {
    if selected_pending[i] {
      let pp = self.pending_proposals[i]
      proposal_or_refs.push(@types.ProposalOrRef::Reference(pp.proposal_ref))
      resolved.push((pp.sender_leaf, pp.proposal))
    }
  }
  // Include extra inline proposals (strictly validated in apply_commit_proposals)
  for i = 0; i < extra_proposals.length(); i = i + 1 {
    let prop = extra_proposals[i]
    proposal_or_refs.push(@types.ProposalOrRef::Proposal(prop))
    resolved.push((self.my_leaf, prop))
  }
  let new_tree = self.tree.clone()
  let (added_members, exclude_leaves, _my_upd, _has_ur) = apply_commit_proposals(
    self.cs,
    self.group_context.group_id,
    self.my_leaf,
    self.my_leaf,
    new_tree,
    resolved,
  )
  let my_cur_leaf_opt = new_tree.get_leaf(self.my_leaf) catch {
    e => raise TreeError(e)
  }
  let my_cur_leaf = match my_cur_leaf_opt {
    Some(l) => l
    None => raise MemberRemoved
  }
  // Step 1: Prepare UpdatePath tree & derive commit_secret
  let leaf_secret = rng.next_bytes(self.cs.secret_len())
  let prepared = new_tree.prepare_update_path_tree(
    self.cs,
    self.my_leaf,
    my_cur_leaf,
    self.signature_priv,
    self.group_context.group_id,
    leaf_secret,
  ) catch {
    e => raise TreeError(e)
  }
  let new_tree_hash = prepared.tree_hash
  // Step 2: Encrypt path secrets against provisional GroupContext
  let provisional_gc : @types.GroupContext = {
    version: self.group_context.version,
    cipher_suite: self.group_context.cipher_suite,
    group_id: self.group_context.group_id,
    epoch: self.group_context.epoch + 1UL,
    tree_hash: new_tree_hash,
    confirmed_transcript_hash: self.group_context.confirmed_transcript_hash,
    extensions: self.group_context.extensions,
  }
  let provisional_gc_bytes = provisional_gc.to_bytes() catch {
    e => raise TlsError(e)
  }
  let update_path = new_tree.encrypt_path_secrets(
    self.cs,
    self.my_leaf,
    prepared,
    provisional_gc_bytes,
    exclude_leaves,
    rng,
  ) catch {
    e => raise TreeError(e)
  }
  // Step 3: Sign FramedContent(Commit) with OLD GroupContext
  let commit_obj : @types.Commit = {
    proposals: proposal_or_refs,
    path: Some(update_path),
  }
  let framed_content : @types.FramedContent = {
    group_id: self.group_context.group_id,
    epoch: self.group_context.epoch,
    sender: @types.Sender::Member(self.my_leaf),
    authenticated_data: b"",
    content: @types.FramedContentBody::Commit(commit_obj),
  }
  let signature = @schedule.sign_framed_content(
    self.cs,
    self.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    framed_content,
    Some(self.group_context),
  ) catch {
    e => raise ScheduleError(e)
  }
  // Step 4: Transcript hash, final GroupContext, new EpochSecrets, confirmation_tag
  let new_confirmed_transcript_hash = @schedule.compute_confirmed_transcript_hash(
    self.cs,
    self.interim_transcript_hash,
    {
      wire_format: @types.WireFormat::MlsPrivateMessage,
      content: framed_content,
      signature,
    },
  ) catch {
    e => raise ScheduleError(e)
  }
  let new_group_context : @types.GroupContext = {
    version: self.group_context.version,
    cipher_suite: self.group_context.cipher_suite,
    group_id: self.group_context.group_id,
    epoch: self.group_context.epoch + 1UL,
    tree_hash: new_tree_hash,
    confirmed_transcript_hash: new_confirmed_transcript_hash,
    extensions: self.group_context.extensions,
  }
  let new_gc_bytes = new_group_context.to_bytes() catch {
    e => raise TlsError(e)
  }
  let new_secrets = @schedule.derive_epoch_secrets(
    self.cs,
    self.secrets.init_secret,
    prepared.commit_secret,
    self.cs.zero_secret(),
    new_gc_bytes,
  ) catch {
    e => raise ScheduleError(e)
  }
  let confirmation_tag = @schedule.compute_confirmation_tag(
    self.cs,
    new_secrets.confirmation_key,
    new_confirmed_transcript_hash,
  )
  let new_interim_transcript_hash = @schedule.compute_interim_transcript_hash(
    self.cs,
    new_confirmed_transcript_hash,
    confirmation_tag,
  ) catch {
    e => raise ScheduleError(e)
  }
  // Step 5: Build Welcome if any members were added
  let welcome : @types.Welcome? = if added_members.length() > 0 {
    let rt_bytes = @types.ratchet_tree_to_bytes(new_tree.to_trimmed_nodes()) catch {
      e => raise TlsError(e)
    }
    let gi_extensions : Array[@types.Extension] = [
      { extension_type: @types.EXT_RATCHET_TREE, extension_data: rt_bytes, },
    ]
    let unsigned_gi : @types.GroupInfo = {
      group_context: new_group_context,
      extensions: gi_extensions,
      confirmation_tag,
      signer: self.my_leaf,
      signature: b"",
    }
    let gi_tbs = unsigned_gi.encode_tbs() catch { e => raise TlsError(e) }
    let gi_sig = self.cs.sign_with_label(
      self.signature_priv,
      "GroupInfoTBS",
      gi_tbs,
    ) catch {
      e => raise CsError(e)
    }
    let group_info : @types.GroupInfo = {
      group_context: unsigned_gi.group_context,
      extensions: unsigned_gi.extensions,
      confirmation_tag: unsigned_gi.confirmation_tag,
      signer: unsigned_gi.signer,
      signature: gi_sig,
    }
    let gi_bytes = group_info.to_bytes() catch { e => raise TlsError(e) }
    let (welcome_key, welcome_nonce) = @schedule.derive_welcome_key_nonce(
      self.cs,
      new_secrets.welcome_secret,
    ) catch {
      e => raise ScheduleError(e)
    }
    let encrypted_group_info = self.cs.aead_seal(
      welcome_key, welcome_nonce, b"", gi_bytes,
    ) catch {
      e => raise CsError(e)
    }
    let encrypted_secrets : Array[@types.EncryptedGroupSecrets] = Array(
      capacity=added_members.length(),
    )
    let my_node = @treemath.leaf_to_node(self.my_leaf)
    for i = 0; i < added_members.length(); i = i + 1 {
      let (new_leaf_idx, kp) = added_members[i]
      let lca = @treemath.common_ancestor(
        my_node,
        @treemath.leaf_to_node(new_leaf_idx),
      )
      let path_secret = lookup_path_secret(prepared.path_secrets, lca)
      let gs : @types.GroupSecrets = {
        joiner_secret: new_secrets.joiner_secret,
        path_secret,
        psks: [],
      }
      let gs_bytes = gs.to_bytes() catch { e => raise TlsError(e) }
      let kp_bytes = kp.to_bytes() catch { e => raise TlsError(e) }
      let kp_ref = self.cs.make_key_package_ref(kp_bytes) catch {
        e => raise CsError(e)
      }
      let (kem_output, ciphertext) = self.cs.encrypt_with_label(
        kp.init_key,
        "Welcome",
        encrypted_group_info,
        gs_bytes,
        rng,
      ) catch {
        e => raise CsError(e)
      }
      encrypted_secrets.push({
        new_member: kp_ref,
        encrypted_group_secrets: { kem_output, ciphertext, },
      })
    }
    Some({
      cipher_suite: self.cs.id(),
      secrets: encrypted_secrets,
      encrypted_group_info,
    })
  } else {
    None
  }
  // Step 6: Encrypt Commit PrivateMessage under OLD epoch's SecretTree
  let reuse_guard = rng.next_bytes(4)
  let (generation, key, nonce) = self.secret_tree.next_handshake_key_nonce(
    self.my_leaf,
  ) catch {
    e => raise TreeError(e)
  }
  let sender_data : @types.MlsSenderData = {
    leaf_index: self.my_leaf,
    generation,
    reuse_guard,
  }
  let auth : @types.FramedContentAuthData = {
    signature,
    confirmation_tag: Some(confirmation_tag),
  }
  let commit_msg = @schedule.encrypt_private_message_with_keys(
    self.cs,
    self.secrets.sender_data_secret,
    sender_data,
    key,
    nonce,
    framed_content,
    auth,
    0,
  ) catch {
    e => raise ScheduleError(e)
  }
  // Step 7: Atomically commit new epoch state
  let new_node_priv_keys : Map[UInt32, Bytes] = Map([])
  new_node_priv_keys.set(
    @treemath.leaf_to_node(self.my_leaf),
    prepared.leaf_enc_priv,
  )
  for i = 0; i < prepared.path_node_keys.length(); i = i + 1 {
    let (d_node, sk, _pk) = prepared.path_node_keys[i]
    new_node_priv_keys.set(d_node, sk)
  }
  let new_active_secrets = ActiveEpochSecrets::from_epoch_secrets(new_secrets)
  self.tree = new_tree
  self.group_context = new_group_context
  self.interim_transcript_hash = new_interim_transcript_hash
  self.secrets = new_active_secrets
  self.secret_tree = @tree.SecretTree::new(
    self.cs,
    new_secrets.encryption_secret,
    new_tree.n_leaves(),
  )
  self.node_priv_keys = new_node_priv_keys
  self.pending_proposals = []
  self.pending_update_privs = Map([])
  { commit_msg, welcome, new_epoch: new_group_context.epoch, }
}

///|
/// Commits all currently queued pending proposals.
pub fn MlsGroup::commit_pending(
  self : MlsGroup,
  rng : @crypto.DeterministicRng,
) -> CommitOutput raise GroupError {
  self.commit([], rng)
}

///|
/// Encrypts and signs an application payload with associated data `aad` into a
/// `PrivateMessage` for the current epoch.
pub fn MlsGroup::protect_application(
  self : MlsGroup,
  plaintext : Bytes,
  aad : Bytes,
  rng : @crypto.DeterministicRng,
) -> @types.PrivateMessage raise GroupError {
  self.ensure_active()
  let framed_content : @types.FramedContent = {
    group_id: self.group_context.group_id,
    epoch: self.group_context.epoch,
    sender: @types.Sender::Member(self.my_leaf),
    authenticated_data: aad,
    content: @types.FramedContentBody::Application(plaintext),
  }
  let signature = @schedule.sign_framed_content(
    self.cs,
    self.signature_priv,
    @types.WireFormat::MlsPrivateMessage,
    framed_content,
    Some(self.group_context),
  ) catch {
    e => raise ScheduleError(e)
  }
  let auth : @types.FramedContentAuthData = {
    signature,
    confirmation_tag: None,
  }
  let reuse_guard = rng.next_bytes(4)
  let (generation, key, nonce) = self.secret_tree.next_application_key_nonce(
    self.my_leaf,
  ) catch {
    e => raise TreeError(e)
  }
  let sender_data : @types.MlsSenderData = {
    leaf_index: self.my_leaf,
    generation,
    reuse_guard,
  }
  @schedule.encrypt_private_message_with_keys(
    self.cs,
    self.secrets.sender_data_secret,
    sender_data,
    key,
    nonce,
    framed_content,
    auth,
    0,
  ) catch {
    e => raise ScheduleError(e)
  }
}

///|
fn MlsGroup::find_pending_proposal(
  self : MlsGroup,
  proposal_ref : Bytes,
) -> PendingProposal? {
  for i = 0; i < self.pending_proposals.length(); i = i + 1 {
    if self.pending_proposals[i].proposal_ref == proposal_ref {
      return Some(self.pending_proposals[i])
    }
  }
  None
}

///|
/// Processes an incoming `PrivateMessage` (Application, Proposal, or Commit)
/// with strict epoch/group checks, forward-secure replay protection, signature
/// verification, and atomic state transitions (failed messages never mutate
/// group state).
pub fn MlsGroup::process_message(
  self : MlsGroup,
  msg : @types.PrivateMessage,
) -> ProcessedMessage raise GroupError {
  self.ensure_active()
  if msg.group_id != self.group_context.group_id {
    raise GroupIdMismatch
  }
  if msg.epoch != self.group_context.epoch {
    raise EpochMismatch(self.group_context.epoch, msg.epoch)
  }
  let sender_data = @schedule.decrypt_sender_data(
    self.cs,
    self.secrets.sender_data_secret,
    msg,
  ) catch {
    e => raise ScheduleError(e)
  }
  let sender_leaf = sender_data.leaf_index
  let sender_leaf_opt = self.tree.get_leaf(sender_leaf) catch {
    _ => raise UnknownSender(sender_leaf)
  }
  let sender_node = match sender_leaf_opt {
    Some(l) => l
    None => raise UnknownSender(sender_leaf)
  }
  let is_application = match msg.content_type {
    @types.ContentType::Application => true
    @types.ContentType::Proposal | @types.ContentType::Commit => false
  }
  // O(1) single-leaf ratchet staging: immediately rejects replays & forward jumps
  // without mutating self.secret_tree until all AEAD/signature/Commit checks pass.
  let ratchet_stage = self.secret_tree.stage_key_nonce(
    sender_leaf,
    sender_data.generation,
    is_application,
  ) catch {
    e => raise TreeError(e)
  }
  let auth_content = @schedule.decrypt_private_message_with_keys(
    self.cs,
    sender_node.signature_key,
    self.group_context,
    sender_data,
    ratchet_stage.key(),
    ratchet_stage.nonce(),
    msg,
  ) catch {
    e => raise ScheduleError(e)
  }
  match auth_content.content.content {
    @types.FramedContentBody::Application(plaintext) => {
      self.secret_tree.commit_stage(ratchet_stage)
      ProcessedMessage::Application(
        sender_leaf,
        plaintext,
        auth_content.content.authenticated_data,
      )
    }
    @types.FramedContentBody::Proposal(proposal) => {
      self.validate_incoming_proposal(sender_leaf, proposal)
      let ac_bytes = auth_content.to_bytes() catch { e => raise TlsError(e) }
      let proposal_ref = self.cs.make_proposal_ref(ac_bytes) catch {
        e => raise CsError(e)
      }
      self.secret_tree.commit_stage(ratchet_stage)
      if self.find_pending_proposal(proposal_ref) is None {
        self.pending_proposals.push({ proposal_ref, sender_leaf, proposal, })
      }
      ProcessedMessage::Proposal(sender_leaf, proposal)
    }
    @types.FramedContentBody::Commit(commit_obj) => {
      if self.group_context.epoch == MAX_EPOCH {
        raise InvalidCommit("epoch overflow: cannot advance past UInt64 max")
      }
      let msg_conf_tag = match auth_content.auth.confirmation_tag {
        Some(tag) => tag
        None => raise InvalidCommit("Commit missing confirmation_tag")
      }
      // Resolve all ProposalOrRef entries
      let resolved : Array[(UInt32, @types.Proposal)] = Array(
        capacity=commit_obj.proposals.length(),
      )
      let seen_refs : Map[Bytes, Bool] = Map([])
      let mut self_removed = false
      for i = 0; i < commit_obj.proposals.length(); i = i + 1 {
        match commit_obj.proposals[i] {
          @types.ProposalOrRef::Proposal(prop) => {
            if prop is @types.Proposal::Remove(target) && target == self.my_leaf {
              self_removed = true
            }
            resolved.push((sender_leaf, prop))
          }
          @types.ProposalOrRef::Reference(pref) => {
            if seen_refs.contains(pref) {
              raise InvalidCommit("duplicate ProposalRef in Commit")
            }
            seen_refs.set(pref, true)
            match self.find_pending_proposal(pref) {
              Some(pp) => {
                if pp.proposal is @types.Proposal::Remove(target) &&
                  target == self.my_leaf {
                  self_removed = true
                }
                resolved.push((pp.sender_leaf, pp.proposal))
              }
              None =>
                raise InvalidCommit("unknown ProposalRef referenced by Commit")
            }
          }
        }
      }
      // Validate proposals on cloned tree
      let new_tree = self.tree.clone()
      let (_added_members, exclude_leaves, my_updated_leaf, has_ur) = apply_commit_proposals(
        self.cs,
        self.group_context.group_id,
        sender_leaf,
        self.my_leaf,
        new_tree,
        resolved,
      )
      // If we are removed by this Commit, we MUST still validate Commit.path &
      // UpdatePath (RFC 9420 §12.4) before committing the ratchet or marking inactive.
      if self_removed {
        let update_path = match commit_obj.path {
          Some(up) => up
          None =>
            raise InvalidCommit("Commit removing member requires an UpdatePath")
        }
        new_tree.merge_update_path_nodes(
          self.cs,
          sender_leaf,
          update_path,
          self.group_context.group_id,
          exclude_leaves,
        ) catch {
          e => raise TreeError(e)
        }
        new_tree.validate_parent_hashes(self.cs) catch {
          e => raise TreeError(e)
        }
        self.secret_tree.commit_stage(ratchet_stage)
        self.active = false
        raise MemberRemoved
      }
      // Prepare cloned private key map, applying our own Update if committed
      let new_node_priv_keys = clone_u32_bytes_map(self.node_priv_keys)
      match my_updated_leaf {
        Some(new_leaf) =>
          match self.pending_update_privs.get(new_leaf.encryption_key) {
            Some(priv_key) =>
              new_node_priv_keys.set(
                @treemath.leaf_to_node(self.my_leaf),
                priv_key,
              )
            None =>
              raise MissingPrivateKey(@treemath.leaf_to_node(self.my_leaf))
          }
        None => ()
      }
      prune_stale_priv_keys(new_tree, new_node_priv_keys)
      // Process UpdatePath if present
      let commit_secret = match commit_obj.path {
        Some(update_path) => {
          new_tree.merge_update_path_nodes(
            self.cs,
            sender_leaf,
            update_path,
            self.group_context.group_id,
            exclude_leaves,
          ) catch {
            e => raise TreeError(e)
          }
          let new_tree_hash = new_tree.tree_hash(self.cs) catch {
            e => raise TreeError(e)
          }
          let provisional_gc : @types.GroupContext = {
            version: self.group_context.version,
            cipher_suite: self.group_context.cipher_suite,
            group_id: self.group_context.group_id,
            epoch: self.group_context.epoch + 1UL,
            tree_hash: new_tree_hash,
            confirmed_transcript_hash: self.group_context.confirmed_transcript_hash,
            extensions: self.group_context.extensions,
          }
          let provisional_gc_bytes = provisional_gc.to_bytes() catch {
            e => raise TlsError(e)
          }
          let mut missing_node : UInt32? = None
          let (derived_keys, cs_secret) = new_tree.decrypt_update_path(
            self.cs,
            sender_leaf,
            self.my_leaf,
            update_path,
            provisional_gc_bytes,
            exclude_leaves,
            fn(node_idx) {
              match new_node_priv_keys.get(node_idx) {
                Some(sk) => Some(sk)
                None => {
                  missing_node = Some(node_idx)
                  None
                }
              }
            },
          ) catch {
            @tree.TreeError::PathMismatch =>
              match missing_node {
                Some(n) => raise MissingPrivateKey(n)
                None => raise TreeError(@tree.TreeError::PathMismatch)
              }
            e => raise TreeError(e)
          }
          for i = 0; i < derived_keys.length(); i = i + 1 {
            let (node_idx, sk) = derived_keys[i]
            new_node_priv_keys.set(node_idx, sk)
          }
          prune_stale_priv_keys(new_tree, new_node_priv_keys)
          cs_secret
        }
        None => {
          if has_ur || resolved.length() == 0 {
            raise InvalidCommit("Commit requires an UpdatePath")
          }
          self.cs.zero_secret()
        }
      }
      let new_tree_hash = new_tree.tree_hash(self.cs) catch {
        e => raise TreeError(e)
      }
      let new_confirmed_transcript_hash = @schedule.compute_confirmed_transcript_hash(
        self.cs,
        self.interim_transcript_hash,
        {
          wire_format: @types.WireFormat::MlsPrivateMessage,
          content: auth_content.content,
          signature: auth_content.auth.signature,
        },
      ) catch {
        e => raise ScheduleError(e)
      }
      let new_group_context : @types.GroupContext = {
        version: self.group_context.version,
        cipher_suite: self.group_context.cipher_suite,
        group_id: self.group_context.group_id,
        epoch: self.group_context.epoch + 1UL,
        tree_hash: new_tree_hash,
        confirmed_transcript_hash: new_confirmed_transcript_hash,
        extensions: self.group_context.extensions,
      }
      let new_gc_bytes = new_group_context.to_bytes() catch {
        e => raise TlsError(e)
      }
      let new_secrets = @schedule.derive_epoch_secrets(
        self.cs,
        self.secrets.init_secret,
        commit_secret,
        self.cs.zero_secret(),
        new_gc_bytes,
      ) catch {
        e => raise ScheduleError(e)
      }
      if !@schedule.verify_confirmation_tag(
          self.cs,
          new_secrets.confirmation_key,
          new_confirmed_transcript_hash,
          msg_conf_tag,
        ) {
        raise ConfirmationTagMismatch
      }
      let new_interim_transcript_hash = @schedule.compute_interim_transcript_hash(
        self.cs,
        new_confirmed_transcript_hash,
        msg_conf_tag,
      ) catch {
        e => raise ScheduleError(e)
      }
      // Atomically advance state to epoch + 1
      let new_active_secrets = ActiveEpochSecrets::from_epoch_secrets(
        new_secrets,
      )
      self.secret_tree.commit_stage(ratchet_stage)
      self.tree = new_tree
      self.group_context = new_group_context
      self.interim_transcript_hash = new_interim_transcript_hash
      self.secrets = new_active_secrets
      self.secret_tree = @tree.SecretTree::new(
        self.cs,
        new_secrets.encryption_secret,
        new_tree.n_leaves(),
      )
      self.node_priv_keys = new_node_priv_keys
      self.pending_proposals = []
      self.pending_update_privs = Map([])
      ProcessedMessage::Commit(sender_leaf, new_group_context.epoch)
    }
  }
}

///|
/// Returns the group's cipher suite.
pub fn MlsGroup::cipher_suite(self : MlsGroup) -> @cs.CipherSuite {
  self.cs
}

///|
/// Returns the group identifier.
pub fn MlsGroup::group_id(self : MlsGroup) -> Bytes {
  self.group_context.group_id
}

///|
/// Returns the current epoch number.
pub fn MlsGroup::epoch(self : MlsGroup) -> UInt64 {
  self.group_context.epoch
}

///|
/// Returns this member's leaf index in the ratchet tree.
pub fn MlsGroup::my_leaf_index(self : MlsGroup) -> UInt32 {
  self.my_leaf
}

///|
/// Returns `true` while this member remains active in the group.
pub fn MlsGroup::is_active(self : MlsGroup) -> Bool {
  self.active
}

///|
/// Returns the ascending list of active members as `(leaf_index, identity)` pairs.
pub fn MlsGroup::members(self : MlsGroup) -> Array[(UInt32, Bytes)] {
  let indices = self.tree.active_leaf_indices()
  let out : Array[(UInt32, Bytes)] = Array(capacity=indices.length())
  for i = 0; i < indices.length(); i = i + 1 {
    let idx = indices[i]
    let leaf_opt = self.tree.get_leaf(idx) catch { _ => None }
    match leaf_opt {
      Some(leaf) => out.push((idx, credential_identity_bytes(leaf.credential)))
      None => ()
    }
  }
  out
}

///|
/// Returns the current epoch's `epoch_authenticator` (RFC 9420 §8).
pub fn MlsGroup::epoch_authenticator(self : MlsGroup) -> Bytes {
  self.secrets.epoch_authenticator
}

///|
/// Returns the current epoch's `tree_hash`.
pub fn MlsGroup::tree_hash(self : MlsGroup) -> Bytes {
  self.group_context.tree_hash
}

///|
/// Exports an application secret using `MLS-Exporter` (RFC 9420 §8.5).
pub fn MlsGroup::export_secret(
  self : MlsGroup,
  label : String,
  context : Bytes,
  length : Int32,
) -> Bytes raise GroupError {
  self.ensure_active()
  @schedule.mls_exporter(
    self.cs,
    self.secrets.exporter_secret,
    label,
    context,
    length,
  ) catch {
    e => raise ScheduleError(e)
  }
}

///|
/// Returns the current ratchet tree nodes (with trailing blank nodes trimmed
/// per RFC 9420 §12.4.3.3).
pub fn MlsGroup::ratchet_tree_nodes(self : MlsGroup) -> @types.RatchetTree {
  self.tree.to_trimmed_nodes()
}
