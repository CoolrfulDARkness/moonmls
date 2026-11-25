///|
const DEFAULT_OUT_OF_ORDER_TOLERANCE : UInt32 = 16U

///|
const DEFAULT_MAX_FORWARD_DISTANCE : UInt32 = 1000U

///|
fn sender_data_sample(
  cs : @cs.CipherSuite,
  ciphertext : Bytes,
) -> Bytes raise TreeError {
  let sample_len = if ciphertext.length() < cs.hash_len() {
    ciphertext.length()
  } else {
    cs.hash_len()
  }
  @tls.bytes_slice(ciphertext, 0, sample_len) catch {
    e => raise TlsError(e)
  }
}

///|
/// RFC 9420 §6.3.2 sender data AEAD key derivation:
/// `ExpandWithLabel(sender_data_secret, "key", ciphertext_sample, AEAD.Nk)`.
pub fn derive_sender_data_key(
  cs : @cs.CipherSuite,
  sender_data_secret : Bytes,
  ciphertext : Bytes,
) -> Bytes raise TreeError {
  let sample = sender_data_sample(cs, ciphertext)
  cs.expand_with_label(sender_data_secret, "key", sample, cs.aead_key_len()) catch {
    e => raise CsError(e)
  }
}

///|
/// RFC 9420 §6.3.2 sender data AEAD nonce derivation:
/// `ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, AEAD.Nn)`.
pub fn derive_sender_data_nonce(
  cs : @cs.CipherSuite,
  sender_data_secret : Bytes,
  ciphertext : Bytes,
) -> Bytes raise TreeError {
  let sample = sender_data_sample(cs, ciphertext)
  cs.expand_with_label(sender_data_secret, "nonce", sample, cs.aead_nonce_len()) catch {
    e => raise CsError(e)
  }
}

///|
priv struct GenerationRatchet {
  mut current_gen : UInt64
  mut current_secret : Bytes
  cached : Map[UInt32, (Bytes, Bytes)]
}

///|
fn GenerationRatchet::new(initial_secret : Bytes) -> GenerationRatchet {
  { current_gen: 0UL, current_secret: initial_secret, cached: Map([]), }
}

///|
fn GenerationRatchet::clone(self : GenerationRatchet) -> GenerationRatchet {
  let cached_copy : Map[UInt32, (Bytes, Bytes)] = Map([])
  self.cached.each(fn(k, v) { cached_copy.set(k, v) })
  {
    current_gen: self.current_gen,
    current_secret: self.current_secret,
    cached: cached_copy,
  }
}

///|
fn derive_gen_key_nonce(
  cs : @cs.CipherSuite,
  secret : Bytes,
  generation : UInt32,
) -> (Bytes, Bytes) raise TreeError {
  let nonce = cs.derive_tree_secret(
    secret,
    "nonce",
    generation,
    cs.aead_nonce_len(),
  ) catch {
    e => raise CsError(e)
  }
  let key = cs.derive_tree_secret(secret, "key", generation, cs.aead_key_len()) catch {
    e => raise CsError(e)
  }
  (key, nonce)
}

///|
fn derive_next_ratchet_secret(
  cs : @cs.CipherSuite,
  secret : Bytes,
  generation : UInt32,
) -> Bytes raise TreeError {
  cs.derive_tree_secret(secret, "secret", generation, cs.secret_len()) catch {
    e => raise CsError(e)
  }
}

///|
fn GenerationRatchet::next(
  self : GenerationRatchet,
  cs : @cs.CipherSuite,
) -> (UInt32, Bytes, Bytes) raise TreeError {
  if self.current_gen > 0xFFFFFFFFUL {
    raise GenerationTooFarAhead(0xFFFFFFFFU)
  }
  let g = self.current_gen.to_uint()
  let (key, nonce) = derive_gen_key_nonce(cs, self.current_secret, g)
  let next_secret = derive_next_ratchet_secret(cs, self.current_secret, g)
  self.current_secret = next_secret
  self.current_gen = self.current_gen + 1UL
  (g, key, nonce)
}

///|
fn GenerationRatchet::get_for_generation(
  self : GenerationRatchet,
  cs : @cs.CipherSuite,
  target_gen : UInt32,
  out_of_order_tolerance : UInt32,
  max_forward_distance : UInt32,
) -> (Bytes, Bytes) raise TreeError {
  let target64 = target_gen.to_uint64()
  if target64 < self.current_gen {
    match self.cached.get(target_gen) {
      Some(kn) => {
        self.cached.remove(target_gen)
        kn
      }
      None => raise ReplayDetected(target_gen)
    }
  } else {
    let dist = target64 - self.current_gen
    if dist > max_forward_distance.to_uint64() {
      raise GenerationTooFarAhead(target_gen)
    }
    let tol64 = out_of_order_tolerance.to_uint64()
    while self.current_gen < target64 {
      let g = self.current_gen.to_uint()
      let next_secret = derive_next_ratchet_secret(cs, self.current_secret, g)
      if target64 - self.current_gen <= tol64 {
        let kn = derive_gen_key_nonce(cs, self.current_secret, g)
        self.cached.set(g, kn)
      }
      self.current_secret = next_secret
      self.current_gen = self.current_gen + 1UL
    }
    let (key, nonce) = derive_gen_key_nonce(cs, self.current_secret, target_gen)
    let next_secret = derive_next_ratchet_secret(
      cs,
      self.current_secret,
      target_gen,
    )
    self.current_secret = next_secret
    self.current_gen = target64 + 1UL
    // Evict cached entries older than the out-of-order window
    if target64 > tol64 {
      let min_keep = target64 - tol64
      let to_evict : Array[UInt32] = []
      self.cached.each(fn(gen, _kn) {
        if gen.to_uint64() < min_keep {
          to_evict.push(gen)
        }
      })
      for i = 0; i < to_evict.length(); i = i + 1 {
        self.cached.remove(to_evict[i])
      }
    }
    (key, nonce)
  }
}

///|
/// Staged single-leaf ratchet transition returned by `SecretTree::stage_key_nonce`.
/// Allows the caller to authenticate and verify a message before atomically
/// committing the ratchet advancement via `SecretTree::commit_stage`.
pub struct RatchetStage {
  priv leaf_idx : UInt32
  priv is_application : Bool
  priv next_ratchet : GenerationRatchet
  priv key : Bytes
  priv nonce : Bytes
}

///|
/// Returns the staged AEAD key for this generation.
pub fn RatchetStage::key(self : RatchetStage) -> Bytes {
  self.key
}

///|
/// Returns the staged AEAD base nonce for this generation.
pub fn RatchetStage::nonce(self : RatchetStage) -> Bytes {
  self.nonce
}

///|
/// RFC 9420 §9.2 Secret Tree with true intra-epoch forward secrecy:
/// intermediate node secrets are derived on demand and immediately deleted
/// after splitting into children, and leaf secrets are deleted immediately
/// after initializing per-leaf handshake & application generation ratchets.
pub struct SecretTree {
  priv cs : @cs.CipherSuite
  priv node_secrets : Map[UInt32, Bytes]
  priv n_leaves : UInt32
  priv full_leaves : UInt32
  priv out_of_order_tolerance : UInt32
  priv max_forward_distance : UInt32
  priv handshake_ratchets : Map[UInt32, GenerationRatchet]
  priv application_ratchets : Map[UInt32, GenerationRatchet]
}

///|
/// Creates a `SecretTree` with default replay window settings
/// (`out_of_order_tolerance = 16`, `max_forward_distance = 1000`).
pub fn SecretTree::new(
  cs : @cs.CipherSuite,
  encryption_secret : Bytes,
  n_leaves : UInt32,
) -> SecretTree {
  SecretTree::new_with_window(
    cs,
    encryption_secret,
    n_leaves,
    DEFAULT_OUT_OF_ORDER_TOLERANCE,
    DEFAULT_MAX_FORWARD_DISTANCE,
  )
}

///|
/// Creates a `SecretTree` with explicit out-of-order tolerance and maximum
/// forward generation jump distance.
pub fn SecretTree::new_with_window(
  cs : @cs.CipherSuite,
  encryption_secret : Bytes,
  n_leaves : UInt32,
  out_of_order_tolerance : UInt32,
  max_forward_distance : UInt32,
) -> SecretTree {
  let full_leaves = next_power_of_two(n_leaves)
  let node_secrets : Map[UInt32, Bytes] = Map([])
  if n_leaves > 0U {
    let root_idx = @treemath.root(full_leaves)
    node_secrets.set(root_idx, encryption_secret)
  }
  {
    cs,
    node_secrets,
    n_leaves,
    full_leaves,
    out_of_order_tolerance,
    max_forward_distance,
    handshake_ratchets: Map([]),
    application_ratchets: Map([]),
  }
}

///|
/// Splits stored node secrets on demand along the path from the lowest
/// available ancestor down to `leaf_idx`, immediately deleting every split
/// parent node secret (RFC 9420 §9.2).
fn SecretTree::split_to_leaf(
  self : SecretTree,
  leaf_idx : UInt32,
) -> Bytes raise TreeError {
  if leaf_idx >= self.n_leaves || leaf_idx >= self.full_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let target = @treemath.leaf_to_node(leaf_idx)
  match self.node_secrets.get(target) {
    Some(s) => return s
    None => ()
  }
  let mut cur = @treemath.root(self.full_leaves)
  let path : Array[UInt32] = [cur]
  while cur != target {
    if target < cur {
      cur = match @treemath.left(cur) {
        Some(v) => v
        None => raise OutOfBounds(leaf_idx)
      }
    } else {
      cur = match @treemath.right(cur) {
        Some(v) => v
        None => raise OutOfBounds(leaf_idx)
      }
    }
    path.push(cur)
  }
  let mut start = -1
  for i = path.length() - 1; i >= 0; i = i - 1 {
    if self.node_secrets.contains(path[i]) {
      start = i
      break
    }
  }
  if start < 0 {
    // Leaf secret was already consumed and erased for forward secrecy
    raise ReplayDetected(0U)
  }
  let nh = self.cs.secret_len()
  for i = start; i < path.length() - 1; i = i + 1 {
    let node_idx = path[i]
    let parent_secret = match self.node_secrets.get(node_idx) {
      Some(s) => s
      None => raise ReplayDetected(0U)
    }
    let l_idx = match @treemath.left(node_idx) {
      Some(v) => v
      None => raise OutOfBounds(leaf_idx)
    }
    let r_idx = match @treemath.right(node_idx) {
      Some(v) => v
      None => raise OutOfBounds(leaf_idx)
    }
    let left_secret = self.cs.expand_with_label(
      parent_secret, "tree", b"left", nh,
    ) catch {
      e => raise CsError(e)
    }
    let right_secret = self.cs.expand_with_label(
      parent_secret, "tree", b"right", nh,
    ) catch {
      e => raise CsError(e)
    }
    self.node_secrets.set(l_idx, left_secret)
    self.node_secrets.set(r_idx, right_secret)
    // Immediately erase the split parent secret for forward secrecy
    self.node_secrets.remove(node_idx)
  }
  match self.node_secrets.get(target) {
    Some(s) => s
    None => raise ReplayDetected(0U)
  }
}

///|
/// Derives the RFC 9420 §9.1 secret for `leaf_idx` by splitting down from the
/// lowest available ancestor using `ExpandWithLabel(node_secret, "tree", "left" / "right", Nh)`.
pub fn SecretTree::leaf_secret(
  self : SecretTree,
  leaf_idx : UInt32,
) -> Bytes raise TreeError {
  self.split_to_leaf(leaf_idx)
}

///|
/// Initializes both handshake and application ratchets for `leaf_idx` on first
/// access and immediately deletes `leaf_secret` from `node_secrets` (RFC 9420 §9.2).
fn SecretTree::ensure_leaf_ratchets(
  self : SecretTree,
  leaf_idx : UInt32,
) -> Unit raise TreeError {
  if leaf_idx >= self.n_leaves || leaf_idx >= self.full_leaves {
    raise OutOfBounds(leaf_idx)
  }
  if self.handshake_ratchets.contains(leaf_idx) &&
    self.application_ratchets.contains(leaf_idx) {
    return
  }
  let ls = self.split_to_leaf(leaf_idx)
  let nh = self.cs.secret_len()
  let hs_init = self.cs.expand_with_label(ls, "handshake", b"", nh) catch {
    e => raise CsError(e)
  }
  let app_init = self.cs.expand_with_label(ls, "application", b"", nh) catch {
    e => raise CsError(e)
  }
  // Immediately delete the leaf secret once both ratchets are seeded
  self.node_secrets.remove(@treemath.leaf_to_node(leaf_idx))
  self.handshake_ratchets.set(leaf_idx, GenerationRatchet::new(hs_init))
  self.application_ratchets.set(leaf_idx, GenerationRatchet::new(app_init))
}

///|
fn SecretTree::get_or_init_handshake_ratchet(
  self : SecretTree,
  leaf_idx : UInt32,
) -> GenerationRatchet raise TreeError {
  self.ensure_leaf_ratchets(leaf_idx)
  match self.handshake_ratchets.get(leaf_idx) {
    Some(r) => r
    None => raise OutOfBounds(leaf_idx)
  }
}

///|
fn SecretTree::get_or_init_application_ratchet(
  self : SecretTree,
  leaf_idx : UInt32,
) -> GenerationRatchet raise TreeError {
  self.ensure_leaf_ratchets(leaf_idx)
  match self.application_ratchets.get(leaf_idx) {
    Some(r) => r
    None => raise OutOfBounds(leaf_idx)
  }
}

///|
/// O(1) non-mutating ratchet staging for receiver-side message processing.
/// Immediately rejects replayed (`ReplayDetected`) or excessive forward-jump
/// (`GenerationTooFarAhead`) generations without advancing the live ratchet.
/// Call `commit_stage` after message authentication/verification succeeds.
pub fn SecretTree::stage_key_nonce(
  self : SecretTree,
  leaf_idx : UInt32,
  generation : UInt32,
  is_application : Bool,
) -> RatchetStage raise TreeError {
  if leaf_idx >= self.n_leaves || leaf_idx >= self.full_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let has_ratchet = if is_application {
    self.application_ratchets.contains(leaf_idx)
  } else {
    self.handshake_ratchets.contains(leaf_idx)
  }
  if !has_ratchet && generation > self.max_forward_distance {
    raise GenerationTooFarAhead(generation)
  }
  let live = if is_application {
    self.get_or_init_application_ratchet(leaf_idx)
  } else {
    self.get_or_init_handshake_ratchet(leaf_idx)
  }
  let staged = live.clone()
  let (key, nonce) = staged.get_for_generation(
    self.cs,
    generation,
    self.out_of_order_tolerance,
    self.max_forward_distance,
  )
  { leaf_idx, is_application, next_ratchet: staged, key, nonce, }
}

///|
/// Atomically commits a previously staged single-leaf ratchet transition.
pub fn SecretTree::commit_stage(
  self : SecretTree,
  stage : RatchetStage,
) -> Unit {
  if stage.is_application {
    self.application_ratchets.set(stage.leaf_idx, stage.next_ratchet)
  } else {
    self.handshake_ratchets.set(stage.leaf_idx, stage.next_ratchet)
  }
}

///|
/// Sender-side handshake ratchet: returns `(generation, key, nonce)` for
/// `leaf_idx` and immediately advances the ratchet, deleting the old secret.
pub fn SecretTree::next_handshake_key_nonce(
  self : SecretTree,
  leaf_idx : UInt32,
) -> (UInt32, Bytes, Bytes) raise TreeError {
  let r = self.get_or_init_handshake_ratchet(leaf_idx)
  r.next(self.cs)
}

///|
/// Sender-side application ratchet: returns `(generation, key, nonce)` for
/// `leaf_idx` and immediately advances the ratchet, deleting the old secret.
pub fn SecretTree::next_application_key_nonce(
  self : SecretTree,
  leaf_idx : UInt32,
) -> (UInt32, Bytes, Bytes) raise TreeError {
  let r = self.get_or_init_application_ratchet(leaf_idx)
  r.next(self.cs)
}

///|
/// Receiver-side handshake ratchet: returns `(key, nonce)` for `(leaf_idx, generation)`
/// with out-of-order tolerance and single-use forward secrecy.
/// Raises `ReplayDetected` if `generation` was already consumed or fell behind
/// the window, and `GenerationTooFarAhead` if it jumps past `max_forward_distance`.
pub fn SecretTree::handshake_key_nonce_for_generation(
  self : SecretTree,
  leaf_idx : UInt32,
  generation : UInt32,
) -> (Bytes, Bytes) raise TreeError {
  let r = self.get_or_init_handshake_ratchet(leaf_idx)
  r.get_for_generation(
    self.cs,
    generation,
    self.out_of_order_tolerance,
    self.max_forward_distance,
  )
}

///|
/// Receiver-side application ratchet: returns `(key, nonce)` for `(leaf_idx, generation)`
/// with out-of-order tolerance and single-use forward secrecy.
/// Raises `ReplayDetected` if `generation` was already consumed or fell behind
/// the window, and `GenerationTooFarAhead` if it jumps past `max_forward_distance`.
pub fn SecretTree::application_key_nonce_for_generation(
  self : SecretTree,
  leaf_idx : UInt32,
  generation : UInt32,
) -> (Bytes, Bytes) raise TreeError {
  let r = self.get_or_init_application_ratchet(leaf_idx)
  r.get_for_generation(
    self.cs,
    generation,
    self.out_of_order_tolerance,
    self.max_forward_distance,
  )
}
