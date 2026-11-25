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
/// RFC 9420 §9 Secret Tree with per-leaf handshake & application generation
/// ratchets and forward-secure out-of-order replay protection windows.
pub struct SecretTree {
  priv cs : @cs.CipherSuite
  priv encryption_secret : Bytes
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
  {
    cs,
    encryption_secret,
    n_leaves,
    full_leaves: next_power_of_two(n_leaves),
    out_of_order_tolerance,
    max_forward_distance,
    handshake_ratchets: Map([]),
    application_ratchets: Map([]),
  }
}

///|
/// Derives the RFC 9420 §9.1 secret for `leaf_idx` by walking from the root
/// `encryption_secret` down left/right child edges using
/// `ExpandWithLabel(node_secret, "tree", "left" / "right", Nh)`.
pub fn SecretTree::leaf_secret(
  self : SecretTree,
  leaf_idx : UInt32,
) -> Bytes raise TreeError {
  if leaf_idx >= self.n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  let target = @treemath.leaf_to_node(leaf_idx)
  let mut cur = @treemath.root(self.full_leaves)
  let mut secret = self.encryption_secret
  let nh = self.cs.secret_len()
  while cur != target {
    if target < cur {
      secret = self.cs.expand_with_label(secret, "tree", b"left", nh) catch {
        e => raise CsError(e)
      }
      cur = match @treemath.left(cur) {
        Some(v) => v
        None => raise OutOfBounds(leaf_idx)
      }
    } else {
      secret = self.cs.expand_with_label(secret, "tree", b"right", nh) catch {
        e => raise CsError(e)
      }
      cur = match @treemath.right(cur) {
        Some(v) => v
        None => raise OutOfBounds(leaf_idx)
      }
    }
  }
  secret
}

///|
fn SecretTree::get_or_init_handshake_ratchet(
  self : SecretTree,
  leaf_idx : UInt32,
) -> GenerationRatchet raise TreeError {
  if leaf_idx >= self.n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  match self.handshake_ratchets.get(leaf_idx) {
    Some(r) => r
    None => {
      let ls = self.leaf_secret(leaf_idx)
      let init = self.cs.expand_with_label(
        ls,
        "handshake",
        b"",
        self.cs.secret_len(),
      ) catch {
        e => raise CsError(e)
      }
      let r = GenerationRatchet::new(init)
      self.handshake_ratchets.set(leaf_idx, r)
      r
    }
  }
}

///|
fn SecretTree::get_or_init_application_ratchet(
  self : SecretTree,
  leaf_idx : UInt32,
) -> GenerationRatchet raise TreeError {
  if leaf_idx >= self.n_leaves {
    raise OutOfBounds(leaf_idx)
  }
  match self.application_ratchets.get(leaf_idx) {
    Some(r) => r
    None => {
      let ls = self.leaf_secret(leaf_idx)
      let init = self.cs.expand_with_label(
        ls,
        "application",
        b"",
        self.cs.secret_len(),
      ) catch {
        e => raise CsError(e)
      }
      let r = GenerationRatchet::new(init)
      self.application_ratchets.set(leaf_idx, r)
      r
    }
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
