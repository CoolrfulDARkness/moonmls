///|
/// Returns the exponent of the largest power of 2 less than or equal to `x`.
/// Returns `0U` when `x == 0U`.
pub fn log2(x : UInt32) -> UInt32 {
  if x == 0U {
    return 0U
  }
  let mut k = 0U
  let mut v = x
  while v > 1U {
    v = v >> 1
    k += 1U
  }
  k
}

///|
/// Returns the level of node `x` in the binary tree (0 for leaves, number of
/// trailing 1-bits in the binary representation of `x`).
pub fn level(x : UInt32) -> UInt32 {
  let mut k = 0U
  let mut v = x
  while (v & 1U) == 1U {
    v = v >> 1
    k += 1U
  }
  k
}

///|
/// Returns `true` if `x` is a leaf node (even node index).
pub fn is_leaf(x : UInt32) -> Bool {
  (x & 1U) == 0U
}

///|
/// Converts a 0-based leaf index to its node index (`2 * leaf_index`).
pub fn leaf_to_node(leaf_index : UInt32) -> UInt32 {
  leaf_index << 1
}

///|
/// Converts a node index to its 0-based leaf index if it is a leaf, or `None`
/// for internal nodes.
pub fn node_to_leaf(node_index : UInt32) -> UInt32? {
  if (node_index & 1U) == 0U {
    Some(node_index >> 1)
  } else {
    None
  }
}

///|
/// Returns the number of nodes needed to represent a tree with `n_leaves`
/// leaves (RFC 9420 Appendix C `node_width`).
pub fn node_width(n_leaves : UInt32) -> UInt32 {
  if n_leaves == 0U {
    0U
  } else {
    2U * (n_leaves - 1U) + 1U
  }
}

///|
/// Returns the number of leaves in a tree with `n_nodes` nodes.
pub fn leaf_count(n_nodes : UInt32) -> UInt32 {
  if n_nodes == 0U {
    0U
  } else {
    (n_nodes >> 1) + 1U
  }
}

///|
/// Returns the root node index of a tree with `n_leaves` leaves.
pub fn root(n_leaves : UInt32) -> UInt32 {
  let w = node_width(n_leaves)
  if w == 0U {
    return 0U
  }
  (1U << log2(w).reinterpret_as_int()) - 1U
}

///|
/// Returns the left child of an internal node `x`, or `None` if `x` is a leaf.
pub fn left(x : UInt32) -> UInt32? {
  let k = level(x)
  if k == 0U || k >= 32U {
    None
  } else {
    Some(x ^ (1U << (k - 1U).reinterpret_as_int()))
  }
}

///|
/// Returns the right child of an internal node `x`, or `None` if `x` is a leaf.
pub fn right(x : UInt32) -> UInt32? {
  let k = level(x)
  if k == 0U || k >= 32U {
    None
  } else {
    Some(x ^ (3U << (k - 1U).reinterpret_as_int()))
  }
}

///|
fn parent_step(x : UInt32) -> UInt32 {
  let k = level(x)
  let b = (x >> (k + 1U).reinterpret_as_int()) & 1U
  (x | (1U << k.reinterpret_as_int())) ^ (b << (k + 1U).reinterpret_as_int())
}

///|
/// Returns the immediate parent of node `x` in a tree with `n_leaves` leaves,
/// or `None` if `x` is the root (or out of bounds).
pub fn parent(x : UInt32, n_leaves : UInt32) -> UInt32? {
  if n_leaves == 0U {
    return None
  }
  let w = node_width(n_leaves)
  if x >= w || x == root(n_leaves) {
    return None
  }
  let mut p = parent_step(x)
  while p >= w {
    p = parent_step(p)
  }
  Some(p)
}

///|
/// Returns the sibling of node `x` in a tree with `n_leaves` leaves, or `None`
/// if `x` is the root (or out of bounds).
pub fn sibling(x : UInt32, n_leaves : UInt32) -> UInt32? {
  match parent(x, n_leaves) {
    None => None
    Some(p) =>
      if x < p {
        let w = node_width(n_leaves)
        match right(p) {
          None => None
          Some(r0) => {
            let mut r = r0
            while r >= w {
              match left(r) {
                Some(l) => r = l
                None => return None
              }
            }
            Some(r)
          }
        }
      } else {
        left(p)
      }
  }
}

///|
/// Returns the direct path of node `x` (from `parent(x)` up to and including
/// `root(n_leaves)`). Returns an empty array for the root or out-of-bounds nodes.
pub fn direct_path(x : UInt32, n_leaves : UInt32) -> Array[UInt32] {
  let path : Array[UInt32] = []
  let mut cur = x
  while true {
    match parent(cur, n_leaves) {
      Some(p) => {
        path.push(p)
        cur = p
      }
      None => break
    }
  }
  path
}

///|
/// Returns the copath of node `x`: the siblings of each node on the path from
/// `x` up to (but not including) the root.
pub fn copath(x : UInt32, n_leaves : UInt32) -> Array[UInt32] {
  let out : Array[UInt32] = []
  let mut cur = x
  while true {
    match parent(cur, n_leaves) {
      Some(p) => {
        match sibling(cur, n_leaves) {
          Some(s) => out.push(s)
          None => ()
        }
        cur = p
      }
      None => break
    }
  }
  out
}

///|
fn safe_shr(v : UInt32, shift : UInt32) -> UInt32 {
  if shift >= 32U {
    0U
  } else {
    v >> shift.reinterpret_as_int()
  }
}

///|
/// Returns the lowest common ancestor of nodes `x` and `y` in the infinite
/// full binary tree (RFC 9420 Appendix C `common_ancestor_semantic`).
pub fn common_ancestor(x : UInt32, y : UInt32) -> UInt32 {
  let lx = level(x) + 1U
  let ly = level(y) + 1U
  if lx <= ly && safe_shr(x, ly) == safe_shr(y, ly) {
    return y
  }
  if ly <= lx && safe_shr(x, lx) == safe_shr(y, lx) {
    return x
  }
  let mut xn = x
  let mut yn = y
  let mut k = 0U
  while xn != yn {
    xn = xn >> 1
    yn = yn >> 1
    k += 1U
  }
  (xn << k.reinterpret_as_int()) + (1U << (k - 1U).reinterpret_as_int()) - 1U
}

///|
/// Returns the inclusive `(min_leaf, max_leaf)` leaf index range covered by
/// the subtree rooted at node `x`.
pub fn subtree_range(x : UInt32) -> (UInt32, UInt32) {
  let k = level(x)
  let min_leaf = safe_shr(x, k + 1U) << k.reinterpret_as_int()
  let max_leaf = min_leaf + (1U << k.reinterpret_as_int()) - 1U
  (min_leaf, max_leaf)
}
