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
const MAX_LEAVES : UInt32 = 0x40000000U

///|
/// Converts a 0-based leaf index to its node index (`2 * leaf_index`).
/// Saturates to `0xFFFFFFFEU` if `leaf_index >= MAX_LEAVES` to prevent overflow.
pub fn leaf_to_node(leaf_index : UInt32) -> UInt32 {
  if leaf_index >= MAX_LEAVES {
    0xFFFFFFFEU
  } else {
    leaf_index << 1
  }
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
/// Returns `0U` if `n_leaves == 0U` or `n_leaves > MAX_LEAVES`.
pub fn node_width(n_leaves : UInt32) -> UInt32 {
  if n_leaves == 0U || n_leaves > MAX_LEAVES {
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
fn parent_step(x : UInt32) -> UInt32? {
  let k = level(x)
  if k >= 31U {
    return None
  }
  let b = (x >> (k + 1U).reinterpret_as_int()) & 1U
  Some(
    (x | (1U << k.reinterpret_as_int())) ^ (b << (k + 1U).reinterpret_as_int()),
  )
}

///|
/// Returns the immediate parent of node `x` in a tree with `n_leaves` leaves,
/// or `None` if `x` is the root (or out of bounds).
pub fn parent(x : UInt32, n_leaves : UInt32) -> UInt32? {
  if n_leaves == 0U || n_leaves > MAX_LEAVES {
    return None
  }
  let w = node_width(n_leaves)
  if x >= w || x == root(n_leaves) {
    return None
  }
  let mut p = match parent_step(x) {
    Some(next) => next
    None => return None
  }
  let mut steps = 0U
  while p >= w {
    if steps >= 32U {
      return None
    }
    match parent_step(p) {
      Some(next) => {
        p = next
        steps += 1U
      }
      None => return None
    }
  }
  Some(p)
}

///|
/// Returns the sibling of node `x` in a tree with `n_leaves` leaves, or `None`
/// if `x` is the root (or out of bounds).
pub fn sibling(x : UInt32, n_leaves : UInt32) -> UInt32? {
  if n_leaves == 0U || n_leaves > MAX_LEAVES {
    return None
  }
  match parent(x, n_leaves) {
    None => None
    Some(p) =>
      if x < p {
        let w = node_width(n_leaves)
        match right(p) {
          None => None
          Some(r0) => {
            let mut r = r0
            let mut steps = 0U
            while r >= w {
              if steps >= 32U {
                return None
              }
              match left(r) {
                Some(l) => {
                  r = l
                  steps += 1U
                }
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
  if n_leaves == 0U || n_leaves > MAX_LEAVES {
    return path
  }
  let mut cur = x
  let mut steps = 0U
  while steps < 32U {
    match parent(cur, n_leaves) {
      Some(p) => {
        if p == cur {
          break
        }
        path.push(p)
        cur = p
        steps += 1U
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
  if n_leaves == 0U || n_leaves > MAX_LEAVES {
    return out
  }
  let mut cur = x
  let mut steps = 0U
  while steps < 32U {
    match parent(cur, n_leaves) {
      Some(p) => {
        if p == cur {
          break
        }
        match sibling(cur, n_leaves) {
          Some(s) => out.push(s)
          None => ()
        }
        cur = p
        steps += 1U
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
fn safe_shl(v : UInt32, shift : UInt32) -> UInt32 {
  if shift >= 32U {
    0U
  } else {
    v << shift.reinterpret_as_int()
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
  safe_shl(xn, k) + (1U << (k - 1U).reinterpret_as_int()) - 1U
}

///|
/// Returns the inclusive `(min_leaf, max_leaf)` leaf index range covered by
/// the subtree rooted at node `x`.
pub fn subtree_range(x : UInt32) -> (UInt32, UInt32) {
  let k = level(x)
  if k >= 32U {
    return (0U, 0xFFFFFFFFU)
  }
  let min_leaf = safe_shr(x, k + 1U) << k.reinterpret_as_int()
  let max_leaf = min_leaf + (1U << k.reinterpret_as_int()) - 1U
  (min_leaf, max_leaf)
}
