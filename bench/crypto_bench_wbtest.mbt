///|
fn make_pattern_bytes(len : Int, salt : Int) -> Bytes {
  Bytes::makei(len, fn(i) { ((i * 31 + salt * 17 + 7) & 0xFF).to_byte() })
}

///|
test "sha256 (1 KiB)" (b : @bench.T) {
  let msg = make_pattern_bytes(1024, 1)
  b.bench(name="sha256 (1 KiB)", fn() { b.keep(@crypto.sha256(msg)) })
}

///|
test "aes128_gcm seal+open (1 KiB)" (b : @bench.T) {
  let key = make_pattern_bytes(16, 2)
  let nonce = make_pattern_bytes(12, 3)
  let aad = make_pattern_bytes(32, 4)
  let pt = make_pattern_bytes(1024, 5)
  b.bench(name="aes128_gcm seal+open (1 KiB)", fn() {
    let out = try {
      let ct = @crypto.aes128_gcm_seal(key, nonce, aad, pt)
      @crypto.aes128_gcm_open(key, nonce, aad, ct)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(out)
  })
}

///|
test "chacha20_poly1305 seal+open (1 KiB)" (b : @bench.T) {
  let key = make_pattern_bytes(32, 6)
  let nonce = make_pattern_bytes(12, 7)
  let aad = make_pattern_bytes(32, 8)
  let pt = make_pattern_bytes(1024, 9)
  b.bench(name="chacha20_poly1305 seal+open (1 KiB)", fn() {
    let out = try {
      let ct = @crypto.chacha20_poly1305_seal(key, nonce, aad, pt)
      @crypto.chacha20_poly1305_open(key, nonce, aad, ct)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(out)
  })
}

///|
test "x25519 scalar_mult" (b : @bench.T) {
  let sk_a = make_pattern_bytes(32, 10)
  let sk_b = make_pattern_bytes(32, 11)
  let pk_b = try @crypto.x25519_public_key(sk_b) catch {
    e => abort(Show::to_string(e))
  }
  b.bench(name="x25519 scalar_mult", fn() {
    let shared = try @crypto.x25519_dh(sk_a, pk_b) catch {
      e => abort(Show::to_string(e))
    }
    b.keep(shared)
  })
}

///|
test "ed25519 sign (64B msg)" (b : @bench.T) {
  let seed = make_pattern_bytes(32, 12)
  let msg = make_pattern_bytes(64, 13)
  b.bench(name="ed25519 sign (64B msg)", fn() {
    let sig = try @crypto.ed25519_sign(seed, msg) catch {
      e => abort(Show::to_string(e))
    }
    b.keep(sig)
  })
}

///|
test "ed25519 verify (64B msg)" (b : @bench.T) {
  let seed = make_pattern_bytes(32, 14)
  let msg = make_pattern_bytes(64, 15)
  let pk = try @crypto.ed25519_public_key(seed) catch {
    e => abort(Show::to_string(e))
  }
  let sig = try @crypto.ed25519_sign(seed, msg) catch {
    e => abort(Show::to_string(e))
  }
  b.bench(name="ed25519 verify (64B msg)", fn() {
    let ok = @crypto.ed25519_verify(pk, msg, sig)
    if !ok {
      abort("ed25519 verify failed")
    }
    b.keep(ok)
  })
}
