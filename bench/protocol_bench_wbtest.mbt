///|
fn make_bench_leaf(cs : @cs.CipherSuite, idx : Int32) -> @types.LeafNode {
  let enc_key = make_pattern_bytes(32, 100 + idx)
  let sig_key = make_pattern_bytes(32, 200 + idx)
  let id_bytes = make_pattern_bytes(16, 300 + idx)
  let sig = make_pattern_bytes(64, 400 + idx)
  let caps : @types.Capabilities = {
    versions: [@types.PROTOCOL_VERSION_MLS10],
    cipher_suites: [cs.id()],
    extensions: [],
    proposals: [],
    credentials: [@types.CREDENTIAL_TYPE_BASIC],
  }
  {
    encryption_key: enc_key,
    signature_key: sig_key,
    credential: @types.Credential::Basic(id_bytes),
    capabilities: caps,
    leaf_node_source: @types.LeafNodeSource::KeyPackage,
    lifetime: Some({ not_before: 0UL, not_after: 9999999999UL, }),
    parent_hash: None,
    extensions: [],
    signature: sig,
  }
}

///|
test "hpke seal+open base (CS1 AES-128-GCM, 64B)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let ikm = make_pattern_bytes(32, 21)
  let (sk_r, pk_r) = cs.kem_keypair_from_ikm(ikm) catch {
    e => abort(Show::to_string(e))
  }
  let info = b"moonmls-hpke-bench-cs1"
  let aad = b"moonmls-aad"
  let pt = make_pattern_bytes(64, 22)
  let rng = @crypto.DeterministicRng::from_seed(make_pattern_bytes(32, 23))
  b.bench(name="hpke seal+open base (CS1 AES-128-GCM, 64B)", fn() {
    let out = try {
      let (enc, ct) = @cs.hpke_seal_base(cs, pk_r, info, aad, pt, rng)
      @cs.hpke_open_base(cs, enc, sk_r, info, aad, ct)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(out)
  })
}

///|
test "hpke seal+open base (CS3 ChaCha20-Poly1305, 64B)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519ChaCha20Poly1305Sha256Ed25519
  let ikm = make_pattern_bytes(32, 24)
  let (sk_r, pk_r) = cs.kem_keypair_from_ikm(ikm) catch {
    e => abort(Show::to_string(e))
  }
  let info = b"moonmls-hpke-bench-cs3"
  let aad = b"moonmls-aad"
  let pt = make_pattern_bytes(64, 25)
  let rng = @crypto.DeterministicRng::from_seed(make_pattern_bytes(32, 26))
  b.bench(name="hpke seal+open base (CS3 ChaCha20-Poly1305, 64B)", fn() {
    let out = try {
      let (enc, ct) = @cs.hpke_seal_base(cs, pk_r, info, aad, pt, rng)
      @cs.hpke_open_base(cs, enc, sk_r, info, aad, ct)
    } catch {
      e => abort(Show::to_string(e))
    }
    b.keep(out)
  })
}

///|
test "treemath direct_path + copath (1024 leaves)" (b : @bench.T) {
  let n_leaves = 1024U
  let leaf_node = @treemath.leaf_to_node(511U)
  b.bench(name="treemath direct_path + copath (1024 leaves)", fn() {
    let dp = @treemath.direct_path(leaf_node, n_leaves)
    let cp = @treemath.copath(leaf_node, n_leaves)
    b.keep((dp, cp))
  })
}

///|
test "ratchet_tree tree_hash (32 leaves)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let rt = @tree.RatchetTreeState::new(make_bench_leaf(cs, 0))
  for i = 1; i < 32; i = i + 1 {
    let _ = rt.add_leaf(make_bench_leaf(cs, i)) catch {
      e => abort(Show::to_string(e))
    }
  }
  b.bench(name="ratchet_tree tree_hash (32 leaves)", fn() {
    let h = rt.tree_hash(cs) catch { e => abort(Show::to_string(e)) }
    b.keep(h)
  })
}

///|
test "epoch key_schedule derive (CS1)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let prev_init = make_pattern_bytes(32, 31)
  let commit_secret = make_pattern_bytes(32, 32)
  let psk_secret = cs.zero_secret()
  let gc : @types.GroupContext = {
    version: @types.PROTOCOL_VERSION_MLS10,
    cipher_suite: cs.id(),
    group_id: make_pattern_bytes(16, 33),
    epoch: 42UL,
    tree_hash: make_pattern_bytes(32, 34),
    confirmed_transcript_hash: make_pattern_bytes(32, 35),
    extensions: [],
  }
  let w = @tls.Writer::new()
  gc.encode(w) catch {
    e => abort(Show::to_string(e))
  }
  let gc_bytes = w.to_bytes()
  b.bench(name="epoch key_schedule derive (CS1)", fn() {
    let secrets = @schedule.derive_epoch_secrets(
      cs, prev_init, commit_secret, psk_secret, gc_bytes,
    ) catch {
      e => abort(Show::to_string(e))
    }
    b.keep(secrets)
  })
}

///|
test "secret_tree application key_nonce derive (32 leaves)" (b : @bench.T) {
  let cs = @cs.CipherSuite::X25519Aes128GcmSha256Ed25519
  let enc_secret = make_pattern_bytes(32, 41)
  b.bench(name="secret_tree application key_nonce derive (32 leaves)", fn() {
    let st = @tree.SecretTree::new(cs, enc_secret, 32U)
    let kn = st.next_application_key_nonce(15U) catch {
      e => abort(Show::to_string(e))
    }
    b.keep(kn)
  })
}
