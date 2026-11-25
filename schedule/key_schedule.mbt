///|
/// All secrets derived for a single MLS epoch (RFC 9420 §8).
#derive(Eq, Debug)
pub(all) struct EpochSecrets {
  joiner_secret : Bytes
  welcome_secret : Bytes
  epoch_secret : Bytes
  sender_data_secret : Bytes
  encryption_secret : Bytes
  exporter_secret : Bytes
  external_secret : Bytes
  confirmation_key : Bytes
  membership_key : Bytes
  resumption_psk : Bytes
  epoch_authenticator : Bytes
  init_secret : Bytes
  external_priv : Bytes
  external_pub : Bytes
}

///|
/// Computes the combined `psk_secret` from an ordered list of `(PreSharedKeyID, psk)`
/// pairs (RFC 9420 §8.4).
///
/// If `psks` is empty, returns `cs.zero_secret()` (`0^Nh`).
pub fn compute_psk_secret(
  cs : @cs.CipherSuite,
  psks : Array[(@types.PreSharedKeyId, Bytes)],
) -> Bytes raise ScheduleError {
  let count = psks.length()
  let zero = cs.zero_secret()
  if count == 0 {
    return zero
  }
  if count > 0xFFFF {
    raise TlsError(@tls.TlsError::LengthMismatch)
  }
  let nh = cs.secret_len()
  let mut psk_secret = zero
  for i = 0; i < count; i = i + 1 {
    let (id, psk) = psks[i]
    let psk_extracted = cs.extract(zero, psk)
    let w = @tls.Writer::new()
    try {
      id.encode(w)
      w.write_u16(i.reinterpret_as_uint())
      w.write_u16(count.reinterpret_as_uint())
    } catch {
      e => raise TlsError(e)
    }
    let psk_label_bytes = w.to_bytes()
    let psk_input = cs.expand_with_label(
      psk_extracted, "derived psk", psk_label_bytes, nh,
    ) catch {
      e => raise map_cs_error(e)
    }
    psk_secret = cs.extract(psk_input, psk_secret)
  }
  psk_secret
}

///|
/// Derives `joiner_secret` from the previous epoch's `init_secret`,
/// `commit_secret`, and the serialized new `GroupContext` (RFC 9420 §8).
pub fn derive_joiner_secret(
  cs : @cs.CipherSuite,
  prev_init_secret : Bytes,
  commit_secret : Bytes,
  group_context_bytes : Bytes,
) -> Bytes raise ScheduleError {
  let intermediate = cs.extract(prev_init_secret, commit_secret)
  cs.expand_with_label(
    intermediate,
    "joiner",
    group_context_bytes,
    cs.secret_len(),
  ) catch {
    e => raise map_cs_error(e)
  }
}

///|
/// Derives `welcome_secret` from `joiner_secret` and `psk_secret` (RFC 9420 §8).
pub fn derive_welcome_secret(
  cs : @cs.CipherSuite,
  joiner_secret : Bytes,
  psk_secret : Bytes,
) -> Bytes raise ScheduleError {
  let member_secret = cs.extract(joiner_secret, psk_secret)
  cs.derive_secret(member_secret, "welcome") catch {
    e => raise map_cs_error(e)
  }
}

///|
/// Derives `(welcome_key, welcome_nonce)` from `welcome_secret` (RFC 9420 §12.4.3.1).
pub fn derive_welcome_key_nonce(
  cs : @cs.CipherSuite,
  welcome_secret : Bytes,
) -> (Bytes, Bytes) raise ScheduleError {
  let key = cs.expand_with_label(welcome_secret, "key", b"", cs.aead_key_len()) catch {
    e => raise map_cs_error(e)
  }
  let nonce = cs.expand_with_label(
    welcome_secret,
    "nonce",
    b"",
    cs.aead_nonce_len(),
  ) catch {
    e => raise map_cs_error(e)
  }
  (key, nonce)
}

///|
/// Derives the complete set of epoch secrets starting from `joiner_secret`,
/// `psk_secret`, and serialized `GroupContext` (RFC 9420 §8 & §8.3).
pub fn derive_epoch_secrets_from_joiner(
  cs : @cs.CipherSuite,
  joiner_secret : Bytes,
  psk_secret : Bytes,
  group_context_bytes : Bytes,
) -> EpochSecrets raise ScheduleError {
  let member_secret = cs.extract(joiner_secret, psk_secret)
  let welcome_secret = cs.derive_secret(member_secret, "welcome") catch {
    e => raise map_cs_error(e)
  }
  let epoch_secret = cs.expand_with_label(
    member_secret,
    "epoch",
    group_context_bytes,
    cs.secret_len(),
  ) catch {
    e => raise map_cs_error(e)
  }
  let sender_data_secret = cs.derive_secret(epoch_secret, "sender data") catch {
    e => raise map_cs_error(e)
  }
  let encryption_secret = cs.derive_secret(epoch_secret, "encryption") catch {
    e => raise map_cs_error(e)
  }
  let exporter_secret = cs.derive_secret(epoch_secret, "exporter") catch {
    e => raise map_cs_error(e)
  }
  let external_secret = cs.derive_secret(epoch_secret, "external") catch {
    e => raise map_cs_error(e)
  }
  let confirmation_key = cs.derive_secret(epoch_secret, "confirm") catch {
    e => raise map_cs_error(e)
  }
  let membership_key = cs.derive_secret(epoch_secret, "membership") catch {
    e => raise map_cs_error(e)
  }
  let resumption_psk = cs.derive_secret(epoch_secret, "resumption") catch {
    e => raise map_cs_error(e)
  }
  let epoch_authenticator = cs.derive_secret(epoch_secret, "authentication") catch {
    e => raise map_cs_error(e)
  }
  let init_secret = cs.derive_secret(epoch_secret, "init") catch {
    e => raise map_cs_error(e)
  }
  let (external_priv, external_pub) = cs.kem_keypair_from_ikm(external_secret) catch {
    e => raise map_cs_error(e)
  }
  {
    joiner_secret,
    welcome_secret,
    epoch_secret,
    sender_data_secret,
    encryption_secret,
    exporter_secret,
    external_secret,
    confirmation_key,
    membership_key,
    resumption_psk,
    epoch_authenticator,
    init_secret,
    external_priv,
    external_pub,
  }
}

///|
/// Derives the complete set of epoch secrets for a new epoch from
/// `prev_init_secret`, `commit_secret`, `psk_secret`, and serialized
/// `GroupContext` (RFC 9420 §8).
pub fn derive_epoch_secrets(
  cs : @cs.CipherSuite,
  prev_init_secret : Bytes,
  commit_secret : Bytes,
  psk_secret : Bytes,
  group_context_bytes : Bytes,
) -> EpochSecrets raise ScheduleError {
  let joiner_secret = derive_joiner_secret(
    cs, prev_init_secret, commit_secret, group_context_bytes,
  )
  derive_epoch_secrets_from_joiner(
    cs, joiner_secret, psk_secret, group_context_bytes,
  )
}

///|
/// Derives an application-specific secret via `MLS-Exporter` (RFC 9420 §8.5).
///
/// `MLS-Exporter(Label, Context, Length) = ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)`.
pub fn mls_exporter(
  cs : @cs.CipherSuite,
  exporter_secret : Bytes,
  label : String,
  context : Bytes,
  length : Int32,
) -> Bytes raise ScheduleError {
  let derived = cs.derive_secret(exporter_secret, label) catch {
    e => raise map_cs_error(e)
  }
  let context_hash = cs.hash(context)
  cs.expand_with_label(derived, "exported", context_hash, length) catch {
    e => raise map_cs_error(e)
  }
}
