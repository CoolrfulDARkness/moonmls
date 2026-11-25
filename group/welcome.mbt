///|
/// Verified output of decrypting and authenticating an MLS `Welcome` message
/// (RFC 9420 §12.4.3.1), usable even when no external `RatchetTree` is provided.
#derive(Eq, Debug)
pub(all) struct WelcomeVerification {
  group_info : @types.GroupInfo
  group_secrets : @types.GroupSecrets
  secrets : @schedule.EpochSecrets
}

///|
/// Decrypts `GroupSecrets` and `GroupInfo` from a `Welcome` message without yet
/// verifying `GroupInfo` signature or `confirmation_tag`.
fn decrypt_welcome_payload(
  cs : @cs.CipherSuite,
  welcome : @types.Welcome,
  init_priv : Bytes,
  kp : @types.KeyPackage,
) -> (@types.GroupSecrets, @types.GroupInfo, Bytes) raise GroupError {
  if welcome.cipher_suite != cs.id() {
    raise CipherSuiteMismatch
  }
  let kp_bytes = kp.to_bytes() catch { e => raise TlsError(e) }
  let kp_ref = cs.make_key_package_ref(kp_bytes) catch { e => raise CsError(e) }
  let mut matched : @types.EncryptedGroupSecrets? = None
  for i = 0; i < welcome.secrets.length(); i = i + 1 {
    if welcome.secrets[i].new_member == kp_ref {
      matched = Some(welcome.secrets[i])
      break
    }
  }
  let egs = match matched {
    Some(e) => e
    None => raise WelcomeKeyPackageNotFound
  }
  let gs_bytes = cs.decrypt_with_label(
    init_priv,
    "Welcome",
    welcome.encrypted_group_info,
    egs.encrypted_group_secrets.kem_output,
    egs.encrypted_group_secrets.ciphertext,
  ) catch {
    e => raise CsError(e)
  }
  let group_secrets = @types.GroupSecrets::from_bytes(gs_bytes) catch {
    e => raise TlsError(e)
  }
  if group_secrets.psks.length() > 0 {
    raise InvalidCommit("PSKs in Welcome are not supported")
  }
  let psk_secret = cs.zero_secret()
  let welcome_secret = @schedule.derive_welcome_secret(
    cs,
    group_secrets.joiner_secret,
    psk_secret,
  ) catch {
    e => raise ScheduleError(e)
  }
  let (welcome_key, welcome_nonce) = @schedule.derive_welcome_key_nonce(
    cs, welcome_secret,
  ) catch {
    e => raise ScheduleError(e)
  }
  let gi_bytes = cs.aead_open(
    welcome_key,
    welcome_nonce,
    b"",
    welcome.encrypted_group_info,
  ) catch {
    e => raise CsError(e)
  }
  let group_info = @types.GroupInfo::from_bytes(gi_bytes) catch {
    e => raise TlsError(e)
  }
  if group_info.group_context.version != @types.PROTOCOL_VERSION_MLS10 {
    raise UnsupportedProtocolVersion(group_info.group_context.version)
  }
  if group_info.group_context.cipher_suite != cs.id() {
    raise CipherSuiteMismatch
  }
  (group_secrets, group_info, psk_secret)
}

///|
/// Verifies and decrypts an MLS `Welcome` message against an explicit
/// `signer_pub` key per RFC 9420 §12.4.3.1:
/// 1. Computes `KeyPackageRef` and finds matching `EncryptedGroupSecrets`.
/// 2. Decrypts `GroupSecrets` using `DecryptWithLabel("Welcome", encrypted_group_info, ...)`.
/// 3. Derives `welcome_secret`, `welcome_key`, and `welcome_nonce`.
/// 4. Decrypts `GroupInfo` and verifies its `"GroupInfoTBS"` signature using `signer_pub`.
/// 5. Derives `EpochSecrets` via `derive_epoch_secrets_from_joiner`.
/// 6. Verifies `GroupInfo.confirmation_tag` in constant time.
pub fn verify_and_decrypt_welcome(
  cs : @cs.CipherSuite,
  welcome : @types.Welcome,
  init_priv : Bytes,
  kp : @types.KeyPackage,
  signer_pub : Bytes,
) -> WelcomeVerification raise GroupError {
  let (group_secrets, group_info, psk_secret) = decrypt_welcome_payload(
    cs, welcome, init_priv, kp,
  )
  let gi_tbs = group_info.encode_tbs() catch { e => raise TlsError(e) }
  if !cs.verify_with_label(
      signer_pub,
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
  { group_info, group_secrets, secrets }
}
