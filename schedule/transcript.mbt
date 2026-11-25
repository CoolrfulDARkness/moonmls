///|
/// Computes `confirmed_transcript_hash = Hash(interim_transcript_hash || ConfirmedTranscriptHashInput)`
/// (RFC 9420 §8.2).
///
/// Per RFC 9420 §8.2, `input.content` MUST be a `Commit`.
pub fn compute_confirmed_transcript_hash(
  cs : @cs.CipherSuite,
  interim_transcript_hash : Bytes,
  input : @types.ConfirmedTranscriptHashInput,
) -> Bytes raise ScheduleError {
  match input.content.content {
    Commit(_) => ()
    Application(_) | Proposal(_) => raise UnexpectedContentType
  }
  let encoded = input.to_bytes() catch { e => raise TlsError(e) }
  cs.hash(@tls.bytes_concat([interim_transcript_hash, encoded]))
}

///|
/// Computes `interim_transcript_hash = Hash(confirmed_transcript_hash || InterimTranscriptHashInput)`
/// (RFC 9420 §8.2), where `InterimTranscriptHashInput` encodes `opaque confirmation_tag<V>`.
pub fn compute_interim_transcript_hash(
  cs : @cs.CipherSuite,
  confirmed_transcript_hash : Bytes,
  confirmation_tag : Bytes,
) -> Bytes raise ScheduleError {
  let input : @types.InterimTranscriptHashInput = { confirmation_tag, }
  let encoded = input.to_bytes() catch { e => raise TlsError(e) }
  cs.hash(@tls.bytes_concat([confirmed_transcript_hash, encoded]))
}

///|
/// Computes `confirmation_tag = MAC(confirmation_key, confirmed_transcript_hash)`
/// (RFC 9420 §8.1).
pub fn compute_confirmation_tag(
  cs : @cs.CipherSuite,
  confirmation_key : Bytes,
  confirmed_transcript_hash : Bytes,
) -> Bytes {
  cs.mac(confirmation_key, confirmed_transcript_hash)
}

///|
/// Verifies `confirmation_tag` in constant time (RFC 9420 §8.1).
pub fn verify_confirmation_tag(
  cs : @cs.CipherSuite,
  confirmation_key : Bytes,
  confirmed_transcript_hash : Bytes,
  tag : Bytes,
) -> Bool {
  cs.verify_mac(confirmation_key, confirmed_transcript_hash, tag)
}

///|
/// Computes `membership_tag = MAC(membership_key, AuthenticatedContentTBM)`
/// (RFC 9420 §6.2).
pub fn compute_membership_tag(
  cs : @cs.CipherSuite,
  membership_key : Bytes,
  tbm : @types.AuthenticatedContentTbm,
) -> Bytes raise ScheduleError {
  let encoded = tbm.to_bytes() catch { e => raise TlsError(e) }
  cs.mac(membership_key, encoded)
}

///|
/// Verifies `membership_tag` in constant time (RFC 9420 §6.2).
pub fn verify_membership_tag(
  cs : @cs.CipherSuite,
  membership_key : Bytes,
  tbm : @types.AuthenticatedContentTbm,
  tag : Bytes,
) -> Bool {
  let encoded = tbm.to_bytes() catch { _ => return false }
  cs.verify_mac(membership_key, encoded, tag)
}
