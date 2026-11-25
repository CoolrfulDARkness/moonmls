///|
/// Errors raised by RFC 9420 §8 Key Schedule, Transcript Hash, and §6 Message
/// Protection operations.
#derive(Eq, Debug)
pub(all) suberror ScheduleError {
  CsError(@cs.CsError)
  TlsError(@tls.TlsError)
  CryptoError(@crypto.CryptoError)
  InvalidSignature
  InvalidMembershipTag
  InvalidConfirmationTag
  MissingMembershipKey
  MissingGroupContext
  InvalidReuseGuard
  DecryptionFailed
  InvalidWireFormat
  UnexpectedContentType
}

///|
pub impl Show for ScheduleError with output(self, logger) {
  match self {
    CsError(err) => {
      logger.write_string("CsError(")
      Show::output(err, logger)
      logger.write_string(")")
    }
    TlsError(err) => {
      logger.write_string("TlsError(")
      Show::output(err, logger)
      logger.write_string(")")
    }
    CryptoError(err) => {
      logger.write_string("CryptoError(")
      Show::output(err, logger)
      logger.write_string(")")
    }
    InvalidSignature => logger.write_string("InvalidSignature")
    InvalidMembershipTag => logger.write_string("InvalidMembershipTag")
    InvalidConfirmationTag => logger.write_string("InvalidConfirmationTag")
    MissingMembershipKey => logger.write_string("MissingMembershipKey")
    MissingGroupContext => logger.write_string("MissingGroupContext")
    InvalidReuseGuard => logger.write_string("InvalidReuseGuard")
    DecryptionFailed => logger.write_string("DecryptionFailed")
    InvalidWireFormat => logger.write_string("InvalidWireFormat")
    UnexpectedContentType => logger.write_string("UnexpectedContentType")
  }
}

///|
fn map_cs_error(err : @cs.CsError) -> ScheduleError {
  match err {
    @cs.DecryptionFailed => DecryptionFailed
    other => CsError(other)
  }
}
