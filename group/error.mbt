///|
/// Errors raised by the RFC 9420 MLS group protocol engine.
#derive(Eq, Debug)
pub(all) suberror GroupError {
  TlsError(@tls.TlsError)
  CryptoError(@crypto.CryptoError)
  CsError(@cs.CsError)
  TreeError(@tree.TreeError)
  ScheduleError(@schedule.ScheduleError)
  InvalidKeyPackage(String)
  WelcomeKeyPackageNotFound
  MissingRatchetTree
  InvalidGroupInfoSignature
  TreeHashMismatch
  ConfirmationTagMismatch
  GroupIdMismatch
  EpochMismatch(UInt64, UInt64)
  UnknownSender(UInt)
  MemberRemoved
  InvalidProposal(String)
  InvalidCommit(String)
  MissingPrivateKey(UInt)
  CannotRemoveSelf
  UnsupportedProtocolVersion(UInt)
  CipherSuiteMismatch
}

///|
pub impl Show for GroupError with output(self, logger) {
  match self {
    TlsError(e) => {
      logger.write_string("TlsError(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    CryptoError(e) => {
      logger.write_string("CryptoError(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    CsError(e) => {
      logger.write_string("CsError(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    TreeError(e) => {
      logger.write_string("TreeError(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    ScheduleError(e) => {
      logger.write_string("ScheduleError(")
      Show::output(e, logger)
      logger.write_string(")")
    }
    InvalidKeyPackage(msg) => {
      logger.write_string("InvalidKeyPackage(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    WelcomeKeyPackageNotFound =>
      logger.write_string("WelcomeKeyPackageNotFound")
    MissingRatchetTree => logger.write_string("MissingRatchetTree")
    InvalidGroupInfoSignature =>
      logger.write_string("InvalidGroupInfoSignature")
    TreeHashMismatch => logger.write_string("TreeHashMismatch")
    ConfirmationTagMismatch => logger.write_string("ConfirmationTagMismatch")
    GroupIdMismatch => logger.write_string("GroupIdMismatch")
    EpochMismatch(expected, actual) => {
      logger.write_string("EpochMismatch(")
      Show::output(expected, logger)
      logger.write_string(", ")
      Show::output(actual, logger)
      logger.write_string(")")
    }
    UnknownSender(leaf) => {
      logger.write_string("UnknownSender(")
      Show::output(leaf, logger)
      logger.write_string(")")
    }
    MemberRemoved => logger.write_string("MemberRemoved")
    InvalidProposal(msg) => {
      logger.write_string("InvalidProposal(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    InvalidCommit(msg) => {
      logger.write_string("InvalidCommit(")
      logger.write_string(msg)
      logger.write_string(")")
    }
    MissingPrivateKey(node) => {
      logger.write_string("MissingPrivateKey(")
      Show::output(node, logger)
      logger.write_string(")")
    }
    CannotRemoveSelf => logger.write_string("CannotRemoveSelf")
    UnsupportedProtocolVersion(v) => {
      logger.write_string("UnsupportedProtocolVersion(")
      Show::output(v, logger)
      logger.write_string(")")
    }
    CipherSuiteMismatch => logger.write_string("CipherSuiteMismatch")
  }
}
