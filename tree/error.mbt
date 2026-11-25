///|
/// Errors raised by RFC 9420 Ratchet Tree, TreeKEM, and Secret Tree operations.
#derive(Eq, Debug)
pub(all) suberror TreeError {
  OutOfBounds(UInt32)
  EmptyTree
  InvalidTreeSize(Int32)
  BlankLeaf(UInt32)
  UnexpectedNodeType(UInt32)
  InvalidParentHash
  InvalidLeafSignature(UInt32)
  DuplicateKey
  InvalidUnmergedLeaf
  ReplayDetected(UInt32)
  GenerationTooFarAhead(UInt32)
  PathMismatch
  NoCommonAncestor
  CsError(@cs.CsError)
  TlsError(@tls.TlsError)
}

///|
pub impl Show for TreeError with fn output(self, logger) {
  match self {
    OutOfBounds(idx) => {
      logger.write_string("OutOfBounds(")
      Show::output(idx, logger)
      logger.write_string(")")
    }
    EmptyTree => logger.write_string("EmptyTree")
    InvalidTreeSize(size) => {
      logger.write_string("InvalidTreeSize(")
      Show::output(size, logger)
      logger.write_string(")")
    }
    BlankLeaf(idx) => {
      logger.write_string("BlankLeaf(")
      Show::output(idx, logger)
      logger.write_string(")")
    }
    UnexpectedNodeType(idx) => {
      logger.write_string("UnexpectedNodeType(")
      Show::output(idx, logger)
      logger.write_string(")")
    }
    InvalidParentHash => logger.write_string("InvalidParentHash")
    InvalidLeafSignature(idx) => {
      logger.write_string("InvalidLeafSignature(")
      Show::output(idx, logger)
      logger.write_string(")")
    }
    DuplicateKey => logger.write_string("DuplicateKey")
    InvalidUnmergedLeaf => logger.write_string("InvalidUnmergedLeaf")
    ReplayDetected(gen) => {
      logger.write_string("ReplayDetected(")
      Show::output(gen, logger)
      logger.write_string(")")
    }
    GenerationTooFarAhead(gen) => {
      logger.write_string("GenerationTooFarAhead(")
      Show::output(gen, logger)
      logger.write_string(")")
    }
    PathMismatch => logger.write_string("PathMismatch")
    NoCommonAncestor => logger.write_string("NoCommonAncestor")
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
  }
}
