use std::fmt;

pub(crate) enum Error {
    DidDocumentHasNoPds,
    HandleInvalid,
    HandleResolutionFailed,
    PlcDirectoryRequestFailed,
    PlcDirectoryReturnedInvalidDidDocument,
    UnsupportedDidMethod(String),
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DidDocumentHasNoPds => write!(f, "The user's DID document doesn't contain a services entry for a PDS"),
            Error::HandleInvalid => write!(f, "The provided handle is invalid (it does not appear in the DID document it points to)"),
            Error::HandleResolutionFailed => write!(f, "Handle resolution failed"),
            Error::PlcDirectoryRequestFailed => {
                write!(f, "An error occurred while talking to plc.directory")
            }
            Error::PlcDirectoryReturnedInvalidDidDocument => {
                write!(f, "plc.directory returned an invalid DID document")
            }
            Error::UnsupportedDidMethod(method) => write!(f, "Unsupported DID method {}; this tool only works with did:plc identities", method),
        }
    }
}
