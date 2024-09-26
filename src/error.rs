use std::fmt;

use atrium_api::types::string::Handle;

pub(crate) enum Error {
    DidDocumentHasNoPds,
    HandleInvalid,
    HandleResolutionFailed,
    LoggedIntoDifferentAccount(Handle),
    NeedToLogIn,
    NeedToLogInAgain,
    PdsAuthFailed(atrium_xrpc::Error<atrium_api::com::atproto::server::create_session::Error>),
    PdsAuthRefreshFailed(
        atrium_xrpc::Error<atrium_api::com::atproto::server::refresh_session::Error>,
    ),
    PdsServerKeyLookupFailed(
        atrium_xrpc::Error<
            atrium_api::com::atproto::identity::get_recommended_did_credentials::Error,
        >,
    ),
    PlcDirectoryRequestFailed(reqwest::Error),
    PlcDirectoryReturnedInvalidAuditLog,
    PlcDirectoryReturnedInvalidDidDocument,
    PlcDirectoryReturnedInvalidOperationLog,
    SessionSaveFailed,
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
            Error::LoggedIntoDifferentAccount(handle) => write!(f, "Currently logged into {}", handle.as_str()),
            Error::NeedToLogIn => write!(f, "This operation requires authentication, please log in"),
            Error::NeedToLogInAgain => write!(f, "Session has expired, please log in again"),
            Error::PdsAuthFailed(e) => write!(f, "Failed to authenticate to PDS: {}", e),
            Error::PdsAuthRefreshFailed(e) => write!(f, "Failed to refresh PDS session: {}", e),
            Error::PdsServerKeyLookupFailed(e) => write!(f, "Lookup of PDS server keys failed: {}", e),
            Error::PlcDirectoryRequestFailed(e) => {
                write!(f, "An error occurred while talking to plc.directory: {e}")
            }
            Error::PlcDirectoryReturnedInvalidAuditLog => {
                write!(f, "plc.directory returned an invalid audit log")
            }
            Error::PlcDirectoryReturnedInvalidDidDocument => {
                write!(f, "plc.directory returned an invalid DID document")
            }
            Error::PlcDirectoryReturnedInvalidOperationLog => {
                write!(f, "plc.directory returned an invalid operation log")
            }
            Error::SessionSaveFailed => write!(f, "Failed to save PDS session data"),
            Error::UnsupportedDidMethod(method) => write!(f, "Unsupported DID method {}; this tool only works with did:plc identities", method),
        }
    }
}
