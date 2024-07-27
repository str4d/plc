use std::path::{Path, PathBuf};

use atrium_api::{
    agent::{store::MemorySessionStore, AtpAgent},
    types::string::Did,
};
use atrium_xrpc_client::reqwest::ReqwestClient;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::error::Error;

const APP_DIR: &str = "plc";
const SESSION_FILE: &str = "session.json";

pub(crate) fn config_file<P: AsRef<Path>>(filename: P) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use known_folders::{get_known_folder_path, KnownFolder};
        let base = get_known_folder_path(KnownFolder::LocalAppData)?.join(APP_DIR);
        std::fs::create_dir_all(&base).ok()?;
        Some(base.join(filename))
    }

    #[cfg(any(unix, target_os = "redox"))]
    {
        xdg::BaseDirectories::with_prefix(APP_DIR)
            .ok()?
            .place_config_file(filename)
            .ok()
    }
}

/// A session with a PDS.
#[derive(Serialize, Deserialize)]
pub(crate) struct Session {
    /// The endpoint with which we have a session.
    endpoint: String,
    /// The active session.
    session: atrium_api::agent::Session,
}

impl Session {
    /// Fetches the current session from the given agent, if any.
    pub(crate) async fn current(
        agent: &AtpAgent<MemorySessionStore, ReqwestClient>,
    ) -> Option<Self> {
        let endpoint = agent.get_endpoint().await;
        agent
            .get_session()
            .await
            .map(|session| Self { endpoint, session })
    }

    /// Loads the current session from disk.
    ///
    /// Returns `None` if there is no valid session stored on disk (that can be read).
    pub(crate) async fn load() -> Option<Self> {
        let session_file = config_file(SESSION_FILE)?;
        let session_data = fs::read_to_string(session_file).await.ok()?;
        serde_json::from_str(&session_data).ok()
    }

    /// Saves the session to disk.
    ///
    /// Returns an error if the session cannot be stored on disk.
    pub(crate) async fn save(&self) -> Result<(), Error> {
        let session_file = config_file(SESSION_FILE).ok_or(Error::SessionSaveFailed)?;
        let session_data =
            serde_json::to_string_pretty(self).map_err(|_| Error::SessionSaveFailed)?;
        fs::write(session_file, session_data)
            .await
            .map_err(|_| Error::SessionSaveFailed)
    }

    /// Resumes the given session.
    pub(crate) async fn resume(
        mut self,
        agent: &AtpAgent<MemorySessionStore, ReqwestClient>,
        did: &Did,
    ) -> Result<(), Error> {
        if did != &self.session.did {
            Err(Error::LoggedIntoDifferentAccount(self.session.data.handle))
        } else if agent.get_endpoint().await != self.endpoint {
            Err(Error::NeedToLogInAgain)
        } else {
            agent
                .resume_session(self.session.clone())
                .await
                .map_err(|_| Error::NeedToLogInAgain)?;

            // We resumed the session; refresh and update it to prolong its existence.
            let refreshed = agent
                .api
                .com
                .atproto
                .server
                .refresh_session()
                .await
                .map_err(Error::PdsAuthRefreshFailed)?;

            assert_eq!(self.session.did, refreshed.data.did);

            self.session.access_jwt = refreshed.data.access_jwt;
            self.session.active = refreshed.data.active;
            self.session.did_doc = refreshed.data.did_doc;
            self.session.handle = refreshed.data.handle;
            self.session.refresh_jwt = refreshed.data.refresh_jwt;
            self.session.status = refreshed.data.status;

            // Save the updated session.
            self.save().await
        }
    }
}
