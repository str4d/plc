use std::sync::Arc;

use atrium_api::{
    agent::{store::MemorySessionStore, AtpAgent},
    types::string::Did,
};
use atrium_xrpc_client::reqwest::ReqwestClient;

use crate::{error::Error, local};

pub(crate) struct Agent {
    inner: Arc<AtpAgent<MemorySessionStore, ReqwestClient>>,
}

impl Agent {
    pub(crate) fn new(endpoint: String) -> Self {
        let agent = AtpAgent::new(ReqwestClient::new(endpoint), MemorySessionStore::default());

        Self {
            inner: Arc::new(agent),
        }
    }

    pub(crate) async fn login(&self, user: &str, password: &str) -> Result<(), Error> {
        self.inner
            .login(user, password)
            .await
            .map_err(Error::PdsAuthFailed)?;

        if let Some(session) = local::Session::current(&self.inner).await {
            session.save().await?;
        }

        Ok(())
    }

    pub(crate) async fn resume_session(&self, did: &Did) -> Result<(), Error> {
        let session = local::Session::load().await.ok_or(Error::NeedToLogIn)?;
        session.resume(&self.inner, did).await
    }
}
