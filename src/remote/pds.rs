use std::collections::HashMap;
use std::sync::Arc;

use atrium_api::{
    agent::{store::MemorySessionStore, AtpAgent},
    types::{string::Did, TryFromUnknown},
};
use atrium_xrpc_client::reqwest::ReqwestClient;

use crate::{data::Key, error::Error, local};

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

    pub(crate) async fn get_recommended_server_keys(&self) -> Result<ServerKeys, Error> {
        let res = self
            .inner
            .api
            .com
            .atproto
            .identity
            .get_recommended_did_credentials()
            .await
            .map_err(Error::PdsServerKeyLookupFailed)?;

        let signing = res.data.verification_methods.and_then(|d| {
            HashMap::<String, String>::try_from_unknown(d)
                .map_err(ParseError::Data)
                .and_then(|m| {
                    m.get("atproto")
                        .map(|key| Key::did(&key).map_err(ParseError::Key))
                        .transpose()
                })
                .transpose()
        });

        let rotation = res
            .data
            .rotation_keys
            .into_iter()
            .flat_map(|keys| keys.into_iter().map(|key| Key::did(&key)))
            .collect();

        Ok(ServerKeys { signing, rotation })
    }
}

pub(crate) struct ServerKeys {
    signing: Option<Result<Key, ParseError>>,
    rotation: Vec<atrium_crypto::Result<Key>>,
}

impl ServerKeys {
    pub(crate) fn is_signing(&self, key: &Key) -> bool {
        matches!(&self.signing, Some(Ok(k)) if k == key)
    }

    pub(crate) fn contains_rotation(&self, key: &Key) -> bool {
        self.rotation
            .iter()
            .find(|i| matches!(i, Ok(k) if k == key))
            .is_some()
    }
}

pub(crate) enum ParseError {
    Data(atrium_api::error::Error),
    Key(atrium_crypto::Error),
}
