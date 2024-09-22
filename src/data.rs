use std::collections::HashMap;

use atrium_api::types::string::Did;
use atrium_crypto::Algorithm;
use diff::Diff;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    remote::{handle, plc},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    did: Did,
    #[serde(flatten)]
    plc: PlcData,
}

#[derive(Clone, Debug, Serialize, Deserialize, Diff)]
#[diff(attr(
    #[derive(Debug)]
))]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlcData {
    pub(crate) rotation_keys: Vec<String>,
    pub(crate) verification_methods: HashMap<String, String>,
    pub(crate) also_known_as: Vec<String>,
    pub(crate) services: HashMap<String, Service>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Diff)]
#[diff(attr(
    #[derive(Debug)]
))]
#[serde(rename_all = "camelCase")]
pub(crate) struct Service {
    pub(crate) r#type: String,
    pub(crate) endpoint: String,
}

impl State {
    pub(crate) async fn resolve(user: &str, client: &Client) -> Result<Self, Error> {
        // Parse `user` as a DID, or look it up as a handle.
        let did = match Did::new(user.into()) {
            Ok(did) => did,
            Err(_) => handle::resolve(user, client).await?,
        };

        // Fetch the current DID state.
        let state = match did.method() {
            "did:plc" => plc::get_state(&did, client).await,
            method => Err(Error::UnsupportedDidMethod(method.into())),
        }?;

        // If we were given a handle, check it bidirectionally.
        if user != did.as_str() && Some(user) != state.handle() {
            return Err(Error::HandleInvalid);
        }

        Ok(state)
    }

    pub(crate) fn did(&self) -> &Did {
        &self.did
    }

    pub(crate) fn inner_data(&self) -> &PlcData {
        &self.plc
    }

    /// Returns the current primary handle for this DID.
    pub(crate) fn handle(&self) -> Option<&str> {
        self.plc.also_known_as.iter().find_map(|uri| {
            uri.strip_prefix("at://")
                .map(|s| s.split_once('/').map(|(handle, _)| handle).unwrap_or(s))
        })
    }

    pub(crate) fn signing_key(&self) -> Option<atrium_crypto::Result<Key>> {
        // Ignore non-ATProto verification methods.
        self.plc.verification_methods.get("atproto").map(Key::did)
    }

    pub(crate) fn rotation_keys(&self) -> Vec<atrium_crypto::Result<Key>> {
        self.plc.rotation_keys.iter().map(Key::did).collect()
    }

    /// Returns the endpoint for the user's currently-configured PDS.
    pub(crate) fn endpoint(&self) -> Option<&str> {
        self.plc
            .services
            .get("atproto_pds")
            .and_then(|v| (v.r#type == "AtprotoPersonalDataServer").then_some(v.endpoint.as_str()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) algorithm: Algorithm,
    pub(crate) public_key: Vec<u8>,
}

impl Key {
    pub(crate) fn did<K: AsRef<str>>(key: K) -> atrium_crypto::Result<Self> {
        atrium_crypto::did::parse_did_key(key.as_ref()).map(|(algorithm, public_key)| Self {
            algorithm,
            public_key,
        })
    }
}
