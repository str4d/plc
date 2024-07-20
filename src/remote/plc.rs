use atrium_api::types::string::Did;
use reqwest::Client;

use crate::{data::State, error::Error};

pub(crate) async fn get_state(did: &Did, client: &Client) -> Result<State, Error> {
    let resp = client
        .get(format!("https://plc.directory/{}/data", did.as_str()))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| Error::PlcDirectoryRequestFailed)?;

    resp.json::<State>()
        .await
        .map_err(|_| Error::PlcDirectoryReturnedInvalidDidDocument)
}
