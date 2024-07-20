use atrium_api::types::string::Did;
use hickory_resolver::TokioAsyncResolver;
use reqwest::{header::CONTENT_TYPE, Client};

use crate::error::Error;

/// Resolves the DID for the given handle, if any.
pub(crate) async fn resolve(handle: &str, client: &Client) -> Result<Did, Error> {
    if let Some(did) = resolve_dns_txt(handle).await {
        Ok(did)
    } else if let Some(did) = resolve_https_well_known(handle, client).await {
        Ok(did)
    } else {
        // Neither resolution method worked.
        Err(Error::HandleResolutionFailed)
    }
}

/// DNS TXT resolution method.
///
/// https://atproto.com/specs/handle#dns-txt-method
async fn resolve_dns_txt(handle: &str) -> Option<Did> {
    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());
    let resp = resolver
        .txt_lookup(format!("_atproto.{}.", handle))
        .await
        .ok()?;

    let mut records = resp
        .into_iter()
        .map(|r| r.to_string())
        // Any TXT records with values not starting with `did=` should be ignored.
        .filter_map(|r| {
            r.strip_prefix("did=")
                .and_then(|did| did.parse::<Did>().ok())
        });

    // Only a single valid record should exist at any point in time. If multiple valid
    // records with different DIDs are present, resolution should fail.
    match (records.next(), records.next()) {
        (Some(did), None) => Some(did),
        _ => None,
    }
}

/// HTTPS well-known resolution method.
///
/// https://atproto.com/specs/handle#https-well-known-method
async fn resolve_https_well_known(handle: &str, client: &Client) -> Option<Did> {
    match client
        .get(format!("https://{}/.well-known/atproto-did", handle))
        .send()
        .await
    {
        Ok(resp)
            if resp.status().is_success()
                && resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .map(|v| v.as_bytes().starts_with(b"text/plain"))
                    .unwrap_or(false) =>
        {
            resp.text().await.ok().and_then(|s| s.parse().ok())
        }
        _ => None,
    }
}
