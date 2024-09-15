use std::fmt;

use anyhow::anyhow;
use atrium_api::{did_doc::DidDocument, types::string::Did};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, Response},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use bytes::{BufMut, BytesMut};
use reqwest::{header, StatusCode};
use serde::Serialize;
use tokio::net::TcpListener;

use super::{Db, ExportParams};
use crate::remote::plc::{LogEntry, SignedOperation};

pub(crate) async fn serve(db: Db, addr: String) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/:did", get(resolve_did))
        .route("/:did/log", get(get_plc_op_log))
        .route("/:did/log/audit", get(get_plc_audit_log))
        .route("/:did/log/last", get(get_last_op))
        .route("/:did/data", get(get_plc_data))
        .route("/export", get(export))
        .with_state(db);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn resolve_did(Path(did): Path<Did>, State(db): State<Db>) -> impl IntoResponse {
    let mut status = StatusCode::OK;

    let mut response = Json(PlcResult::from(
        db.get_last_active_entry(did.clone())
            .await
            .and_then(|entry| {
                entry
                    .ok_or_else(|| {
                        status = StatusCode::NOT_FOUND;
                        anyhow!("DID not registered: {}", did.as_ref())
                    })?
                    .into_state()
                    .ok_or_else(|| {
                        status = StatusCode::GONE;
                        anyhow!("DID not available: {}", did.as_ref())
                    })
            })
            .and_then(|state| {
                state.into_doc().map(DidDocWithContext::new).map_err(|()| {
                    anyhow!(
                        "Verification methods for DID are corrupted: {}",
                        did.as_ref()
                    )
                })
            }),
    ))
    .into_response();

    *response.status_mut() = status;
    *response
        .headers_mut()
        .get_mut(header::CONTENT_TYPE)
        .expect("Json sets this") = HeaderValue::from_static("application/did+ld+json");

    response
}

async fn get_plc_op_log(
    Path(did): Path<Did>,
    State(db): State<Db>,
) -> (StatusCode, Json<PlcResult<Vec<SignedOperation>>>) {
    let mut status = StatusCode::OK;

    let response = Json(
        db.get_audit_log(did.clone())
            .await
            .and_then(|entries| {
                if entries.is_empty() {
                    status = StatusCode::NOT_FOUND;
                    Err(anyhow!("DID not registered: {}", did.as_ref()))
                } else {
                    Ok(entries.into_iter().map(|entry| entry.operation).collect())
                }
            })
            .into(),
    );

    (status, response)
}

async fn get_plc_audit_log(
    Path(did): Path<Did>,
    State(db): State<Db>,
) -> (StatusCode, Json<PlcResult<Vec<LogEntry>>>) {
    let mut status = StatusCode::OK;

    let response = Json(
        db.get_audit_log(did.clone())
            .await
            .and_then(|entries| {
                if entries.is_empty() {
                    status = StatusCode::NOT_FOUND;
                    Err(anyhow!("DID not registered: {}", did.as_ref()))
                } else {
                    Ok(entries)
                }
            })
            .into(),
    );

    (status, response)
}

async fn get_last_op(
    Path(did): Path<Did>,
    State(db): State<Db>,
) -> (StatusCode, Json<PlcResult<SignedOperation>>) {
    let mut status = StatusCode::OK;

    let response = Json(
        db.get_last_active_entry(did.clone())
            .await
            .and_then(|entry| {
                entry.ok_or_else(|| {
                    status = StatusCode::NOT_FOUND;
                    anyhow!("DID not registered: {}", did.as_ref())
                })
            })
            .map(|entry| entry.operation)
            .into(),
    );

    (status, response)
}

async fn get_plc_data(
    Path(did): Path<Did>,
    State(db): State<Db>,
) -> (StatusCode, Json<PlcResult<crate::data::State>>) {
    let mut status = StatusCode::OK;

    let response = Json(
        db.get_last_active_entry(did.clone())
            .await
            .and_then(|entry| {
                entry
                    .ok_or_else(|| {
                        status = StatusCode::NOT_FOUND;
                        anyhow!("DID not registered: {}", did.as_ref())
                    })?
                    .into_state()
                    .ok_or_else(|| {
                        status = StatusCode::GONE;
                        anyhow!("DID not available: {}", did.as_ref())
                    })
            })
            .into(),
    );

    (status, response)
}

async fn export(Query(params): Query<ExportParams>, State(db): State<Db>) -> JsonLines<LogEntry> {
    JsonLines(PlcResult::from(db.export(params).await))
}

#[derive(Serialize)]
struct DidDocWithContext {
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(flatten)]
    doc: DidDocument,
}

impl DidDocWithContext {
    fn new(doc: DidDocument) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://w3id.org/security/multikey/v1".into(),
                "https://w3id.org/security/suites/secp256k1-2019/v1".into(),
            ],
            doc,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum PlcResult<T> {
    Ok(T),
    Err { message: String },
}

impl<T, E: fmt::Display> From<Result<T, E>> for PlcResult<T> {
    fn from(value: Result<T, E>) -> Self {
        match value {
            Ok(v) => PlcResult::Ok(v),
            Err(e) => PlcResult::Err {
                message: e.to_string(),
            },
        }
    }
}

struct JsonLines<T>(PlcResult<Vec<T>>);

impl<T> IntoResponse for JsonLines<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response<axum::body::Body> {
        let write_output = |items: Vec<_>| -> std::io::Result<_> {
            // Use a small initial capacity of 128 bytes like serde_json::to_vec
            // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
            let mut buf = BytesMut::with_capacity(128).writer();
            let mut writer = serde_jsonlines::JsonLinesWriter::new(&mut buf);
            writer.write_all(&items)?;
            writer.flush()?;
            Ok(buf)
        };

        match self.0 {
            PlcResult::Ok(items) => match write_output(items) {
                Ok(buf) => (
                    [(
                        header::CONTENT_TYPE,
                        // This is not specified anywhere, but it's what plc.directory uses.
                        HeaderValue::from_static("application/jsonlines"),
                    )],
                    buf.into_inner().freeze(),
                )
                    .into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
                    )],
                    err.to_string(),
                )
                    .into_response(),
            },
            err => (StatusCode::INTERNAL_SERVER_ERROR, Json(err)).into_response(),
        }
    }
}
