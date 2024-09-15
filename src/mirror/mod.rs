use atrium_api::types::string::Datetime;
use serde::Deserialize;

mod api;
pub(crate) use api::serve;

mod db;
pub(crate) use db::Db;

#[derive(Debug, Deserialize)]
pub(crate) struct ExportParams {
    count: Option<usize>,
    after: Option<Datetime>,
}

impl ExportParams {
    fn bounded_count(&self) -> usize {
        self.count.unwrap_or(10).min(1000)
    }
}
