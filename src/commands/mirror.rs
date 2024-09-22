use std::{
    thread,
    time::{Duration, Instant},
};

use tokio::sync::oneshot;
use tracing::{debug, error, info};

use crate::{
    cli::{AuditMirror, RunMirror},
    mirror,
    remote::plc::{self, AuditLog},
};

impl RunMirror {
    pub(crate) async fn run(self) -> anyhow::Result<()> {
        tracing_subscriber::fmt::init();

        let client = reqwest::Client::builder()
            .user_agent("plc mirror")
            .build()?;

        // Open the database, initializing it if necessary.
        let db_handle = mirror::Db::open(&self.sqlite_db, false).await?;

        // Get the most recent entry in the database.
        let mut after = db_handle.get_last_created().await?;

        // Spawn the importer.
        let db = db_handle.clone();
        tokio::spawn(async move {
            loop {
                let imported = match plc::export(after.as_ref(), &client).await {
                    Err(e) => {
                        error!("Failed to export entries from PLC registry: {:?}", e);
                        0
                    }
                    Ok(entries) => match db.import(entries).await {
                        Ok(None) => 0,
                        Ok(Some((last_created_at, imported))) => {
                            after = Some(last_created_at);
                            imported
                        }
                        Err(e) => {
                            error!("Failed to import entries: {}", e);
                            break;
                        }
                    },
                };

                if imported < 1000 {
                    // We've caught up.
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        });

        if let Some(addr) = self.listen {
            // Spawn the server.
            let db = db_handle.clone();
            tokio::spawn(async move {
                if let Err(e) = mirror::serve(db, addr).await {
                    error!("Mirror server exited with an error: {e}")
                }
            });
        }

        // Wait for exit.
        tokio::signal::ctrl_c().await?;

        info!("Shutting down PLC mirror");
        db_handle.close().await?;

        Ok(())
    }
}

impl AuditMirror {
    pub(crate) async fn run(self) -> anyhow::Result<()> {
        tracing_subscriber::fmt::init();

        let chunks = thread::available_parallelism()?.get();

        let (finished_tx, finished_rx) = oneshot::channel();

        // Open the database.
        let db_handle = mirror::Db::open(&self.sqlite_db, true).await?;

        // Spawn the auditor.
        let db = db_handle.clone();
        tokio::spawn(async move {
            let mut progress_report_time = Instant::now();

            let mut auditing = vec![];
            let mut total_audited = 0;
            let mut after = None;
            loop {
                let total_dids = match db.total_dids().await {
                    Ok(total_dids) => total_dids,
                    Err(e) => {
                        error!("Failed to count DIDs: {e}");
                        return;
                    }
                };

                while auditing.len() < chunks {
                    match db.list_dids(10_000, after).await {
                        Ok(dids) if dids.is_empty() => break,
                        Ok(dids) => {
                            after = Some(dids.last().as_ref().expect("non-empty").0);

                            let db = db.clone();
                            auditing.push(tokio::spawn(async move {
                                let audited = dids.len();
                                for (id, did) in dids {
                                    match db.get_audit_log(did.clone()).await {
                                        Ok(entries) => {
                                            let audit_log = AuditLog::new(did.clone(), entries);

                                            match audit_log.validate() {
                                                Ok(()) => {
                                                    debug!(
                                                        "[{id}] Audit log for {} is valid!",
                                                        did.as_ref()
                                                    )
                                                }
                                                Err(errors) => {
                                                    error!(
                                                        "[{id}] Audit log for {} is invalid:",
                                                        did.as_ref()
                                                    );
                                                    for e in errors {
                                                        error!("- {}", e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e)
                                            if e.to_string()
                                                == "connection to sqlite database closed" =>
                                        {
                                            return None;
                                        }
                                        Err(e) => error!(
                                            "[{id}] Failed to get audit log for {}: {e}",
                                            did.as_ref()
                                        ),
                                    }
                                }
                                Some(audited)
                            }));
                        }
                        Err(e) if e.to_string() == "connection to sqlite database closed" => {
                            return;
                        }
                        Err(e) => {
                            error!("Failed to list DIDs after {:?}: {e}", after);
                            return;
                        }
                    }
                }

                if auditing.is_empty() {
                    info!("Finished auditing mirror");
                    let _ = finished_tx.send(());
                    return;
                }

                let (res, _, remaining) = futures_util::future::select_all(auditing).await;
                if let Ok(Some(audited)) = res {
                    total_audited += audited;
                }
                auditing = remaining;

                if Instant::now() >= progress_report_time {
                    let progress = (total_audited * 100) as f64 / total_dids as f64;
                    info!(
                        "Audit progress: {:0.1}% ({total_audited}/{total_dids})",
                        progress,
                    );
                    progress_report_time += Duration::from_secs(60);
                }
            }
        });

        // Wait for exit.
        tokio::select! {
            _ = finished_rx => (),
            _ = tokio::signal::ctrl_c() => (),
        }

        db_handle.close().await?;

        Ok(())
    }
}
