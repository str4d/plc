use std::time::Duration;

use tracing::{error, info};

use crate::{cli::RunMirror, mirror, remote::plc};

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
