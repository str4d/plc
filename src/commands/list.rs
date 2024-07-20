use crate::{cli::List, data::State, error::Error};

impl List {
    pub(crate) async fn run(&self) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let state = State::resolve(&self.user, &client).await?;

        let pds = state.endpoint().ok_or(Error::DidDocumentHasNoPds)?;

        println!("Account {}", state.did().as_str());
        if let Some(handle) = state.handle() {
            println!("- Primary handle: @{}", handle);
        } else {
            println!("- Invalid handle");
        }
        println!("- PDS: {}", pds);

        let signing_keys = state.signing_keys();
        println!("- {} signing keys:", signing_keys.len());
        for res in &signing_keys {
            match res {
                Ok(k) => {
                    println!(
                        "  - Unknown ({:?}): {}",
                        k.algorithm,
                        hex::encode(&k.public_key)
                    );
                }
                Err(e) => println!("  - Invalid: {}", e),
            }
        }

        let rotation_keys = state.rotation_keys();
        println!("- {} rotation keys:", rotation_keys.len());
        for (i, res) in rotation_keys.iter().enumerate() {
            match res {
                Ok(k) => {
                    println!(
                        "  - [{}] Unknown ({:?}): {}",
                        i,
                        k.algorithm,
                        hex::encode(&k.public_key),
                    );
                }
                Err(e) => println!("  - [{}] Invalid: {}", i, e),
            }
        }

        Ok(())
    }
}
