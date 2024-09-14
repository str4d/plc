use crate::{
    cli::ListOps,
    data::{PlcData, State},
    error::Error,
    remote::plc,
};

impl ListOps {
    pub(crate) async fn run(&self) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let state = State::resolve(&self.user, &client).await?;

        let log = plc::get_ops_log(state.did(), &client).await?;

        let print_state = |data: &PlcData| {
            println!("- Rotation keys:");
            for (i, key) in data.rotation_keys.iter().enumerate() {
                println!("  - [{i}] {key}");
            }
            println!("- Verification methods:");
            for (id, value) in &data.verification_methods {
                println!("  - {id}: {value}");
            }
            println!("- Also-known-as:");
            for (i, aka) in data.also_known_as.iter().enumerate() {
                println!("  - [{i}] {aka}");
            }
            println!("- Services:");
            for (id, service) in &data.services {
                println!("  - {id}: {} = {}", service.r#type, service.endpoint);
            }
        };

        println!("Account {}", state.did().as_str());
        println!();
        println!("Initial state:");
        print_state(&log.create);

        for (i, update) in log.updates.iter().enumerate() {
            println!();
            println!("Update {}:", i + 1);

            for rkey in &update.rotation_keys.0 {
                match rkey {
                    diff::VecDiffType::Inserted { index, changes } => {
                        if *index == 0 {
                            println!("- Inserted before rotation key [{index}]:");
                        } else {
                            println!("- Inserted after rotation key [{}]:", index - 1);
                        }
                        for change in changes.iter().flatten() {
                            println!("  - {change}");
                        }
                    }
                    diff::VecDiffType::Altered { index, changes } => {
                        for (i, change) in changes.iter().enumerate() {
                            if let Some(value) = change {
                                println!("- Changed rotation key [{}] to {}", index + i, value);
                            }
                        }
                    }
                    diff::VecDiffType::Removed { index, len } => {
                        for i in *index..(index + len) {
                            println!("- Removed rotation key [{i}]");
                        }
                    }
                }
            }

            for (key, change) in &update.verification_methods.altered {
                if let Some(value) = change {
                    println!("- Changed verification method {key} to {value}");
                }
            }
            for key in &update.verification_methods.removed {
                println!("- Removed verification method {key}");
            }

            for aka in &update.also_known_as.0 {
                match aka {
                    diff::VecDiffType::Inserted { index, changes } => {
                        if *index == 0 {
                            println!("- Inserted before Also-known-as[{index}]:");
                        } else {
                            println!("- Inserted after Also-known-as[{}]:", index - 1);
                        }
                        for change in changes.iter().flatten() {
                            println!("  - {change}");
                        }
                    }
                    diff::VecDiffType::Altered { index, changes } => {
                        for (i, change) in changes.iter().enumerate() {
                            if let Some(value) = change {
                                println!("- Changed Also-known-as[{}] to {}", index + i, value);
                            }
                        }
                    }
                    diff::VecDiffType::Removed { index, len } => {
                        for i in *index..(index + len) {
                            println!("- Removed Also-known-as[{i}]");
                        }
                    }
                }
            }

            for (id, change) in &update.services.altered {
                if let Some(value) = &change.r#type {
                    println!("- Changed service {id} type to {value}");
                }
                if let Some(value) = &change.endpoint {
                    println!("- Changed service {id} endpoint to {value}");
                }
            }
            for id in &update.services.removed {
                println!("- Removed service {id}");
            }
        }

        println!();
        if log.deactivated {
            println!("Current state: Deactivated");
        } else {
            println!("Current state:");
            print_state(state.inner_data());
        }

        Ok(())
    }
}
