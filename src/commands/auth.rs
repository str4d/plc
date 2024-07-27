use crate::{cli::Login, data::State, error::Error, remote::pds};

impl Login {
    pub(crate) async fn run(&self) -> Result<(), Error> {
        // Fetch the user's current state.
        let client = reqwest::Client::new();
        let state = State::resolve(&self.user, &client).await?;

        // Get the endpoint we will log into.
        let endpoint = state.endpoint().ok_or(Error::DidDocumentHasNoPds)?;

        let agent = pds::Agent::new(endpoint.into());
        agent.login(&self.user, &self.app_password).await?;

        println!("Logged in as @{}", state.handle().unwrap_or(&self.user));

        Ok(())
    }
}
