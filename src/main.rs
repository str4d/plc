use clap::Parser;

mod cli;
mod commands;
mod data;
mod error;
mod local;
mod remote;
mod util;

#[cfg(feature = "mirror")]
mod mirror;

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    let opts = cli::Options::parse();

    match opts.command {
        cli::Command::Auth(cli::Auth::Login(command)) => command.run().await,
        cli::Command::Keys(cli::Keys::List(command)) => command.run().await,
        cli::Command::Ops(cli::Ops::List(command)) => command.run().await,
        cli::Command::Ops(cli::Ops::Audit(command)) => command.run().await,
        #[cfg(feature = "mirror")]
        cli::Command::Mirror(command) => match command {
            cli::Mirror::Run(command) => command.run().await,
            cli::Mirror::Audit(command) => command.run().await,
        }
        .map_err(error::Error::Mirror),
    }
}
