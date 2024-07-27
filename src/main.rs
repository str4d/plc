use clap::Parser;

mod cli;
mod commands;
mod data;
mod error;
mod local;
mod remote;

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    let opts = cli::Options::parse();

    match opts.command {
        cli::Command::Auth(cli::Auth::Login(command)) => command.run().await,
        cli::Command::List(command) => command.run().await,
    }
}
