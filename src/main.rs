use clap::Parser;

mod cli;
mod commands;
mod data;
mod error;
mod remote;

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    let opts = cli::Options::parse();

    match opts.command {
        cli::Command::List(command) => command.run().await,
    }
}
