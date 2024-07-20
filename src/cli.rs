use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
pub(crate) struct Options {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    List(List),
}

/// Lists keys for a user
#[derive(Debug, Args)]
pub(crate) struct List {
    pub(crate) user: String,
}
