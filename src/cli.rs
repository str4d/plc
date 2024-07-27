use clap::{Args, Parser, Subcommand};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Parser)]
pub(crate) struct Options {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    #[command(subcommand)]
    Auth(Auth),
    List(List),
}

/// Manage authentication
#[derive(Debug, Subcommand)]
pub(crate) enum Auth {
    Login(Login),
}

/// Log in a user
#[derive(Debug, Args, ZeroizeOnDrop)]
pub(crate) struct Login {
    pub(crate) user: String,
    pub(crate) app_password: String,
}

/// Lists keys for a user
#[derive(Debug, Args)]
pub(crate) struct List {
    pub(crate) user: String,
}
