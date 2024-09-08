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
    #[command(subcommand)]
    Ops(Ops),
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

/// Inspect operations for a DID.
#[derive(Debug, Subcommand)]
pub(crate) enum Ops {
    List(ListOps),
}

/// Lists operations for a user's DID.
#[derive(Debug, Args)]
pub(crate) struct ListOps {
    pub(crate) user: String,
}
