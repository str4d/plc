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
    #[cfg(feature = "mirror")]
    #[command(subcommand)]
    Mirror(Mirror),
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
    Audit(AuditOps),
}

/// Lists operations for a user's DID.
#[derive(Debug, Args)]
pub(crate) struct ListOps {
    pub(crate) user: String,
}

/// Audit operations for a user's DID.
#[derive(Debug, Args)]
pub(crate) struct AuditOps {
    pub(crate) user: String,
}

/// Operate a mirror of the PLC registry.
#[cfg(feature = "mirror")]
#[derive(Debug, Subcommand)]
pub(crate) enum Mirror {
    Run(RunMirror),
    Audit(AuditMirror),
}

/// Runs a mirror of the PLC registry.
#[cfg(feature = "mirror")]
#[derive(Debug, Args)]
pub(crate) struct RunMirror {
    pub(crate) sqlite_db: String,

    /// If provided, the mirror will expose the same API as plc.directory on this address.
    #[arg(short, long)]
    pub(crate) listen: Option<String>,
}

/// Audits the contents of the given PLC registry mirror.
#[cfg(feature = "mirror")]
#[derive(Debug, Args)]
pub(crate) struct AuditMirror {
    pub(crate) sqlite_db: String,
}
