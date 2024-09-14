use std::env;

use snapbox::{
    assert::DEFAULT_ACTION_ENV,
    cmd::{cargo_bin, Command},
    dir::DirRoot,
    file, Assert, Redactions,
};

struct Plc {
    config_dir: DirRoot,
    config: Assert,
}

impl Plc {
    fn init(handle: &str) -> Self {
        let config_dir = DirRoot::mutable_temp().unwrap();

        let mut substitutions = Redactions::new();
        substitutions
            .insert("[HANDLE]", handle.to_string())
            .unwrap();

        let config = Assert::new()
            .action_env(DEFAULT_ACTION_ENV)
            .redact_with(substitutions);

        Self { config_dir, config }
    }

    fn run(&self) -> Command {
        let cmd = Command::new(cargo_bin!("plc")).with_assert(self.config.clone());

        #[cfg(windows)]
        {
            panic!("Test cannot be run on Windows")
        }

        #[cfg(any(unix, target_os = "redox"))]
        {
            cmd.env("XDG_CONFIG_HOME", self.config_dir.path().unwrap())
        }
    }
}

#[test]
fn end_to_end() {
    let account = match env::var("PLC_INTEGRATION_TEST_ACCOUNT") {
        Ok(account) => account,
        // Skip test if we aren't given a test account.
        Err(_) => return,
    };

    let (handle, app_password) = account.split_once('/').unwrap();

    let plc = Plc::init(handle);

    //
    // Phase 1: List existing keys.
    //

    // List keys while unauthenticated.
    plc.run()
        .args(["list", handle])
        .assert()
        .success()
        .stdout_eq(file!["integration-1-list-base-unauthed.stdout"]);

    // Authenticate.
    plc.run()
        .args(["auth", "login", handle, app_password])
        .assert()
        .success()
        .stdout_eq(file!["integration-1-auth.stdout"]);

    // List keys while authenticated.
    plc.run()
        .args(["list", handle])
        .assert()
        .success()
        .stdout_eq(file!["integration-1-list-base-authed.stdout"]);
}
