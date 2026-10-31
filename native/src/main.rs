mod assets;
mod common;
mod credentials;
mod discovery;
mod gateway;
mod install;
mod intent;
mod onboarding;
mod protocol;
mod relay;
mod remote;
mod ssh;
mod ssh_config;
mod transport;
#[cfg(windows)]
mod windows_process;
#[cfg(windows)]
mod windows_security;
#[cfg(windows)]
mod windows_ipc;
#[cfg(windows)]
mod windows_credentials;

use common::{Error, Result};
use serde_json::{json, Value};
use std::io::Write;

fn emit(value: &Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, value);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}
async fn dispatch(args: &[String]) -> Result<Option<Value>> {
    match args.first().map(String::as_str) {
        Some("--version") if args.len() == 1 => Ok(Some(
            json!({"ok":true,"version":env!("CARGO_PKG_VERSION"),"runtime":"rust","os":std::env::consts::OS,"arch":std::env::consts::ARCH}),
        )),
        Some("runtime") if args.len() == 1 => Ok(Some(
            json!({"ok":true,"binary":std::env::current_exe().map_err(|_|Error::new("runtime-path","Cannot locate native executable."))?,"runtime_ready":true,"version":env!("CARGO_PKG_VERSION")}),
        )),
        Some("--help") if args.len() == 1 => Ok(Some(
            json!({"ok":true,"usage":"tern-turn-relay relay|onboarding|credentials|install|remote COMMAND [OPTIONS]","secrets":"Only hidden native input, private files or stdin; never arguments."}),
        )),
        Some("relay") => relay::run(&args[1..]).await.map(Some),
        Some("onboarding") => onboarding::run(&args[1..]).await.map(Some),
        Some("credentials") => credentials::run(&args[1..]).await.map(Some),
        Some("install") => install::run(&args[1..]).await.map(Some),
        Some("remote") if args.get(1).map(String::as_str) == Some("serve") => {
            remote::serve(&args[1..]).await.map(|_| None)
        }
        Some("remote") => remote::run(&args[1..]).await.map(Some),
        _ => Err(Error::with_exit(
            "invalid-request",
            "Unknown command; use --help. Argument values withheld.",
            2,
        )),
    }
}
fn main() {
    #[cfg(windows)]
    if let Err(error) = windows_process::prevent_stdio_inheritance() {
        emit(&json!({"ok":false,"code":error.code,"error":error.message,"exit_code":error.exit_code}));
        std::process::exit(error.exit_code);
    }
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    // Never expose request values or credentials through a panic hook.
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            emit(
                &json!({"ok":false,"code":"runtime-failed","error":"Cannot initialize native runtime."}),
            );
            std::process::exit(7)
        }
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(dispatch(&args))
    }));
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));
    let code = match result {
        Ok(Ok(Some(value))) => {
            let code = value.get("exit_code").and_then(Value::as_i64).unwrap_or(
                if value.get("ok") == Some(&Value::Bool(false)) {
                    1
                } else {
                    0
                },
            ) as i32;
            emit(&value);
            code
        }
        Ok(Ok(None)) => 0,
        Ok(Err(error)) => {
            let mut value = json!({"ok":false,"code":error.code,"error":error.message,"exit_code":error.exit_code});
            if args.first().map(String::as_str) == Some("remote") {
                value["reason"] = json!(error.code);
            }
            if matches!(
                args.first().map(String::as_str),
                Some("onboarding" | "install")
            ) {
                if let Some(action) = args.get(1).filter(|a| {
                    [
                        "inspect",
                        "discover",
                        "apply",
                        "configure-credentials",
                        "update",
                        "uninstall",
                        "migrate",
                        "install",
                    ]
                    .contains(&a.as_str())
                }) {
                    value["action"] = json!(action);
                }
            }
            if args.first().map(String::as_str) == Some("credentials")
                && matches!(error.code, "credential-absent" | "not-found")
            {
                value["configured"] = json!(false);
            }
            emit(&value);
            error.exit_code
        }
        Err(_) => {
            emit(
                &json!({"ok":false,"code":"internal-error","error":"Native operation failed; diagnostics withheld.","exit_code":7}),
            );
            7
        }
    };
    std::process::exit(code);
}
