//! Interactive shell inside a container.
//!
//! kdt does not implement the exec protocol: it hands the terminal to `kubectl exec -it` the same
//! way [`crate::edit`] hands it to `$EDITOR`, and takes it back when the shell exits. A TUI cannot
//! multiplex a PTY into a ratatui pane without becoming a terminal emulator, and `kubectl` already
//! negotiates the SPDY/websocket upgrade, the window size and the TTY.
//!
//! The consequence to own: this is the one feature of kdt that needs a binary in `$PATH`, so its
//! absence is reported before the terminal is given away rather than as a blank screen afterwards.

use std::path::PathBuf;

// Which container to land in, resolved by the caller from the selected row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub namespace: String,
    pub pod: String,
    pub container: Option<String>,
}

// The default command: the shells worth trying, in order, tested before being exec'd. `exec bash ||
// exec sh` reads better but does not work — a failed `exec` takes the shell down with it instead of
// falling through, so the fallback has to be decided before the exec, not after.
const DEFAULT_SHELL: &str = "command -v bash >/dev/null 2>&1 && exec bash || exec sh";

pub fn kubectl_binary() -> String {
    std::env::var("KDT_KUBECTL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "kubectl".to_string())
}

// Where the binary lives, or None when it is nowhere on the PATH. An absolute name is taken at its
// word, as `Command` would.
pub fn locate(binary: &str) -> Option<PathBuf> {
    let direct = PathBuf::from(binary);
    if direct.components().count() > 1 {
        return direct.is_file().then_some(direct);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|c| c.is_file())
}

// The command line to run, as a program and its arguments — no shell of ours in between, so a pod
// name never gets a chance to be interpreted. Pure, so the shape of the call is testable.
pub fn command_line(target: &Target, context: Option<&str>) -> (String, Vec<String>) {
    let mut args: Vec<String> = Vec::new();
    if let Some(ctx) = context {
        args.push("--context".to_string());
        args.push(ctx.to_string());
    }
    args.push("exec".to_string());
    args.push("-it".to_string());
    args.push("-n".to_string());
    args.push(target.namespace.clone());
    args.push(target.pod.clone());
    if let Some(c) = &target.container {
        args.push("-c".to_string());
        args.push(c.clone());
    }
    args.push("--".to_string());
    args.push("sh".to_string());
    args.push("-c".to_string());
    args.push(shell_command());
    (kubectl_binary(), args)
}

fn shell_command() -> String {
    std::env::var("KDT_EXEC_SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SHELL.to_string())
}

// Run the shell, with the terminal already handed over by the caller. A non-zero status is reported
// as it comes: `kubectl`'s own errors scrolled past on a screen kdt is about to repaint, so the
// exit code is the only trace left of them.
pub async fn run(target: &Target, context: Option<&str>) -> Result<(), String> {
    let (program, args) = command_line(target, context);
    let status = tokio::process::Command::new(&program)
        .args(&args)
        .status()
        .await
        .map_err(|e| format!("{program} : {e}"))?;
    if !status.success() {
        return Err(format!("{program} : {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_container_and_the_context_are_only_passed_when_there_is_one() {
        let bare = Target {
            namespace: "apps".to_string(),
            pod: "web-0".to_string(),
            container: None,
        };
        let (_, args) = command_line(&bare, None);
        // Only the part before `--` is kdt's: past it, `-c` is the shell's own flag.
        let head = &args[..args.iter().position(|a| a == "--").expect("separator")];
        assert_eq!(head, &["exec", "-it", "-n", "apps", "web-0"]);
        assert!(!head.contains(&"-c".to_string()));
        assert!(!head.contains(&"--context".to_string()));

        let full = Target { container: Some("sidecar".to_string()), ..bare };
        let (_, args) = command_line(&full, Some("prod"));
        assert_eq!(
            &args[..9],
            &["--context", "prod", "exec", "-it", "-n", "apps", "web-0", "-c", "sidecar"]
        );
    }

    #[test]
    fn the_shell_is_the_last_argument_and_stays_one_word() {
        let t = Target {
            namespace: "apps".to_string(),
            pod: "web-0".to_string(),
            container: None,
        };
        let (_, args) = command_line(&t, None);
        let tail = &args[args.len() - 4..];
        assert_eq!(tail[0], "--");
        assert_eq!(tail[1], "sh");
        assert_eq!(tail[2], "-c");
        assert!(tail[3].contains("exec bash"), "the fallback chain is one argument");
    }

    #[test]
    fn an_absolute_binary_is_taken_at_its_word() {
        assert_eq!(locate("/definitely/not/here/kubectl"), None);
        assert_eq!(locate("/bin/sh").as_deref(), Some(std::path::Path::new("/bin/sh")));
    }
}
