use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nix::sys::statvfs::statvfs;
use nix::unistd::geteuid;

const DEFAULT_VENV_PATH: &str = "/home/pypippark-dep";
const LOG_PREFIX: &str = "[pypippark]";

static VERBOSE: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(name = "pypippark")]
#[command(
    name = "pypippark",
    version = "2.0.0-alpha",
    about = "Manage a single, system-wide Python virtual environment (Rust port)",
    long_about = r#"Manage a single, system-wide Python virtual environment (Rust port).

EXAMPLES:
  pypippark install requests flask
  pypippark list
  pypippark run ./script.py -- arg1 arg2
  pypippark enter
  pypippark check

Use -V or --version to check version

We value transparency and open-source collaboration. With that freedom comes responsibility:
please test our tools in safe environments before production use. This product is provided as-is,
without any warranty."#
)]

struct Cli {
    /// path to venv (overrides default)
    #[arg(long, global = true)]
    venv: Option<PathBuf>,

    /// system python (defaults to current process environment's python3)
    #[arg(long, global = true)]
    python: Option<OsString>,

    /// verbose diagnostics
    #[arg(short, long, global = true)]
    verbose: bool,
    
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Install {
        pkgs: Vec<String>,
    },
    List,
    Remove {
        pkgs: Vec<String>,
    },
    Update,
    Run {
        script: PathBuf,
        args: Vec<String>,
    },
    /// Spawn an interactive shell inside the venv (this is the "enter" feature)
    Enter,
    /// Run an advanced I/O & environment health check for the venv
    Check,
}

fn log(level: &str, msg: &str) {
    let emoji = match level {
        "INFO" => "ℹ️",
        "SUCCESS" => "✅",
        "WARNING" => "⚠️",
        "ERROR" => "❌",
        _ => "❔",
    };
    println!("{} {} {}", LOG_PREFIX, emoji, msg);
}

fn verbose_log(msg: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        println!("{} 🔍 {}", LOG_PREFIX, msg);
    }
}

fn system_python(provided: Option<OsString>) -> String {
    if let Some(p) = provided {
        p.into_string().unwrap_or_else(|_os| {
            log(
                "WARNING",
                "Invalid system python provided; falling back to current process python",
            );
            env::var("PYTHON").unwrap_or_else(|_| "python3".into())
        })
    } else {
        env::var("PYTHON").unwrap_or_else(|_| "python3".into())
    }
}

/// Attempts to write a small temp file inside `path` to test writability.
fn is_writable_test(path: &Path) -> bool {
    let test_file = path.join(".pypippark_write_test");
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&test_file)
    {
        Ok(mut f) => {
            let _ = f.write_all(b"test");
            let _ = fs::remove_file(&test_file);
            true
        }
        Err(_) => false,
    }
}

/// Ensure virtualenv exists; if missing create it. Returns (python_bin, pip_bin) inside venv.
fn ensure_venv(path: &Path, system_py: &str) -> Result<(PathBuf, PathBuf)> {
    if !path.exists() {
        log("INFO", &format!("Creating virtualenv at {:?}", path));
        let status = Command::new(system_py)
            .args(["-m", "venv", path.to_str().unwrap()])
            .status()
            .with_context(|| "failed to spawn python -m venv")?;
        if !status.success() {
            bail!("python -m venv returned non-zero");
        }
    }

    // If running as root and the venv isn't writable, chown it to the invoking user.
    if geteuid().is_root() && !is_writable_test(path) {
        let user = env::var("SUDO_USER").unwrap_or_else(|_| whoami::username());
        log(
            "WARNING",
            &format!("Adjusting ownership of {:?} → {}:{}", path, user, user),
        );
        let status = Command::new("chown")
            .args(["-R", &format!("{}:{}", user, user), path.to_str().unwrap()])
            .status()
            .with_context(|| "failed to spawn chown")?;
        if !status.success() {
            bail!("chown returned non-zero");
        }
    }

    let py = path.join("bin").join("python3");
    let pip = path.join("bin").join("pip");

    Ok((py, pip))
}

/// Returns environment variables to run commands inside the venv.
/// Note: caller will usually call Command.envs(activate_env(...)).
fn activate_env(path: &Path) -> Vec<(OsString, OsString)> {
    let mut envs: Vec<(OsString, OsString)> = env::vars_os().collect();
    envs.retain(|(k, _)| k != "PYTHONHOME");
    envs.push((
        OsString::from("VIRTUAL_ENV"),
        OsString::from(path.to_str().unwrap()),
    ));
    // Prepend venv bin to PATH:
    let old_path = env::var_os("PATH").unwrap_or_default();
    let new_path = {
        let mut pb = PathBuf::from(path);
        pb.push("bin");
        let mut s = OsString::from(pb.to_str().unwrap());
        s.push(":");
        s.push(old_path);
        s
    };
    envs.retain(|(k, _)| k != "PATH");
    envs.push((OsString::from("PATH"), new_path));
    envs
}

fn run_with_env(cmd: &str, args: &[&str], envs: &[(OsString, OsString)]) -> Result<()> {
    let mut c = Command::new(cmd);
    c.args(args).envs(envs.iter().cloned());
    let status = c
        .status()
        .with_context(|| format!("failed to run {:?}", cmd))?;
    if !status.success() {
        bail!("command {:?} returned non-zero", cmd);
    }
    Ok(())
}

fn cmd_install(venv: &Path, system_py: &str, pkgs: &[String]) -> Result<()> {
    let (_py, pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);
    let args: Vec<&str> = std::iter::once(pip.to_str().unwrap())
        .chain(std::iter::once("install"))
        .chain(pkgs.iter().map(String::as_str))
        .collect();
    log("INFO", &format!("Installing {}...", pkgs.join(", ")));
    run_with_env(args[0], &args[1..], &envs)?;
    log(
        "SUCCESS",
        &format!("Installed {} successfully!", pkgs.join(", ")),
    );
    Ok(())
}

fn cmd_list(venv: &Path, system_py: &str) -> Result<()> {
    let (_py, pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);
    log("INFO", "Listing installed packages...");
    run_with_env(pip.to_str().unwrap(), &["list"], &envs)?;
    Ok(())
}

fn cmd_remove(venv: &Path, system_py: &str, pkgs: &[String]) -> Result<()> {
    let (_py, pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);
    let mut args = vec!["uninstall", "-y"];
    for p in pkgs {
        args.push(p.as_str());
    }
    log("WARNING", &format!("Removing {}...", pkgs.join(", ")));
    run_with_env(pip.to_str().unwrap(), &args, &envs)?;
    log(
        "SUCCESS",
        &format!("Removed {} successfully!", pkgs.join(", ")),
    );
    Ok(())
}

fn cmd_update(venv: &Path, system_py: &str) -> Result<()> {
    let (_py, pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);

    log("INFO", "Upgrading pip...");
    run_with_env(
        pip.to_str().unwrap(),
        &["install", "--upgrade", "pip"],
        &envs,
    )?;

    log("INFO", "Checking for outdated packages…");
    let out = Command::new(pip.to_str().unwrap())
        .args(["list", "--outdated", "--format=freeze"])
        .envs(envs.iter().cloned())
        .output()
        .with_context(|| "failed to run pip list --outdated")?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let out_trim = stdout.trim();
    if out_trim.is_empty() {
        log("SUCCESS", "All packages are already up-to-date.");
        return Ok(());
    }

    let pkgs: Vec<&str> = out_trim
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| line.split("==").next())
        .collect();

    log("INFO", &format!("Upgrading: {}", pkgs.join(", ")));

    let mut args = vec!["install", "--upgrade"];
    args.extend(pkgs.iter().cloned());
    run_with_env(pip.to_str().unwrap(), &args, &envs)?;
    log("SUCCESS", "All packages updated successfully!");
    Ok(())
}

fn cmd_run(venv: &Path, system_py: &str, script: &Path, script_args: &[String]) -> Result<()> {
    if !script.is_file() {
        log("ERROR", &format!("Script not found: {:?}", script));
        bail!("script not found");
    }
    let (py, _pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);
    let mut args: Vec<&str> = vec![script.to_str().unwrap()];
    args.extend(script_args.iter().map(String::as_str));
    log("INFO", &format!("Running {:?}...", script));
    run_with_env(py.to_str().unwrap(), &args, &envs)?;
    log("SUCCESS", &format!("Finished running {:?}.", script));
    Ok(())
}

/// Spawn interactive shell inside venv (the new feature).
fn cmd_enter(venv: &Path, system_py: &str) -> Result<()> {
    let (_py, _pip) = ensure_venv(venv, system_py)?;
    let envs = activate_env(venv);

    // choose shell: prefer $SHELL, fallback to /bin/bash or /bin/sh
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
    log("INFO", &format!("Entering venv shell: {}", shell));
    let status = Command::new(shell)
        .envs(envs.iter().cloned())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| "failed to spawn shell")?;

    if !status.success() {
        bail!("shell exited with non-zero status");
    }
    Ok(())
}

/// Advanced health / I/O check for the venv environment.
fn cmd_check(venv: &Path, system_py: &str) -> Result<()> {
    log("INFO", "Running advanced I/O & environment check...");
    verbose_log(&format!("Checking venv path: {:?}", venv));

    // show system python version (use variable to avoid warnings)
    verbose_log(&format!("System python binary: {}", system_py));
    match Command::new(system_py).arg("--version").output() {
        Ok(out) => {
            let ver = {
                let s_err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if !s_err.is_empty() {
                    s_err
                } else {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                }
            };
            if !ver.is_empty() {
                verbose_log(&format!("system python --version: {}", ver));
            } else {
                verbose_log("system python --version returned empty output");
            }
        }
        Err(e) => {
            verbose_log(&format!(
                "failed to execute system python '{}': {:?}",
                system_py, e
            ));
        }
    }

    // 1) Basic existence & type
    if !venv.exists() {
        log("ERROR", &format!("Venv path does not exist: {:?}", venv));
        bail!("venv missing");
    }
    if !venv.is_dir() {
        log(
            "ERROR",
            &format!("Venv path is not a directory: {:?}", venv),
        );
        bail!("venv invalid");
    }
    verbose_log("Path exists and is a directory.");

    // 2) Symlink check
    let meta = fs::symlink_metadata(venv).with_context(|| "failed to read metadata")?;
    if meta.file_type().is_symlink() {
        log(
            "WARNING",
            "Venv path is a symlink — double-check target permissions.",
        );
    } else {
        verbose_log("Not a symlink.");
    }

    // 3) Permission bits & ownership
    let metadata = fs::metadata(venv).with_context(|| "failed to read metadata")?;
    let mode = metadata.permissions().mode();
    let uid = metadata.uid();
    let gid = metadata.gid();
    verbose_log(&format!("mode={:o}, uid={}, gid={}", mode, uid, gid));
    if mode & 0o700 == 0 {
        log(
            "WARNING",
            "Venv has no owner-execute/read/write bits set — may be unusable.",
        );
    }

    // 4) Writable test
    if is_writable_test(venv) {
        verbose_log("Write test succeeded.");
    } else {
        log(
            "WARNING",
            "Path is not writable by current user (write test failed).",
        );
    }

    // 5) Disk space + inode checks using statvfs
    match statvfs(venv) {
        Ok(s) => {
            let free_bytes = (s.blocks_available() as u64) * (s.fragment_size() as u64);
            let total_blocks = s.blocks() as u64;
            let free_blocks = s.blocks_available() as u64;
            let pct_free = if total_blocks > 0 {
                (free_blocks as f64 / total_blocks as f64) * 100.0
            } else {
                100.0
            };
            verbose_log(&format!(
                "Disk free: {} bytes (~{:.1}% free on FS)",
                free_bytes, pct_free
            ));
            if pct_free < 5.0 {
                log(
                    "WARNING",
                    "Filesystem is almost full (<5% free). This may break installs.",
                );
            }
            // inode check (if available)
            let total_files = s.files() as u64;
            let free_files = s.files_available() as u64;
            if total_files > 0 {
                let pct_files_free = (free_files as f64 / total_files as f64) * 100.0;
                verbose_log(&format!("Inodes free: {:.1}%", pct_files_free));
                if pct_files_free < 1.0 {
                    log("WARNING", "Filesystem has very few inodes free (<1%).");
                }
            }
        }
        Err(e) => {
            verbose_log(&format!("statvfs failed: {:?}", e));
            log("WARNING", "Could not read filesystem stats (statvfs).");
        }
    }

    // 6) Python & pip presence + executability
    let py = venv.join("bin").join("python3");
    let pip = venv.join("bin").join("pip");
    if py.exists() {
        let m = fs::metadata(&py).with_context(|| "failed to stat python binary")?;
        if m.permissions().mode() & 0o111 == 0 {
            log(
                "WARNING",
                &format!("{} exists but is not executable", py.display()),
            );
        } else {
            verbose_log("python3 binary exists and is executable.");
        }
    } else {
        log(
            "ERROR",
            &format!("python3 binary missing at {}", py.display()),
        );
    }

    if pip.exists() {
        let m = fs::metadata(&pip).with_context(|| "failed to stat pip binary")?;
        if m.permissions().mode() & 0o111 == 0 {
            log(
                "WARNING",
                &format!("{} exists but is not executable", pip.display()),
            );
        } else {
            verbose_log("pip binary exists and is executable.");
        }
    } else {
        log(
            "WARNING",
            &format!(
                "pip missing at {} — installs/upgrades may fail.",
                pip.display()
            ),
        );
    }

    // 7) Run pip --version in the activated env (if present)
    let envs = activate_env(venv);
    if pip.exists() {
        verbose_log("Running `pip --version` inside venv...");
        let out = Command::new(pip.to_str().unwrap())
            .arg("--version")
            .envs(envs.iter().cloned())
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                verbose_log(&format!("pip --version output: {}", s));
                if !o.status.success() {
                    log("WARNING", "pip executed but returned non-zero status.");
                }
            }
            Err(e) => {
                log("WARNING", &format!("Failed to run pip: {:?}", e));
            }
        }
    }

    // 8) Verify python sys.prefix matches venv path (sanity)
    if py.exists() {
        verbose_log("Verifying python sys.prefix inside venv...");
        let out = Command::new(py.to_str().unwrap())
            .args(["-c", "import sys, json; print(json.dumps(sys.prefix))"])
            .envs(envs.iter().cloned())
            .output();
        match out {
            Ok(o) => {
                if o.status.success() {
                    if let Ok(prefix_raw) = String::from_utf8(o.stdout) {
                        let prefix = prefix_raw.trim().trim_matches('"').to_string();
                        verbose_log(&format!("python sys.prefix = {}", prefix));
                        let venv_s = venv.to_string_lossy().into_owned();
                        if !prefix.starts_with(&venv_s) {
                            log(
                                "WARNING",
                                "python's sys.prefix does not start with venv path — venv may be broken.",
                            );
                        } else {
                            verbose_log("python sys.prefix looks good.");
                        }
                    }
                } else {
                    log(
                        "WARNING",
                        "python inside venv returned non-zero when checking sys.prefix.",
                    );
                }
            }
            Err(e) => {
                log(
                    "WARNING",
                    &format!("Failed to run python from venv: {:?}", e),
                );
            }
        }
    }

    log("SUCCESS", "I/O & environment check complete.");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // set global verbosity
    VERBOSE.store(cli.verbose, Ordering::Relaxed);

    let venv_path = cli.venv.unwrap_or_else(|| PathBuf::from(DEFAULT_VENV_PATH));
    let system_py = system_python(cli.python);

    match cli.cmd {
        Commands::Install { pkgs } => cmd_install(&venv_path, &system_py, &pkgs)?,
        Commands::List => cmd_list(&venv_path, &system_py)?,
        Commands::Remove { pkgs } => cmd_remove(&venv_path, &system_py, &pkgs)?,
        Commands::Update => cmd_update(&venv_path, &system_py)?,
        Commands::Run { script, args } => cmd_run(&venv_path, &system_py, &script, &args)?,
        Commands::Enter => cmd_enter(&venv_path, &system_py)?,
        Commands::Check => cmd_check(&venv_path, &system_py)?,
    }

    Ok(())
}
