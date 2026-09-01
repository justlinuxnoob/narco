//! Driving the C Tor daemon over its control port.
//!
//! Arti (the Rust Tor library) could not complete circuits on several Windows
//! machines — channels handshook fine, then every circuit sat unused until the
//! relay tore it down, so the directory never downloaded. Rather than keep
//! guessing at that, this drives the same `tor` binary Tor Browser ships, which
//! is about as proven as software gets on Windows.
//!
//! The daemon is launched as a child process with a generated config, then
//! driven over the control port: bootstrap progress from `STATUS_CLIENT`
//! events, onion services via `ADD_ONION`, and outbound connections through its
//! SOCKS port. See <https://spec.torproject.org/control-spec/>.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

/// Give up on bootstrap rather than hang forever on a hostile network.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);
/// How long to wait for the daemon to write its port files at startup.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum DaemonError {
    /// The bundled `tor` binary could not be found.
    NotFound(String),
    Spawn(String),
    Control(String),
    Bootstrap(String),
    Io(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::NotFound(p) => write!(f, "could not find the bundled tor binary ({p})"),
            DaemonError::Spawn(e) => write!(f, "could not start tor: {e}"),
            DaemonError::Control(e) => write!(f, "tor control connection failed: {e}"),
            DaemonError::Bootstrap(e) => write!(f, "could not connect to the Tor network: {e}"),
            DaemonError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<io::Error> for DaemonError {
    fn from(e: io::Error) -> Self {
        DaemonError::Io(e.to_string())
    }
}

/// Locate the `tor` executable.
///
/// Prefers a copy shipped beside our own executable (what the installers
/// bundle), then falls back to one on `PATH` so a development checkout works
/// without bundling.
pub fn find_tor_binary() -> Result<PathBuf, DaemonError> {
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };

    // Set by the app to Tauri's resource directory, whose location differs per
    // platform and packaging format, so it cannot be guessed from here.
    if let Some(dir) = std::env::var_os("NARCO_TOR_DIR") {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join(name), dir.join("tor").join(name)] {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(DaemonError::NotFound(name.into()))
}

/// A running `tor` process plus an authenticated control connection.
pub struct TorDaemon {
    child: Child,
    control: TcpStream,
    socks_port: u16,
    /// Kept so the directory is removed when the daemon shuts down.
    data_dir: PathBuf,
}

impl TorDaemon {
    /// Launch tor and wait for it to finish bootstrapping.
    ///
    /// `on_progress` receives the bootstrap percentage and tor's own summary
    /// text, so the UI can show real progress rather than a spinner.
    pub async fn launch(
        data_dir: &Path,
        mut on_progress: impl FnMut(u8, &str),
    ) -> Result<Self, DaemonError> {
        let tor = find_tor_binary()?;
        std::fs::create_dir_all(data_dir)?;

        // Ports 0 make tor pick free ones and write them out, so several
        // instances can coexist and nothing collides with a system tor.
        let control_file = data_dir.join("control-port");
        let socks_file = data_dir.join("socks-port");
        let _ = std::fs::remove_file(&control_file);
        let _ = std::fs::remove_file(&socks_file);

        let mut cmd = Command::new(&tor);

        // The Tor bundle ships its own libssl/libcrypto/libevent beside the
        // binary. Without pointing the loader at them it picks up the system
        // copies and dies with "undefined symbol: evutil_secure_rng_add_bytes".
        // Windows resolves DLLs next to the executable automatically, so this
        // is only needed on Unix.
        #[cfg(unix)]
        if let Some(dir) = tor.parent() {
            let mut paths = vec![dir.to_path_buf()];
            if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
                paths.extend(std::env::split_paths(&existing));
            }
            if let Ok(joined) = std::env::join_paths(paths) {
                cmd.env("LD_LIBRARY_PATH", joined);
            }
        }

        let mut child = cmd
            .arg("--ignore-missing-torrc")
            .args(["-f", "/nonexistent"])
            .args(["DataDirectory", &data_dir.to_string_lossy()])
            .args(["SocksPort", "auto"])
            .args(["ControlPort", "auto"])
            .args(["ControlPortWriteToFile", &control_file.to_string_lossy()])
            .args(["CookieAuthentication", "1"])
            .args(["ClientOnly", "1"])
            // Quieter and faster: we never act as a relay or need IPv6-only.
            .args(["AvoidDiskWrites", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DaemonError::Spawn(e.to_string()))?;

        // tor prints bootstrap lines on stdout; that is our progress source.
        let stdout = child.stdout.take().ok_or_else(|| {
            DaemonError::Spawn("tor produced no stdout to read progress from".into())
        })?;

        let control_port = wait_for_control_port(&control_file).await?;
        let cookie = std::fs::read(data_dir.join("control_auth_cookie"))?;

        let mut control = TcpStream::connect(("127.0.0.1", control_port))
            .await
            .map_err(|e| DaemonError::Control(e.to_string()))?;
        authenticate(&mut control, &cookie).await?;

        let socks_port = read_socks_port(&mut control).await?;

        // Follow bootstrap on stdout until done or the deadline passes.
        let mut lines = BufReader::new(stdout).lines();
        let deadline = tokio::time::Instant::now() + BOOTSTRAP_TIMEOUT;
        let mut percent = 0u8;
        loop {
            let next = tokio::time::timeout_at(deadline, lines.next_line()).await;
            match next {
                Ok(Ok(Some(line))) => {
                    if let Some((pct, summary)) = parse_bootstrap(&line) {
                        percent = pct;
                        on_progress(pct, summary);
                        if pct >= 100 {
                            break;
                        }
                    }
                }
                // tor exited, or its stdout closed.
                Ok(Ok(None)) => {
                    return Err(DaemonError::Bootstrap(
                        "tor stopped unexpectedly during startup".into(),
                    ))
                }
                Ok(Err(e)) => return Err(DaemonError::Bootstrap(e.to_string())),
                Err(_) => {
                    return Err(DaemonError::Bootstrap(format!(
                        "stalled at {percent}% after {}s. Antivirus or firewall software \
                         inspecting connections is the usual cause; a network that blocks \
                         Tor will do it too.",
                        BOOTSTRAP_TIMEOUT.as_secs()
                    )))
                }
            }
        }

        Ok(Self {
            child,
            control,
            socks_port,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// The local SOCKS5 port to dial `.onion` addresses through.
    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    /// Publish an onion service for `key_blob`, forwarding `virtual_port` to a
    /// local listener. Returns the `.onion` address tor reports.
    ///
    /// `DiscardPK` tells tor not to echo the private key back at us: we already
    /// have it, and not receiving it keeps it out of the control stream.
    pub async fn add_onion(
        &mut self,
        key_blob: &str,
        virtual_port: u16,
        local_port: u16,
    ) -> Result<String, DaemonError> {
        let cmd = format!(
            "ADD_ONION ED25519-V3:{key_blob} Flags=DiscardPK Port={virtual_port},127.0.0.1:{local_port}\r\n"
        );
        let reply = self.command(&cmd).await?;
        for line in reply.lines() {
            if let Some(id) = line
                .trim_start_matches(['2', '5', '0', '-', ' '])
                .strip_prefix("ServiceID=")
            {
                return Ok(format!("{id}.onion"));
            }
        }
        Err(DaemonError::Control(format!(
            "ADD_ONION gave no ServiceID: {reply}"
        )))
    }

    /// Stop publishing a service. Used to close the door once two peers are in.
    pub async fn del_onion(&mut self, address: &str) -> Result<(), DaemonError> {
        let id = address.trim_end_matches(".onion");
        self.command(&format!("DEL_ONION {id}\r\n")).await?;
        Ok(())
    }

    /// Send one control command and collect its reply.
    async fn command(&mut self, cmd: &str) -> Result<String, DaemonError> {
        self.control.write_all(cmd.as_bytes()).await?;
        self.control.flush().await?;
        read_reply(&mut self.control).await
    }
}

impl Drop for TorDaemon {
    fn drop(&mut self) {
        // `kill_on_drop` handles the process; also clear the data directory so
        // a session leaves nothing behind on disk.
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// `650 STATUS_CLIENT ... BOOTSTRAP PROGRESS=n ... SUMMARY="..."`, or the same
/// shape on stdout. Returns the percentage and summary when present.
fn parse_bootstrap(line: &str) -> Option<(u8, &str)> {
    if !line.contains("Bootstrapped") && !line.contains("BOOTSTRAP") {
        return None;
    }
    // Both formats carry the number: `Bootstrapped 45% (loading_status)` and
    // `PROGRESS=45`.
    let pct = if let Some(rest) = line.split("PROGRESS=").nth(1) {
        rest.split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?
    } else {
        let rest = line.split("Bootstrapped ").nth(1)?;
        rest.split('%').next()?.trim().parse().ok()?
    };
    let summary = line
        .split("SUMMARY=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .or_else(|| line.split(": ").last())
        .unwrap_or("working");
    Some((pct, summary))
}

/// tor writes `PORT=127.0.0.1:9051` once the control port is open.
async fn wait_for_control_port(path: &Path) -> Result<u16, DaemonError> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(port) = text
                .trim()
                .rsplit(':')
                .next()
                .and_then(|p| p.trim().parse::<u16>().ok())
            {
                return Ok(port);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(DaemonError::Spawn(
                "tor did not report a control port; it may have failed to start".into(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn authenticate(control: &mut TcpStream, cookie: &[u8]) -> Result<(), DaemonError> {
    let hex: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
    control
        .write_all(format!("AUTHENTICATE {hex}\r\n").as_bytes())
        .await?;
    control.flush().await?;
    let reply = read_reply(control).await?;
    if reply.starts_with("250") {
        Ok(())
    } else {
        Err(DaemonError::Control(format!(
            "AUTHENTICATE failed: {reply}"
        )))
    }
}

async fn read_socks_port(control: &mut TcpStream) -> Result<u16, DaemonError> {
    control
        .write_all(b"GETINFO net/listeners/socks\r\n")
        .await?;
    control.flush().await?;
    let reply = read_reply(control).await?;
    reply
        .split('"')
        .nth(1)
        .and_then(|s| s.rsplit(':').next())
        .and_then(|p| p.trim().parse().ok())
        .ok_or_else(|| DaemonError::Control(format!("could not read SOCKS port: {reply}")))
}

/// Read one control-protocol reply: lines until one starting `NNN ` (space
/// rather than `-`, which marks continuation).
async fn read_reply(control: &mut TcpStream) -> Result<String, DaemonError> {
    use tokio::io::AsyncReadExt;
    let mut out = String::new();
    let mut byte = [0u8; 1];
    let mut line = String::new();
    loop {
        let n = control.read(&mut byte).await?;
        if n == 0 {
            return Err(DaemonError::Control("control connection closed".into()));
        }
        let c = byte[0] as char;
        if c == '\n' {
            let finished = line.len() >= 4 && line.as_bytes()[3] == b' ';
            out.push_str(line.trim_end());
            out.push('\n');
            if finished {
                return Ok(out);
            }
            line.clear();
        } else if c != '\r' {
            line.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_bootstrap_formats() {
        let (p, s) = parse_bootstrap("Sep 01 21:00:00.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors").unwrap();
        assert_eq!(p, 45);
        assert!(!s.is_empty());

        let (p, s) = parse_bootstrap(
            "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"",
        )
        .unwrap();
        assert_eq!(p, 100);
        assert_eq!(s, "Done");
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(parse_bootstrap("[notice] Opening Socks listener").is_none());
        assert!(parse_bootstrap("250 OK").is_none());
    }
}
