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
/// How long to wait for the daemon to write its port and cookie files.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// How many of tor's own output lines to keep for error messages.
const RECENT_LINES: usize = 12;
/// Poll interval while waiting for those files.
const STARTUP_POLL: Duration = Duration::from_millis(50);

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
            DaemonError::NotFound(p) => write!(f, "could not find the bundled tor binary: {p}"),
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

/// Strip Windows' `\\?\` extended-length prefix.
///
/// Tauri hands back resource paths carrying it. Rust copes, but the path goes
/// on to a child process as a plain string, and tor has no reason to
/// understand it. Verbatim paths also disable the `.` and `..` normalisation
/// the rest of this function relies on.
fn plain(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        // UNC (`\\?\UNC\server\share`) does not survive the naive strip.
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

/// Locate the `tor` executable.
///
/// Prefers a copy shipped beside our own executable (what the packaged builds
/// carry), then falls back to one on `PATH` so a development checkout works
/// without bundling.
///
/// Deliberately tries more places than should be necessary, and on failure
/// reports every one of them. A user whose app cannot find its own daemon can
/// only send us a log, so the log has to be enough on its own.
pub fn find_tor_binary() -> Result<PathBuf, DaemonError> {
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };
    let mut tried = Vec::new();

    let mut roots = Vec::new();
    // Set by the app to Tauri's resource directory, whose location differs per
    // platform and packaging format, so it cannot be guessed from here.
    if let Some(dir) = std::env::var_os("NARCO_TOR_DIR") {
        let dir = plain(PathBuf::from(dir));
        // The second entry covers a resource directory that already points at
        // the tor folder, which would otherwise resolve to `tor/tor/tor.exe`.
        roots.push(dir.clone());
        roots.push(dir.join("tor"));
        if let Some(parent) = dir.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = plain(exe).parent() {
            roots.push(dir.to_path_buf());
            roots.push(dir.join("tor"));
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        roots.extend(std::env::split_paths(&path));
    }

    for root in roots {
        let candidate = root.join(name);
        if candidate.is_file() {
            tracing::info!("using tor at {}", candidate.display());
            return Ok(candidate);
        }
        if !tried.contains(&candidate) {
            tried.push(candidate);
        }
    }

    Err(DaemonError::NotFound(format!(
        "{name}; looked in: {}",
        tried
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
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

        // tor refuses to start against a data directory it cannot make sense
        // of, and does not repair one — a `state` that is not a file kills it
        // outright. The directory holds nothing but cached network directories,
        // so discarding it costs one slower connection and never a message.
        if data_dir.exists() && !data_dir.join("state").is_file() && data_dir.join("state").exists()
        {
            tracing::warn!(
                "discarding an unusable tor data directory at {}",
                data_dir.display()
            );
            let _ = std::fs::remove_dir_all(data_dir);
        }

        std::fs::create_dir_all(data_dir).map_err(|e| {
            DaemonError::Spawn(format!(
                "could not create tor's data directory {}: {e}",
                data_dir.display()
            ))
        })?;

        // Ports 0 make tor pick free ones and write them out, so several
        // instances can coexist and nothing collides with a system tor.
        let control_file = data_dir.join("control-port");
        let cookie_file = data_dir.join("control_auth_cookie");
        // Stale files from a previous run would be read as this run's, giving a
        // dead port and an authentication failure.
        let _ = std::fs::remove_file(&control_file);
        let _ = std::fs::remove_file(&cookie_file);

        // An empty config file we own. Pointing `-f` at a path that does not
        // exist works on Unix, but on Windows a bare "/nonexistent" names a
        // path on the current drive that is not ours to assume anything about.
        let torrc = data_dir.join("torrc");
        std::fs::write(&torrc, b"")
            .map_err(|e| DaemonError::Spawn(format!("could not write {}: {e}", torrc.display())))?;

        let mut cmd = Command::new(&tor);

        // tor is a console program and Narco is a windowed one, so without this
        // Windows opens a black console window and leaves it on screen for as
        // long as the daemon runs.
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        // Used only if the tables are present. We stopped shipping them: they
        // are 24 MB, and path selection does not consult them — tor picks for
        // subnet and family diversity, not country. They matter only for the
        // country-based node rules this app never sets.
        if let Some(dir) = tor.parent() {
            for (option, name) in [("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")] {
                let path = dir.join(name);
                if path.is_file() {
                    cmd.args([option, &path.to_string_lossy()]);
                }
            }
        }

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
            .args(["-f", &torrc.to_string_lossy()])
            .args(["DataDirectory", &data_dir.to_string_lossy()])
            .args(["SocksPort", "auto"])
            .args(["ControlPort", "auto"])
            .args(["ControlPortWriteToFile", &control_file.to_string_lossy()])
            .args(["CookieAuthentication", "1"])
            .args(["ClientOnly", "1"])
            // Tie the daemon's life to ours. Windows does not kill a child
            // when its parent dies, and the Drop that used to do it never runs
            // when the window closes and the process exits — so every session
            // left an orphaned tor holding this directory's lock, and the next
            // launch died against it with "another Tor process is running".
            // tor watches this pid and exits once it is gone, which covers a
            // crash or a kill as well as a clean exit.
            .args(["__OwningControllerProcess", &std::process::id().to_string()])
            // Quieter and faster: we never act as a relay or need IPv6-only.
            .args(["AvoidDiskWrites", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DaemonError::Spawn(format!("{e} (tried to run {})", tor.display())))?;

        // tor prints bootstrap lines on stdout; that is our progress source.
        let stdout = child.stdout.take().ok_or_else(|| {
            DaemonError::Spawn("tor produced no stdout to read progress from".into())
        })?;

        // Read tor's output from the moment it starts rather than from when
        // the control port appears. Whatever kills it during startup — a
        // locked data directory, a port it cannot open, a rejected option — it
        // explains on the way out, and the old code only began reading at a
        // point a dying tor never reaches. The one case that most needs an
        // explanation was the one case that threw it away.
        let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel();
        let recent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        pump(stdout, false, recent.clone(), line_tx.clone());
        if let Some(stderr) = child.stderr.take() {
            pump(stderr, true, recent.clone(), line_tx.clone());
        }
        // The last sender, so the bootstrap loop sees the channel close when
        // tor's output ends instead of waiting out the timeout.
        drop(line_tx);

        let control_port =
            match wait_for_startup_file(&control_file, &mut child, "control port file").await {
                Ok(bytes) => parse_control_port(&bytes)?,
                Err(e) => return Err(with_tor_output(e, &recent).await),
            };
        let cookie =
            match wait_for_startup_file(&cookie_file, &mut child, "authentication cookie").await {
                Ok(bytes) => bytes,
                Err(e) => return Err(with_tor_output(e, &recent).await),
            };

        let mut control = TcpStream::connect(("127.0.0.1", control_port))
            .await
            .map_err(|e| {
                DaemonError::Control(format!("could not reach tor on port {control_port}: {e}"))
            })?;
        authenticate(&mut control, &cookie).await?;

        // The second half of the same guarantee: tor shuts down when this
        // control connection closes. The operating system closes it for us
        // however the app dies, so this covers the cases the pid check cannot.
        if let Err(e) = command_on(&mut control, "TAKEOWNERSHIP\r\n").await {
            // Not fatal on its own — the pid check above still applies.
            tracing::warn!("tor did not accept TAKEOWNERSHIP: {e}");
        }

        let socks_port = read_socks_port(&mut control).await?;

        // Follow bootstrap on tor's output until done or the deadline passes.
        let deadline = tokio::time::Instant::now() + BOOTSTRAP_TIMEOUT;
        let mut percent = 0u8;
        loop {
            let next = tokio::time::timeout_at(deadline, line_rx.recv()).await;
            match next {
                Ok(Some(line)) => {
                    if let Some((pct, summary)) = parse_bootstrap(&line) {
                        percent = pct;
                        on_progress(pct, summary);
                        if pct >= 100 {
                            break;
                        }
                    }
                }
                // tor exited, or its output closed.
                Ok(None) => {
                    return Err(with_tor_output(
                        DaemonError::Bootstrap("tor stopped unexpectedly".into()),
                        &recent,
                    )
                    .await)
                }
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
        command_on(&mut self.control, cmd).await
    }
}

/// Send one control command on a connection we do not own yet.
async fn command_on(control: &mut TcpStream, cmd: &str) -> Result<String, DaemonError> {
    control.write_all(cmd.as_bytes()).await?;
    control.flush().await?;
    let reply = read_reply(control).await?;
    if reply.starts_with("250") {
        Ok(reply)
    } else {
        Err(DaemonError::Control(reply.trim().to_string()))
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

/// Forward one of tor's output streams to the log, to a rolling buffer for
/// error messages, and to the bootstrap loop.
fn pump<R>(
    reader: R,
    is_stderr: bool,
    recent: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if is_stderr {
                tracing::warn!("tor: {line}");
            } else {
                tracing::debug!("tor: {line}");
            }
            if let Ok(mut r) = recent.lock() {
                if r.len() == RECENT_LINES {
                    r.remove(0);
                }
                r.push(line.clone());
            }
            let _ = tx.send(line);
        }
    });
}

/// Attach tor's last words to a failure. Its own output is the only place the
/// real reason appears, and a user who hits this can send us nothing else.
async fn with_tor_output(
    error: DaemonError,
    recent: &std::sync::Mutex<Vec<String>>,
) -> DaemonError {
    // Let the readers drain what tor wrote on its way out; the pipe closing and
    // the process exiting are not the same instant.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let tail = match recent.lock() {
        Ok(r) if !r.is_empty() => r.join(" | "),
        _ => return error,
    };

    // Say what to do, not just what happened. A tor left over from an older
    // build holds this lock and no amount of retrying clears it.
    if tail.contains("another Tor process is running") {
        return DaemonError::Spawn(
            "a Tor process from an earlier session is still running and holding \
             Narco's data directory. Close Narco, end any tor process in your \
             task manager, and start it again. Builds after 0.5.4 shut their \
             own Tor down and will not do this."
                .into(),
        );
    }
    match error {
        DaemonError::Spawn(m) => DaemonError::Spawn(format!("{m}. tor said: {tail}")),
        DaemonError::Bootstrap(m) => DaemonError::Bootstrap(format!("{m}. tor said: {tail}")),
        other => other,
    }
}

/// Wait for one of the files tor writes at startup and return its contents.
///
/// tor writes its control-port file and its authentication cookie at separate
/// moments, so reading one the instant the other appears is a race. It is a
/// race Linux nearly always wins and Windows often loses, because antivirus
/// software inspects each write and widens the gap — losing it surfaced as a
/// bare "The system cannot find the file specified. (os error 2)" seconds after
/// launch, with nothing to say which file was missing.
///
/// Requiring the length to hold steady across two polls avoids the other half
/// of the problem: the file exists between being created and being written, and
/// a cookie read at that instant would authenticate with the wrong bytes.
///
/// Also watches the child, so a tor that dies immediately is reported as having
/// died rather than as a timeout thirty seconds later.
async fn wait_for_startup_file(
    path: &Path,
    child: &mut Child,
    what: &str,
) -> Result<Vec<u8>, DaemonError> {
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    let mut settled: Option<usize> = None;
    loop {
        match std::fs::read(path) {
            Ok(bytes) if !bytes.is_empty() => {
                if settled == Some(bytes.len()) {
                    return Ok(bytes);
                }
                settled = Some(bytes.len());
            }
            _ => settled = None,
        }

        if let Ok(Some(status)) = child.try_wait() {
            return Err(DaemonError::Spawn(format!(
                "tor exited ({status}) before writing its {what}"
            )));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(DaemonError::Spawn(format!(
                "tor did not write its {what} ({}) within {}s. Antivirus software \
                 blocking the bundled tor is the usual cause.",
                path.display(),
                STARTUP_TIMEOUT.as_secs()
            )));
        }
        tokio::time::sleep(STARTUP_POLL).await;
    }
}

/// tor writes `PORT=127.0.0.1:9051` once the control port is open.
fn parse_control_port(bytes: &[u8]) -> Result<u16, DaemonError> {
    let text = String::from_utf8_lossy(bytes);
    text.trim()
        .rsplit(':')
        .next()
        .and_then(|p| p.trim().parse::<u16>().ok())
        .ok_or_else(|| {
            DaemonError::Spawn(format!(
                "could not read tor's control port from {:?}",
                text.trim()
            ))
        })
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

    #[test]
    fn reads_the_control_port_tor_writes() {
        assert_eq!(parse_control_port(b"PORT=127.0.0.1:9051\n").unwrap(), 9051);
        assert_eq!(parse_control_port(b"PORT=127.0.0.1:41337").unwrap(), 41337);
        assert!(parse_control_port(b"").is_err());
        assert!(parse_control_port(b"PORT=127.0.0.1:").is_err());
    }

    /// The Windows failure: the cookie arrives after the port file, and reading
    /// it too eagerly gave "the system cannot find the file specified".
    #[tokio::test]
    async fn waits_for_a_file_that_appears_late() {
        let dir = std::env::temp_dir().join(format!("narco-late-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control_auth_cookie");
        let _ = std::fs::remove_file(&path);

        let writer = {
            let path = path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                std::fs::write(&path, [7u8; 32]).unwrap();
            })
        };

        // A child that outlives the wait, so only the file gates the result.
        let mut child = Command::new(if cfg!(windows) { "cmd" } else { "sleep" })
            .args(if cfg!(windows) {
                vec!["/c", "timeout", "/t", "5"]
            } else {
                vec!["5"]
            })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let bytes = wait_for_startup_file(&path, &mut child, "cookie")
            .await
            .unwrap();
        assert_eq!(bytes, [7u8; 32]);
        writer.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tor killed by antivirus should say so, not time out silently.
    #[tokio::test]
    async fn reports_a_daemon_that_dies_instead_of_timing_out() {
        let mut child = Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                vec!["/c", "exit"]
            } else {
                vec![]
            })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let missing = std::env::temp_dir().join("narco-nonexistent-startup-file");
        let _ = std::fs::remove_file(&missing);

        let err = wait_for_startup_file(&missing, &mut child, "control port file")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exited"),
            "expected an exit report, got: {err}"
        );
    }
}
