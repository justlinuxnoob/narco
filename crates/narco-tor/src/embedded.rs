//! Running the C tor inside this process, for iOS.
//!
//! Every other platform launches the same `tor` binary as a child process. iOS
//! forbids that outright — executing a second binary is blocked by code
//! signing, which is also why no Tor Browser exists for iOS. So here the very
//! same tor runs on a thread instead of in a process.
//!
//! It is genuinely the same Tor: the `tor.xcframework` published by the
//! Tor.framework project (what Onion Browser and Orbot iOS ship) exports tor's
//! C entry points, and the release we link is tor 0.4.9.11 — the identical
//! version the Expert Bundle gives Windows, Linux and Android.
//!
//! Because it is the same tor, it opens the same control and SOCKS ports, so
//! everything in [`crate::daemon`] past the point of starting it — cookie
//! authentication, `ADD_ONION`, bootstrap parsing, the SOCKS5 dial — is shared
//! rather than reimplemented. That is the whole reason for doing it this way:
//! one Tor implementation and one set of failure modes across four platforms.

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

// The only `unsafe` in this crate, which otherwise forbids it. Calling a C
// entry point cannot be done any other way, so it is confined to this module
// and to the three functions below.
#[allow(unsafe_code)]
mod sys {
    use super::{c_char, c_int, c_void};

    unsafe extern "C" {
        pub fn tor_main_configuration_new() -> *mut c_void;
        pub fn tor_main_configuration_set_command_line(
            cfg: *mut c_void,
            argc: c_int,
            argv: *mut *mut c_char,
        ) -> c_int;
        pub fn tor_main_configuration_free(cfg: *mut c_void);
        pub fn tor_run_main(cfg: *const c_void) -> c_int;
    }
}

/// Start tor on its own thread and return once it has been handed its config.
///
/// `args` is the same argument list the child-process path builds, minus the
/// program name, which is prepended here as tor expects `argv[0]` to be its
/// own name.
///
/// Does not wait for bootstrap. The caller watches that over the control port,
/// exactly as it does when tor is a separate process.
#[allow(unsafe_code)]
pub fn start(args: &[String]) -> Result<(), String> {
    // Owned for the life of the process. tor keeps pointers into this argv
    // while it runs, and it runs until the app exits, so these are
    // deliberately leaked rather than freed under a running tor.
    let mut owned: Vec<CString> = Vec::with_capacity(args.len() + 1);
    owned.push(CString::new("tor").map_err(|e| e.to_string())?);
    for a in args {
        owned.push(CString::new(a.as_str()).map_err(|e| e.to_string())?);
    }
    let mut argv: Vec<*mut c_char> = owned.iter().map(|s| s.as_ptr() as *mut c_char).collect();
    let argc = argv.len() as c_int;

    let cfg = unsafe { sys::tor_main_configuration_new() };
    if cfg.is_null() {
        return Err("tor_main_configuration_new returned null".into());
    }

    let rc = unsafe { sys::tor_main_configuration_set_command_line(cfg, argc, argv.as_mut_ptr()) };
    if rc != 0 {
        unsafe { sys::tor_main_configuration_free(cfg) };
        return Err(format!("tor rejected its command line (code {rc})"));
    }

    // The argv and its strings must outlive the thread below.
    std::mem::forget(owned);
    std::mem::forget(argv);

    let cfg = cfg as usize; // raw pointers are not Send; tor owns it from here
    std::thread::Builder::new()
        .name("tor".into())
        // tor is not a small stack program. The default 2 MiB is enough for the
        // main loop but leaves no margin for the directory parsing it does on
        // first bootstrap.
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let code = unsafe { sys::tor_run_main(cfg as *const c_void) };
            // Only reached if tor stops, which it should not while the app
            // lives. The control connection dropping is what the rest of the
            // code notices.
            tracing::warn!("tor exited with code {code}");
        })
        .map_err(|e| format!("could not start the tor thread: {e}"))?;

    Ok(())
}
