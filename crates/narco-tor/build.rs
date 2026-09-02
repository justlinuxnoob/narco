//! Link the C tor on iOS.
//!
//! Every other platform ships tor as a separate binary and never links it. iOS
//! cannot execute a second binary, so there it is linked into the app instead
//! and started on a thread — see `src/embedded.rs`.
//!
//! The library comes from the `tor.xcframework` published by the Tor.framework
//! project, which is what Onion Browser and Orbot iOS ship. CI downloads it and
//! points `NARCO_TOR_XCFRAMEWORK` at the slice for the target being built. It
//! is a static archive, so it links in and there is nothing to embed in the
//! app bundle or load at runtime.

fn main() {
    println!("cargo:rerun-if-env-changed=NARCO_TOR_XCFRAMEWORK");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("ios") {
        return;
    }

    let Ok(dir) = std::env::var("NARCO_TOR_XCFRAMEWORK") else {
        // Left unset for `cargo check`, which never links. A real build without
        // it fails at link time with an undefined `tor_run_main`, which names
        // the problem clearly enough.
        println!(
            "cargo:warning=NARCO_TOR_XCFRAMEWORK is not set; iOS linking will \
             fail unless this is a check-only build"
        );
        return;
    };

    println!("cargo:rustc-link-search=framework={dir}");
    println!("cargo:rustc-link-lib=framework=tor");

    // tor's own dependencies inside the framework still need these from the
    // system: compression for directory documents, and the C++ runtime that
    // OpenSSL's assembly helpers pull in.
    println!("cargo:rustc-link-lib=z");
    println!("cargo:rustc-link-lib=c++");
}
