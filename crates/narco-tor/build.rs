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

    // Loud, not a warning. Without it the build dies much later as an
    // undefined `_tor_run_main` from the linker, which does not say whether the
    // variable never arrived or the flags were wrong — and that difference is
    // the whole diagnosis.
    let dir = std::env::var("NARCO_TOR_XCFRAMEWORK").unwrap_or_else(|_| {
        panic!(
            "NARCO_TOR_XCFRAMEWORK is not set. iOS links the C tor from the \
             tor.xcframework; the workflow sets this per target. Use \
             `--features check-embedded` for a check-only build off iOS."
        )
    });

    // Pick the slice from the target rather than having the workflow set a
    // different value per step. That plumbing did not survive the trip through
    // xcodebuild into its script phase, so the simulator build linked nothing
    // while the device build was fine. The target is always here.
    let target = std::env::var("TARGET").unwrap_or_default();
    let slice = if target.ends_with("-sim") || target.starts_with("x86_64-apple-ios") {
        "ios-arm64_x86_64-simulator"
    } else {
        "ios-arm64"
    };
    // Accept either the xcframework root or a slice directly, so an already
    // specific path still works.
    let dir = if std::path::Path::new(&dir).join("tor.framework").is_dir() {
        dir
    } else {
        format!("{dir}/{slice}")
    };

    // Printed so the log shows which slice was used. Linking the device slice
    // into a simulator build fails in exactly the same way as not linking.
    println!("cargo:warning=linking tor for {target} from {dir}");
    println!("cargo:rustc-link-search=framework={dir}");
    println!("cargo:rustc-link-lib=framework=tor");

    // tor's own dependencies inside the framework still need these from the
    // system: compression for directory documents, and the C++ runtime that
    // OpenSSL's assembly helpers pull in.
    println!("cargo:rustc-link-lib=z");
    println!("cargo:rustc-link-lib=c++");
}
