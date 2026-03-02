//! Solana sBPF AOT compilation support.
//!
//! Uses `sbpf2host` to convert a Solana sBPF `.so` binary into a
//! host-native shared library (`.dylib` on macOS, `.so` on Linux)
//! that IDA Pro can open with full Hex-Rays decompilation support.
//!
//! IDA Pro has no native Hex-Rays decompiler for the sBPF instruction
//! set. AOT-compiling to the host architecture produces a regular
//! shared library with standard ABI, letting the existing ARM64/x86_64
//! decompiler plugin work on Solana program code.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ToolError;

// ── Binary discovery ──────────────────────────────────────────────────────

/// Locate the `sbpf2host` binary.
///
/// Search order:
/// 1. `SBPF2HOST` environment variable (explicit path)
/// 2. `PATH` — `which sbpf2host`
/// 3. Well-known install locations (`~/.cargo/bin`, `/usr/local/bin`)
pub fn find_sbpf2host() -> Result<PathBuf, ToolError> {
    // 1. Explicit environment variable
    if let Ok(path) = std::env::var("SBPF2HOST") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
        return Err(ToolError::InvalidParams(format!(
            "$SBPF2HOST is set to '{}' but the file does not exist",
            path
        )));
    }

    // 2. PATH lookup
    if let Ok(output) = Command::new("which").arg("sbpf2host").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                let p = PathBuf::from(s);
                if p.exists() {
                    return Ok(p);
                }
            }
        }
    }

    // 3. Well-known locations
    let candidates: &[&str] = &[
        // Cargo install (most common)
        "~/.cargo/bin/sbpf2host",
        "/usr/local/bin/sbpf2host",
        "/usr/bin/sbpf2host",
        // Linux workspace builds
        "~/.local/bin/sbpf2host",
    ];
    for raw in candidates {
        let expanded = crate::expand_path(raw);
        if expanded.exists() {
            return Ok(expanded);
        }
    }

    Err(ToolError::InvalidParams(
        "Cannot find sbpf2host. Install it (`cargo install sbpf2host`) or set the \
         SBPF2HOST environment variable to its path."
            .into(),
    ))
}

// ── Output path helpers ───────────────────────────────────────────────────

/// Compute the output `.dylib` / `.so` path for a given sBPF input.
///
/// If `output_dir` is provided, the output file is placed there.
/// Otherwise it is placed alongside the input file.
///
/// The output extension is platform-specific:
/// - macOS → `.dylib`
/// - Linux → `.host.so`  (to avoid colliding with the original `.so`)
/// - Other → `.dylib`
pub fn sbpf2host_output_path(input: &Path, output_dir: Option<&Path>) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sbpf_out".to_string());

    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        // On Linux the original is already .so; use .host.so to avoid collision
        "host.so"
    };

    let dir = output_dir.unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")));
    dir.join(format!("{stem}.{ext}"))
}

/// Returns the expected `.dSYM` path that `sbpf2host` produces on macOS.
///
/// `sbpf2host` writes `<output>.dSYM` alongside the dylib.  We auto-load
/// it after opening so IDA gets debug symbols automatically.
pub fn sbpf2host_dsym_path(dylib_path: &Path) -> PathBuf {
    let mut dsym = dylib_path.as_os_str().to_os_string();
    dsym.push(".dSYM");
    let dsym_root = PathBuf::from(dsym);
    // DWARF lives inside: <foo>.dylib.dSYM/Contents/Resources/DWARF/<stem>
    let stem = dylib_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    dsym_root
        .join("Contents")
        .join("Resources")
        .join("DWARF")
        .join(stem)
}

// ── Compilation ───────────────────────────────────────────────────────────

/// Result of a successful `sbpf2host` AOT compilation.
pub struct Sbpf2HostResult {
    /// Path to the produced host-native shared library.
    pub dylib_path: PathBuf,
    /// Whether debug symbols (`.dSYM`) were found alongside the dylib.
    pub has_debug_info: bool,
}

/// Run `sbpf2host` to AOT-compile a Solana sBPF `.so` to a host-native dylib.
///
/// # Arguments
/// - `input`      — path to the sBPF `.so`
/// - `output_dir` — optional directory for the output dylib (default: alongside input)
/// - `dump_ir`    — if true, pass `--dump-ir` to sbpf2host
///
/// # Errors
/// Returns `ToolError::InvalidParams` if sbpf2host is not found or exits non-zero.
pub fn run_sbpf2host(
    input: &Path,
    output_dir: Option<&Path>,
    dump_ir: bool,
) -> Result<Sbpf2HostResult, ToolError> {
    let sbpf2host = find_sbpf2host()?;
    let dylib_path = sbpf2host_output_path(input, output_dir);

    tracing::info!(
        input = %input.display(),
        output = %dylib_path.display(),
        "Running sbpf2host AOT compilation"
    );

    let mut cmd = Command::new(&sbpf2host);
    // --dylib-output expects the path WITHOUT extension; sbpf2host appends
    // the platform extension (.dylib / .so) itself.
    let dylib_stem = dylib_path.with_extension("");
    cmd.arg(input)
        .arg(format!("--dylib-output={}", dylib_stem.display()));

    if dump_ir {
        cmd.arg("--dump-ir");
    }

    let output = cmd.output().map_err(|e| {
        ToolError::InvalidParams(format!(
            "Failed to spawn sbpf2host ({}): {}",
            sbpf2host.display(),
            e
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ToolError::InvalidParams(format!(
            "sbpf2host failed (exit {})\nstderr: {}\nstdout: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim()
        )));
    }

    if !dylib_path.exists() {
        return Err(ToolError::InvalidParams(format!(
            "sbpf2host succeeded but output not found: {}",
            dylib_path.display()
        )));
    }

    let dsym = sbpf2host_dsym_path(&dylib_path);
    let has_debug_info = dsym.exists();

    tracing::info!(
        output = %dylib_path.display(),
        has_debug_info,
        "sbpf2host AOT compilation complete"
    );

    Ok(Sbpf2HostResult {
        dylib_path,
        has_debug_info,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn output_path_macos_no_output_dir() {
        let input = Path::new("/tmp/675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8.so");
        let out = sbpf2host_output_path(input, None);
        // On macOS the extension is .dylib; on Linux it's .host.so
        let ext = out.extension().unwrap().to_str().unwrap();
        assert!(ext == "dylib" || ext == "so", "unexpected extension: {ext}");
        assert_eq!(
            out.parent().unwrap(),
            Path::new("/tmp"),
            "output must be alongside input"
        );
        // stem must be preserved
        assert!(out
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"),);
    }

    #[test]
    fn output_path_with_output_dir() {
        let input = Path::new("/downloads/program.so");
        let dir = Path::new("/out");
        let out = sbpf2host_output_path(input, Some(dir));
        assert_eq!(out.parent().unwrap(), dir);
        assert!(out
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("program"));
    }

    #[test]
    fn dsym_path_structure() {
        let dylib = Path::new("/tmp/program.dylib");
        let dsym = sbpf2host_dsym_path(dylib);
        assert!(dsym.to_str().unwrap().contains(".dSYM"));
        assert!(dsym.to_str().unwrap().contains("DWARF"));
        assert!(dsym.to_str().unwrap().ends_with("program.dylib"));
    }
}
