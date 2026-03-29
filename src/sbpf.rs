//! Solana sBPF AOT compilation support.
//!
//! Uses `sbpf-interpreter --llvm-dylib` to convert a Solana sBPF `.so`
//! binary into a host-native shared library (`.dylib` on macOS, `.so`
//! on Linux) that IDA Pro can open with full Hex-Rays decompilation
//! support.
//!
//! IDA Pro has no native Hex-Rays decompiler for the sBPF instruction
//! set. AOT-compiling to the host architecture produces a regular
//! shared library with standard ABI, letting the existing ARM64/x86_64
//! decompiler plugin work on Solana program code.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::ToolError;

// ── Binary discovery ──────────────────────────────────────────────────────

pub fn find_sbpf2host() -> Result<PathBuf, ToolError> {
    for env_key in ["SBPF_INTERPRETER", "SBPF2HOST"] {
        if let Ok(path) = std::env::var(env_key) {
            let p = PathBuf::from(&path);
            if p.exists() {
                return Ok(p);
            }
            return Err(ToolError::InvalidParams(format!(
                "${env_key} is set to '{path}' but the file does not exist",
            )));
        }
    }

    if let Ok(output) = Command::new("which").arg("sbpf-interpreter").output() {
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

    let candidates: &[&str] = &[
        "~/.config/opencode/skills/sbpf-trace/bin/sbpf-interpreter",
        "~/.cargo/bin/sbpf-interpreter",
        "~/.local/bin/sbpf-interpreter",
        "/usr/local/bin/sbpf-interpreter",
    ];
    for raw in candidates {
        let expanded = crate::expand_path(raw);
        if expanded.exists() {
            return Ok(expanded);
        }
    }

    Err(ToolError::InvalidParams(
        "Cannot find sbpf-interpreter. Build it with `cargo build --release --features llvm` \
         or set SBPF_INTERPRETER env var to its path."
            .into(),
    ))
}

// ── Output directory resolution ───────────────────────────────────────────

/// Check whether a directory is writable by probing with a temp file.
///
/// More reliable than inspecting `metadata().permissions()` on Unix, which
/// only checks owner bits and ignores ACLs / mount flags / sandboxing.
fn is_dir_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".sbpf_compile_probe_{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolve the effective output directory for AOT compilation products.
///
/// - If `output_dir` is explicitly provided, returns it as-is (respecting
///   the caller's choice, even if the directory might not be writable).
/// - Otherwise, uses the input file's parent directory — **unless** that
///   directory is not writable (common when the MCP server runs in a
///   sandbox with a read-only CWD), in which case falls back to
///   [`std::env::temp_dir()`].
pub fn resolve_output_dir(input: &Path, output_dir: Option<&Path>) -> PathBuf {
    if let Some(dir) = output_dir {
        return dir.to_path_buf();
    }
    let parent = input.parent().unwrap_or(Path::new("."));
    if is_dir_writable(parent) {
        parent.to_path_buf()
    } else {
        let tmp = std::env::temp_dir();
        tracing::warn!(
            input_dir = %parent.display(),
            fallback = %tmp.display(),
            "Input directory is not writable; falling back to temp dir for sbpf-interpreter output"
        );
        tmp
    }
}

// ── Output path helpers ───────────────────────────────────────────────────

/// Compute the output `.dylib` / `.so` path for a given sBPF input.
///
/// Platform-specific extension: macOS → `.dylib`, Linux → `.host.so`.
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

/// Returns the expected `.dSYM` path alongside the dylib on macOS.
///
/// If a `.dSYM` bundle exists, we auto-load it after opening so IDA gets
/// debug symbols automatically.
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

/// Result of a successful AOT compilation.
pub struct Sbpf2HostResult {
    /// Path to the produced host-native shared library.
    pub dylib_path: PathBuf,
    /// Whether debug symbols (`.dSYM`) were found alongside the dylib.
    pub has_debug_info: bool,
}

pub fn run_sbpf2host(
    input: &Path,
    output_dir: Option<&Path>,
    dump_ir: bool,
) -> Result<Sbpf2HostResult, ToolError> {
    let bin = find_sbpf2host()?;
    let dylib_path = sbpf2host_output_path(input, output_dir);

    tracing::info!(
        input = %input.display(),
        output = %dylib_path.display(),
        "Running sbpf-interpreter AOT compilation"
    );

    let abs_input = std::fs::canonicalize(input).unwrap_or_else(|_| input.to_path_buf());
    let working_dir = dylib_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);

    let mut cmd = Command::new(&bin);
    cmd.arg("--program")
        .arg(&abs_input)
        .arg("--llvm-dylib")
        .arg(&dylib_path)
        .current_dir(&working_dir);

    if dump_ir {
        let ir_path = dylib_path.with_extension("ll");
        cmd.arg("--llvm-dump-ir").arg(&ir_path);
    }

    let output = cmd.output().map_err(|e| {
        ToolError::InvalidParams(format!(
            "Failed to spawn sbpf-interpreter ({}): {}",
            bin.display(),
            e
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ToolError::InvalidParams(format!(
            "sbpf-interpreter failed (exit {})\nstderr: {}\nstdout: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim()
        )));
    }

    if !dylib_path.exists() {
        return Err(ToolError::InvalidParams(format!(
            "sbpf-interpreter succeeded but output not found: {}",
            dylib_path.display()
        )));
    }

    let dsym = sbpf2host_dsym_path(&dylib_path);
    let has_debug_info = dsym.exists();

    tracing::info!(
        output = %dylib_path.display(),
        has_debug_info,
        "sbpf-interpreter AOT compilation complete"
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

    #[test]
    fn resolve_output_dir_explicit() {
        let input = Path::new("/some/program.so");
        let dir = Path::new("/explicit/dir");
        assert_eq!(
            resolve_output_dir(input, Some(dir)),
            Path::new("/explicit/dir")
        );
    }

    #[test]
    fn resolve_output_dir_writable_parent() {
        let tmp = std::env::temp_dir();
        let input = tmp.join("program.so");
        assert_eq!(resolve_output_dir(&input, None), tmp);
    }

    #[test]
    fn resolve_output_dir_readonly_fallback() {
        let input = Path::new("/nonexistent_sbpf2host_test_dir/program.so");
        assert_eq!(resolve_output_dir(input, None), std::env::temp_dir());
    }
}
