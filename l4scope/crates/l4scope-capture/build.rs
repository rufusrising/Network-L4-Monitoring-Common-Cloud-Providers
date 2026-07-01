//! Build script: when the `ebpf` feature is enabled, compile the CO-RE BPF
//! program (`bpf/l4scope.bpf.c`) into an object that `ebpf.rs` embeds via
//! `include_bytes_aligned!`. No-op for the default (std-only) build.
//!
//! Requirements when building `--features ebpf` (Linux):
//!   * clang/llvm (>= 11) with the `bpf` target
//!   * libbpf headers (`bpf/bpf_helpers.h`) — package `libbpf-dev`
//!   * a generated `bpf/vmlinux.h`:
//!       bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only compile the BPF object when the feature is on.
    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Workspace layout: crates/l4scope-capture -> ../../bpf
    let bpf_dir = manifest.join("../../bpf");
    let src = bpf_dir.join("l4scope.bpf.c");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("l4scope.bpf.o");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", bpf_dir.join("vmlinux.h").display());

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        Ok(other) => panic!("unsupported eBPF target arch: {other}"),
        Err(_) => "x86",
    };

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            &format!("-D__TARGET_ARCH_{arch}"),
            "-I",
            bpf_dir.to_str().unwrap(),
            "-c",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run clang to build the BPF object ({e}). Install clang/llvm and \
                 libbpf-dev, and generate bpf/vmlinux.h (see build.rs docs)."
            )
        });

    if !status.success() {
        panic!(
            "clang failed to compile {}. Ensure bpf/vmlinux.h exists and libbpf headers are \
             installed.",
            src.display()
        );
    }
}
