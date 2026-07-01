# Building the native capture backends (eBPF / Windows)

The default `cargo build` is std-only and produces a fully working agent with the
`synthetic`, `pcap_file`, and `live` backends. The **native, production** backends
are opt-in because they need OS toolchains. This guide covers building and running
them; it also flags what still needs a compile-and-verify pass.

> Status note: the eBPF userspace loader (aya) and the CO-RE program are written
> against `aya` 0.13 and libbpf, but were authored in an environment without a
> Rust/clang toolchain, so the first `--features ebpf` build should be treated as
> a compile-and-fix step. The default std-only build is verified.

## Linux — eBPF (recommended for production)

This is the intended production path on Linux hosts and Kubernetes nodes: no
`tcpdump`, no libpcap, no external process — the agent loads a CO-RE BPF program
and reads a ring buffer.

### Prerequisites

- Kernel ≥ ~5.4 with **BTF** enabled (`/sys/kernel/btf/vmlinux` exists). True on
  current Amazon Linux 2023, Ubuntu 20.04+, Container-Optimized OS, AKS Ubuntu.
- Toolchain: `clang`/`llvm` (≥ 11), `libbpf-dev`, `bpftool`, and Rust.
  - Debian/Ubuntu: `apt-get install -y clang llvm libbpf-dev linux-tools-common bpftool`
- Capabilities at runtime: `CAP_BPF` (or root) + `CAP_NET_ADMIN`.

### Build

```bash
# 1) Generate the CO-RE type header from the running kernel's BTF:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# 2) Build the agent with the eBPF backend. build.rs invokes clang to compile
#    bpf/l4scope.bpf.c into an object that the backend embeds.
cargo build --release -p l4scope-agent --features ebpf
```

### Run

```bash
sudo target/release/l4scope --backend ebpf --iface eth0
# or via config: set [capture] backend = "ebpf", interface = "eth0"
```

The backend attaches the program to the interface's TC clsact **ingress and
egress** hooks, so it sees both directions of every flow. Records carry only L4
headers; no payload leaves the kernel.

### How it fits together

```
bpf/l4scope.bpf.c  --clang-->  l4scope.bpf.o  --include_bytes_aligned!-->  ebpf.rs
                                                     |
   TC ingress/egress  --ringbuf(BpfL4Event)-->  RingBuf.next() --decode--> PacketMeta
```

`BpfL4Event` (Rust, `ebpf.rs`) and `struct l4_event` (C) are the shared ABI —
keep their field order/sizes in lock-step if you extend them.

## Kubernetes (EKS / GKE / AKS)

Build an image with `--features ebpf` and deploy the DaemonSet in
`deploy/daemonset.yaml` (already requests `NET_ADMIN` + `BPF`). Two additions for
eBPF nodes:

- Mount BTF if not already present at the standard path (most managed images have
  it): the DaemonSet comment shows the `hostPath` for `/sys/kernel/btf`.
- Generate `bpf/vmlinux.h` at image build time in the builder stage (run
  `bpftool btf dump ... format c`), or ship a portable header.

Prometheus scrapes port 9560; events go to stdout (NDJSON) for the node log
agent.

## Windows — options (native, no tcpdump)

Packet visibility on Windows is genuinely different from Linux; there are three
viable paths. The repo currently ships a **compiling stub** for the native ETW
backend and this decision guide:

1. **ETW realtime (native, no install) — recommended long-term.** Subscribe to the
   `Microsoft-Windows-TCPIP` provider (GUID `2F07E2EE-15DB-40F1-90EF-9D7BA282188A`)
   with the `ferrisetw` crate, bridge events to the engine. Note ETW TCPIP is
   *event-level* (connect/retransmit/reset/rundown), not raw packet headers, so
   the Windows path maps ETW events more directly to `L4Event`s rather than
   synthesizing full `PacketMeta`. This is the right always-on agent design for
   Windows but needs implementation + verification on a Windows host (uncomment
   the `ferrisetw` dep in `l4scope-capture/Cargo.toml`). I can complete this with
   you in a compile loop.
2. **pktmon (built-in, no install) — batch/near-real-time.** `pktmon` ships with
   Windows 10 1809+ / Server 2019+. Capture then convert to pcapng and feed the
   `pcap_file` backend:
   ```
   pktmon start --capture --pkt-size 256 -f cap.etl
   pktmon stop
   pktmon pcapng cap.etl -o cap.pcapng   # then convert/replay
   ```
   Good for incident capture; not a continuous stream.
3. **Npcap + tshark (install required) — live parity.** If you can install
   Wireshark/Npcap, the existing `live` backend works unchanged:
   ```
   l4scope --backend live --iface "Ethernet" ^
           --live-cmd "tshark -i Ethernet -w - -F pcap -s 256"
   ```

Recommendation for a locked-down Windows fleet with no installs: pursue option 1
(ETW). For quick wins today: option 2 (pktmon) for on-demand, or option 3 where
Npcap is permitted.

## Verifying any backend quickly

`l4scope --demo` needs no privileges or toolchain and exercises every detector —
use it to confirm the engine and exporters before wiring native capture.
