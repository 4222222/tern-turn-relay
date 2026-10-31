# Rust TURN dataplane experiment

This branch is a runnable experiment, not a replacement for the released Tern plugin. Production installation, credentials, configuration and session daemon are unchanged. Rust owns the experimental TLS/TURN transport and authenticated UDP data plane; the existing Python/Luau onboarding and SSH control plane have not been ported.

## Run

Build with `cargo build --release --locked --manifest-path experiments/rust-prototype/Cargo.toml`, preferably on an existing remote builder or CI. The isolated `rust-prototype.yml` workflow produces a macOS arm64 executable. Linux was built on the existing remote server with `CARGO_BUILD_JOBS=2`.

The executable consumes one JSON request on stdin, then a separate `{"command":"stop"}` line. Roles are `client`, `echo` and loopback `relay`; exact request fields and bounds are in `src/main.rs`. Keep stdin open until stopping. Credentials and gateway session keys must travel only through anonymous pipes, never command arguments, logs or checked-in files. The native binary requires neither Python nor Cargo at runtime.

For the paired experiment, run the existing Python interpreter with:

```sh
python3 -B experiments/rust-prototype/bench.py \
  --source-root "$SOURCE_ROOT" \
  --dependency-root "$EXISTING_AIOICE_DEPENDENCIES" \
  --rust-bin "$RUST_BINARY"
```

Supply a JSON envelope on stdin: version 1, repetitions 2, lifecycle true, and `request` containing the client request. The runner starts workers serially in Python/Rust/Rust/Python order, followed by separate Python and Rust lifecycle checks. It emits allowlisted JSONL metrics, not credentials. `python_peer.py` imports the existing Python Endpoint and gateway codec instead of reimplementing the production baseline.

On a multihomed echo server, set `bind_host` to the exact `advertise_host`, not `0.0.0.0`. An initial wildcard-bound experiment received and echoed requests remotely but delivered no replies to either client. Binding the advertised address restored verified Python echoes on the same TURN path. The wildcard run is invalid setup evidence, not a performance sample. Always verify a short authenticated echo before the paired measurement.

## Measurement contract

Both implementations use the same pinned Cloudflare TURN IPv4 endpoint, TLS hostname verification, authenticated remote UDP echo, payload size, concurrency window and packet deadline. Echoed payload is verified before acknowledgement. Throughput counts acknowledged application payload bits, excluding wire overhead. RTT includes local scheduling and is not terminal keystroke latency or native Tern/QUIC throughput.

RSS and user+system CPU time are sampled per worker; they exclude the echo, runner and other processes. CPU includes benchmark payload generation and validation. RSS is not allocator live memory or proportional memory; short peaks and final CPU intervals can be missed. A macOS host under memory pressure is not a controlled dedicated benchmark machine. Two samples per implementation show variation, not statistical significance.

Lifecycle durations are deliberately unequal: production Python requests a 120-second allocation and is observed for 150 seconds; the Rust library obtained 600 seconds and is observed for 330 seconds. Successful Refresh responses prove renewal acknowledgement, not survival beyond the original 600-second expiry. Recovery deliberately aborts one owned TLS connection, detects failure, creates a new allocation and requires a verified echo; it does not simulate a WAN or provider outage. Stop requires observed normal process exit, not forced termination.

## Library constraints relevant to interpretation

- `turn` 0.17.2 owns a 1024-entry inbound queue and silently drops failed `try_send` calls. The adapter's separately reported `queue_drops` does not include that queue. Zero adapter drops is not proof of zero upstream drops.
- Rust flushes each TLS frame; aioice's synchronous transport write normally completes after enqueue and waits only when backpressured. These implementations have different pacing and send-completion semantics.
- Rust may initially send indications while ChannelBind completes asynchronously; aioice waits for ChannelBind. Control transactions and data writes can contend on upstream locks.
- The public Rust allocation API has no lifetime override. This experiment preserves the upstream request rather than rewriting authenticated STUN messages or forking TURN.

These are observed implementation differences, not demonstrated explanations for a particular timeout.

Sources: [turn client](https://docs.rs/crate/turn/0.17.2/source/src/client/mod.rs), [relay connection](https://docs.rs/crate/turn/0.17.2/source/src/client/relay_conn.rs), [aioice 0.10.2](https://github.com/aiortc/aioice/blob/0.10.2/src/aioice/turn.py), [tokio-rustls buffering](https://docs.rs/tokio-rustls/0.26.4/tokio_rustls/index.html).

## Measured result — 2026-10-31

Verdict: Rust substantially reduced this worker's resident footprint and simplified its native runtime distribution. The experiment did **not** demonstrate lower network latency or consistently higher throughput. Keep the released Python implementation in production; a full Rust migration is a packaging/resource decision, not an established latency fix.

Build: `675d00f`, [macOS CI run 41177296414](https://github.com/jiwangyihao/tern-turn-relay/actions/runs/41177296414). Executable SHA-256: `17dce02e3571eae06dcaa0b634f6007d3a7fe6daf3d301c2759de3da770ac3b8`. The valid experiment used 1200-byte payloads, window 512, a 5-second packet deadline, 20 sequential RTT samples and 2 MiB target per throughput run. Execution order was Python 1, Rust 1, Rust 2, Python 2.

| Metric | Python runs 1 / 2 | Rust runs 1 / 2 |
|---|---:|---:|
| Mean idle RSS, MiB | 37.00 / 34.22 | 3.97 / 3.71 |
| Sampled peak RSS, MiB | 37.02 / 36.98 | 4.19 / 4.39 |
| Whole-worker sampled CPU, seconds | 0.20 / 0.21 | 0.08 / 0.08 |
| Throughput-phase CPU, seconds | 0.09 / 0.11 | 0.07 / 0.07 |
| Verified payload throughput, Mbit/s | 9.38 / 2.06 | 8.47 / 3.16 |
| Sequential RTT p50, ms | 310.08 / 318.99 | 318.62 / 311.01 |
| Sequential RTT p95, ms | 451.66 / 448.36 | 450.48 / 430.73 |
| Explicit Stop to observed exit, ms | 276.34 / 350.19 | 1.23 / 1.05 |

Every valid short run acknowledged all 20 latency packets and all 1747 full-size throughput packets (2,096,400 payload bytes). All reported integrity errors, timeouts and adapter queue drops were zero. Later throughput samples slowed in both implementations; the sample is too small and the link too variable to rank throughput. The earlier pilot's Rust timeouts did not recur in these four valid runs, but this is not a long-term reliability guarantee.

Python observed two Refresh acknowledgements during 150 seconds; Rust observed three during 330 seconds. Rust's three responses may belong to one upstream timer cycle, not three independent renewal cycles. After an owned TLS abort, both obtained a verified echo again: Python 967.59 ms, Rust 977.47 ms. All six workers exited normally after explicit Stop. Expired input credentials were separately rejected before Ready.

An isolated native Tern `remote doctor` also completed with exit 0 through the Rust loopback relay, reported a QUIC/UDP response and the SSH-provisioned pinned gateway identity. The gateway referenced the existing daemon with 20 sessions; its temporary frontend and Rust relay were stopped afterward. This proves native transport interoperability, not measured terminal typing performance or a full native UI migration.

The macOS arm64 executable is 2,502,496 bytes; its CI ZIP was 1,319,485 bytes. `otool -L` showed only system libiconv/libSystem dependencies. Existing installed Python runtime plus aioice dependencies occupied 61,508 KiB according to `du`, versus 2,444 KiB for the Rust binary. These are component footprints, **not equivalent complete product packages**: onboarding, SSH supervision, credential management and the remote gateway still use the existing Python implementation. Linux Rust was also compiled and used as the authenticated echo; no Intel macOS or Windows executable was validated.

Local memory pressure remained at warning level; swap was approximately 47–48 GiB. Both idle CPU samples rounded to zero at the sampling resolution, not proof of zero CPU consumption. Resource and timing numbers are observations from this host, not universal language benchmarks. Redacted local raw evidence is retained under `.artifacts/rust-prototype/comparison-valid.jsonl`; the invalid wildcard-bound run is separately retained as `comparison.jsonl` and excluded above.
