# Changelog

## 0.4.0

- Replace the shipped Python runtime and helper scripts with native Rust executables on macOS arm64/x86_64 and Linux arm64/x86_64; retain the native Luau configuration UI.
- Verify version-pinned executable sizes and SHA-256 before activation; acquire the Linux helper through the same private release manifest rather than requiring remote Python.
- Preserve the authenticated gateway, original session daemon identity, independent SSH TCP forwarding, bounded queues, allocation renewal and classified recovery contracts.
- Add explicit stopped-state schema-3 migration to schema 4, preserving credentials, gateway pins, workspace binding and managed SSH-rule ownership. Old private runtimes are retained, not executed or blindly deleted.
- Keep credential input and issuance in the native helper, reject duplicate JSON keys, and retain private-file, no-redirect, no-proxy and redacted-error boundaries.
- Publish source, native assets, fixed checksums and third-party license notices. Rust reduces runtime overhead; no latency or throughput improvement is guaranteed.

## 0.3.0

- Install through Tern's native Preferences or `tern plugin install`; load safely before configuration without starting Python or network work.
- Add a native settings wizard for private runtime preparation, hidden credential input, verified server/workspace selection, explicit configuration review, connection, update and uninstall.
- Prepare a private pinned CPython 3.13.9 on macOS arm64/x86_64 with publisher SHA-256 verification, bounded downloads and extraction, and no system Python installation.
- Discover actual service-owned UDP listeners and daemon relationships; preserve process/socket identity and reject changed reviews before applying.
- Support native package configuration and ownership-checked legacy-link migration with independent rollback; preserve private data during native removal.
- Keep secrets out of Luau, arguments, environment variables and public results; cancellation and failed validation leave existing credentials unchanged.
- Keep automation available through a bounded JSON onboarding interface. Remote Linux Python 3.9+ remains required.

## 0.2.2

- Fix false daemon-identity rejection during in-place Tern upgrades: pin the process incarnation and socket, validate executable path/role/ownership, and migrate legacy executable-inode records only after stable identity checks pass.
- Classify gateway control failures with sanitized reasons instead of collapsing heartbeat, EOF and protocol errors into one message.
- Recover verified transient control failures with bounded backoff and fresh gateway authentication; discard all old-generation flows and session keys before forwarding resumes.
- Recheck original daemon and gateway identity on reconnect, preserve independent SSH TCP sessions, and cancel pending recovery on Stop.
- Surface gateway recovery progress and failure classification in connection details; keep unknown and security failures fail-closed.

## 0.2.1

- Refresh TURN allocations at half-life with monotonic expiry checks and bounded transient retries; never forward using an expired allocation.
- Rebuild failed flow transports against the same authenticated gateway while preserving flow identity, sequence and replay state. Healthy sibling flows continue forwarding.
- Bound demand-driven recovery with shared cooldown, keep active demand out of the idle-exit path, and cancel recovery on Stop or gateway loss.
- Expose recovery state and cumulative successful allocation refreshes; clear resolved backend error indicators without hiding unrelated UI errors.
- Cover renewal loss, authorization denial, expiry, transport migration and recovery cancellation with deterministic regression scenarios.

## 0.2.0

- Add private Cloudflare TURN-key configuration, local status, remote credential checks and explicit local removal for terminal users and agents.
- Discover existing remote Tern identity and daemon through strictly authenticated SSH; remove personal host aliases, paths and fingerprints from distributable defaults.
- Install durable content-addressed packages, reuse compatible dependencies, preserve configuration on upgrade and validate ownership on uninstall.
- Produce deterministic allowlisted release archives with SHA-256 checksums and MPL-2.0 licensing.
- Retry transient network failures when allocating a new TURN flow at most twice after the initial attempt; certificate, authorization and identity failures remain fail-closed.
- Treat flow-capacity exhaustion as bounded admission loss rather than permanently poisoning the relay; existing flows remain usable and new admission resumes after capacity is released.
- Keep the independent authenticated gateway, existing daemon/session identity and explicit-only direct restoration.
- Show compact binary-unit status summaries and persistent, reusable connection details instead of truncated diagnostic toasts.
- Document human-confirmed Cloudflare Key creation and secret-safe agent-assisted configuration. OAuth login is not included in this release.
