# Changelog

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
