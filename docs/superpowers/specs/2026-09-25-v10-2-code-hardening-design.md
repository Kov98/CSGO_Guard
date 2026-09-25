# CSGO Guard v10.2 Code Hardening Design

## Intent

Evoluir diretamente a v10.1 para uma v10.2 mais forte sem reescrever o projeto, sem adicionar volume artificial de documentação e sem aumentar a superfície ofensiva do driver. O foco é código de segurança e detecção: client-side, service/driver binding, protocolo, telemetria autoritativa do servidor, histórico temporal, perfis de arma/recoil e detectores estatísticos.

Success means the v10.2 materially improves the quality and trustworthiness of signals, makes local session spoofing harder, makes server-side analysis more context-aware, and keeps behavioral enforcement conservative until calibrated on replay corpora.

## Approaches considered

### A. Detector-first

Add many new detectors quickly on top of the v10.1 event model. This grows apparent coverage fastest, but most new signals would reuse the same underlying data and become correlated. It risks producing more code without meaningfully improving trust.

### B. Trust-chain-first

Spend the whole release tightening client/service/driver/session authentication and attestation, with minimal gameplay work. This strongly improves client integrity but leaves the largest current opportunity—the server-side temporal model—mostly unchanged.

### C. Balanced trust + temporal modeling — selected

Harden the local trust chain while expanding the authoritative server model and then build detectors on top of the stronger data. This yields fewer but more meaningful new signals and improves both bypass resistance and false-positive control. This is the selected architecture.

## Architecture

The v10.2 keeps the existing boundaries:

`launcher/client -> SYSTEM service -> kernel driver`

and

`authoritative CSGO game server -> authenticated telemetry -> backend world history -> detector pipeline -> evidence quorum`.

The main change is that each boundary carries stronger session identity and each detector receives richer authoritative history instead of only a current event plus a short player-local queue.

## 1. Client/service IPC hardening

The service request gains an authenticated envelope without trusting the request body before authentication. The MAC covers the stable serialized request fields, including protocol version and struct size, request ID, session ID, heartbeat sequence, client/game PIDs and process start times, nonce, attestation challenge ID and monotonic client timestamp.

The service derives a per-session IPC key from the installation secret and session context. Replay state is consumed only after header, process-instance binding, freshness and MAC validation succeed.

The response proof becomes bound to the exact request ID, request nonce and session ID.

## 2. Service/driver/session binding

The kernel control session is tightened without adding arbitrary memory primitives. The driver tracks control-owner PID plus process creation identity, active session ID, monotonic control sequence, protected client PID plus creation identity and protected game PID plus creation identity.

A PID reuse must not inherit a prior protected/control identity. If the control-owner process exits, the driver invalidates the active session and requires explicit re-claim.

The ABI is bumped for structures that carry process-instance identity. All mutable IOCTLs validate exact ABI, exact struct size, owner identity, active session and strictly increasing sequence.

No new arbitrary kernel read/write, physical memory access, process attach or PatchGuard-bypass interfaces are introduced.

## 3. Executable/module integrity

The existing module fingerprint is expanded from path/size/timestamp identity to content identity for protected binaries and loaded game modules.

The service maintains a bounded cache keyed by stable file identity. For each relevant executable/module it records normalized path, file size, last-write metadata, SHA-256 content digest, Authenticode verification state when available and signer identity metadata when available.

Unexpected content changes invalidate the cached fingerprint. The backend treats local module identity as client evidence, not server authority.

## 4. Authoritative world history

`MatchWorldHistory` becomes the canonical temporal model for gameplay detectors. For each player and tick it stores bounded history of origin/velocity, view angles, aim punch/recoil, stance/on-ground state, weapon profile identity, alive state and server command/tick-base/network state.

For target relationships it stores target snapshot tick, geometry validity, visibility, target angular position, distance, lag-compensation target tick and whether lag compensation was actually applied.

History is bounded by configured maximum unlag plus detector lookback. No detector may silently fall back to client-provided target geometry.

## 5. Lag-compensation-aware analysis

The lag-compensation and aim detectors resolve target state at the authoritative target tick, not simply the current event tick.

A resolver returns `Exact`, `Interpolated` or `Unavailable`. Behavioral detectors suppress geometry-dependent conclusions when resolution is `Unavailable`.

Interpolation is capped by tick distance and never extrapolates beyond recorded authoritative history.

## 6. Versioned weapon/recoil profiles

The weapon catalog becomes version-aware. A profile set is identified by game/build ID, profile-set SHA-256, weapon name, cycle time, movement-speed constraints, scoped-state rules and recoil/punch parameters used by supported detectors.

Telemetry batches bind to the profile-set hash in use by the game server. If the backend cannot resolve that exact set, weapon/recoil detectors become `Unavailable` rather than using generic fallback thresholds for enforcement.

## 7. Temporal detector framework

The detector pipeline gains explicit temporal windows. A signal carries family, kind, confidence, source window ID, correlation group, sample count, observation duration and authoritative-data quality.

High-confidence behavioral evidence requires repeated observations across independent time windows.

New/refined detectors in v10.2:

1. **TargetTransitionKinematicsDetector** — angular travel, acceleration and settling when switching between distinct authoritative targets.
2. **PreFireAcquisitionDetector** — acquisition quality in ticks immediately preceding a valid shot using resolved target history.
3. **FirstShotConsistencyDetector** — repeated first-shot precision in comparable authoritative contexts, separated by weapon and distance buckets.
4. **RecoilTrajectoryDetector** — multi-shot view-angle trajectory versus authoritative punch evolution rather than a single-shot compensation delta.
5. **MovementCommandConsistencyDetector** — buttons, on-ground state, velocity, tick base and movement transitions across short authoritative windows.
6. **TemporalAimLockDetector** — persistent low-error tracking over time while target motion changes.

Existing v10.1 detectors remain and are refined to use the shared temporal resolver where applicable.

## 8. Evidence independence and enforcement

EvidenceQuorum is strengthened so correlated detector kinds cannot simulate independent evidence.

Automatic behavioral enforcement requires at least two independent evidence families, at least two independent source windows, no unresolved authoritative-data-quality failure, no shadow/calibration-only detector, and policy minimum sample count plus observation duration.

Deterministic protocol/integrity violations remain eligible for immediate deny/review according to policy. New behavioral detectors ship in shadow/calibration mode by default.

## 9. Protocol/backend hardening

Authenticated telemetry batches bind protocol version, server ID, match ID, player/session ID, build ID, weapon profile-set hash, first/last tick, sequence, nonce and payload digest into the signed/HMAC-protected envelope.

The replay guard records state only after signature/HMAC verification. Batch tick ranges must be monotonic and consistent with event contents. Profile-set/build changes inside an active match are rejected unless match authority explicitly rotates them.

## 10. Tests and calibration

Each production behavior is introduced test-first.

Required test groups cover IPC MAC tampering/replay/PID reuse, kernel control-owner PID reuse/session invalidation, module digest changes with unchanged path/metadata, authoritative history exact/interpolated/unavailable resolution, build/profile mismatch suppression, each new detector with clean and synthetic-violation fixtures, evidence-correlation quorum behavior, telemetry replay/build-profile rotation rejection and the existing kernel surface audit.

Calibration reports clean trigger rate, synthetic-violation coverage, confidence distribution, sample counts and replay stability. No new behavioral detector is promoted from shadow mode solely because a synthetic fixture triggers it.

## 11. Explicit non-goals

The v10.2 does not add arbitrary kernel memory read/write, physical-memory mapping, SSDT hooks, PatchGuard bypasses, unsigned-driver bypasses, client-authoritative gameplay evidence, automatic behavioral bans from one detector, Steam ticket authentication, or claims of WDK/TPM compatibility without real hardware validation.

## Delivery

The release remains a single current project tree. The v10.2 ZIP replaces the v10.1 artifact for local inspection while older states remain versioned separately.

The final artifact must pass all portable security/contract tests and produce a deterministic ZIP. Windows-only WDK/driver/TPM validation remains a separate explicit validation stage.
