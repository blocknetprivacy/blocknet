# Blocknet Security/Consensus Problems

This file is a live backlog of negative findings only.

## Severity Legend

- `critical`: direct consensus break, chain corruption, or destructive control path
- `high`: practical DoS, abuse, or major trust-boundary weakness
- `medium`: exploitable weakness with constraints or significant safety gap
- `low`: hardening/documentation issues with limited immediate impact

## Findings

### Critical

1. [DONE] `critical` - `Chain.ProcessBlock()` trusts callers for validation  
   - **Location:** `block.go` (`ProcessBlock`)  
   - **Problem:** It mutates consensus state without internally enforcing full block validation. Any current/future caller that forgets pre-validation becomes a consensus backdoor.  
   - **Impact:** Invalid blocks can enter state via call-path mistakes/regressions.  
   - **Required fix:** Move/duplicate mandatory validation into `ProcessBlock` (or replace with a single validated entrypoint and make raw method private/internal).
   - **Status:** fixed (2026-02-12)  
   - **What changed:** `ProcessBlock` now calls internal mandatory validation before any state/storage mutation, using shared chain-context validation logic (`validateBlockWithContext`) instead of trusting callers.  
   - **Regression coverage:** added `TestProcessBlock_EnforcesValidationInternally` (direct `ProcessBlock` call rejects invalid block without external pre-validation).  
   - **Notes:** expensive daemon reorg integration tests were deferred to `Deferred Test Backlog` to preserve fix cadence.

2. [DONE] `critical` - `Chain.AddBlock()` / `addBlockInternal()` can write blocks without validation  
   - **Location:** `block.go` (`AddBlock`, `addBlockInternal`)  
   - **Problem:** Direct persistence + state updates can occur without PoW/difficulty/tx validation.  
   - **Impact:** Any non-genesis call-site mistake can inject invalid chain data.  
   - **Required fix:** Restrict to genesis-only API or force validation in this path; explicitly fail non-genesis unvalidated calls.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Removed exported `AddBlock` usage path; introduced unexported `addGenesisBlock` for empty-chain genesis init only; added explicit fail-fast guards in `addBlockInternal` to reject any non-genesis or non-empty-chain unvalidated insertion and force non-genesis flow through `ProcessBlock`.  

### High

3. [DONE] `high` - P2P validation for non-tip fork blocks is weaker than tip blocks  
   - **Location:** `block.go` (`ValidateBlockP2P`)  
   - **Problem:** Full `NextDifficulty` and median-time checks are only strict on tip-extension path; side-chain/fork blocks can bypass equivalent chain-context checks.  
   - **Impact:** Weakly-validated forks can accumulate in storage/memory and influence reorg dynamics under edge conditions.  
   - **Required fix:** Add parent-chain-context difficulty/timestamp validation for fork blocks too (not only best-tip extensions).
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Unified chain-context validation now derives expected LWMA difficulty and median-time from the block's actual parent branch for all non-genesis blocks (tip and non-tip), then enforces both checks in shared `validateBlockWithContext`; both `ValidateBlockP2P` and `ProcessBlock` use this same path.  

4. [DONE] `high` - Global P2P payload cap is shared across different protocol payload classes  
   - **Location:** `p2p/util.go` (`MaxMessageSize`, `readLengthPrefixed`), `p2p/sync.go` (`readMessage` paths), `p2p/node.go`/`p2p/dandelion.go` (direct `readLengthPrefixed` paths)  
   - **Problem:** A single 16MB pre-decode limit is reused for sync/PEX typed messages and block/tx/dandelion stream payloads, while consensus objects (e.g., blocks) are much smaller.  
   - **Impact:** Memory-pressure DoS via oversized-but-transport-valid payloads; weak separation between control-path and bulk-sync limits.  
   - **Required fix:** Enforce protocol/message-class-specific hard caps before allocation/decode (sync by message type; block/tx/dandelion by stream protocol), while preserving sync batching with explicit response byte budgets.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Added explicit per-class read caps before allocation via `readLengthPrefixedWithLimit`/`readMessageWithLimit`; wired sync and PEX to message-type-specific limits (`readSyncMessage`, `readPEXMessage`), and block/tx/dandelion direct streams to protocol-specific caps. Added sync response byte-budget trimming for headers/blocks/mempool so batching remains supported but bounded.

5. [DONE] `high` - Sync mempool fetch unmarshals unbounded `[][]byte` payloads  
   - **Location:** `p2p/sync.go` (`fetchAndProcessMempool`, `handleGetMempool`), `p2p/util.go`  
   - **Problem:** No limit on transaction count before full JSON decode.  
   - **Impact:** Remote memory amplification / CPU exhaustion via large mempool response payloads.  
   - **Required fix:** Enforce max entry count and byte budget; use streaming decode with limits.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Added `MaxSyncMempoolTxCount` (5000, aligned with default mempool capacity) in `p2p/util.go`. On the receiving side (`fetchAndProcessMempool`), decoded `[][]byte` is now capped by entry count and decoded byte budget via `trimByteSliceBatch` before any processing loop. On the sending side (`handleGetMempool`), replaced the no-op `len(txs)` count parameter with the same `MaxSyncMempoolTxCount` cap so honest nodes also bound entry count.  

6. [DONE] `high` - `findTxBoundary()` parses attacker-controlled counts without safety bounds  
   - **Location:** `tx_aux.go` (`findTxBoundary`)  
   - **Problem:** `inputCount`/`outputCount`/`ringSize` are used for loop arithmetic without strict upper limits.  
   - **Impact:** CPU burn and malformed-tail parsing abuse in aux-data decode path.  
   - **Required fix:** Apply hard limits matching `DeserializeTx` and fail fast on overflow/over-budget paths.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Added hard caps in `findTxBoundary` derived from protocol constants (`maxInputs=256`, `maxOutputs=256`, `maxRingSize=RingSize` (16), `maxProofSize=1024` per Bulletproof buffer, `maxSigSize=96+64*RingSize` (1120) per RingCT CLSAG buffer); each field is checked immediately after decode and returns `len(data)` (no valid boundary) on violation, preventing CPU burn and malformed-tail parsing. Values are tighter than `DeserializeTx`'s looser local caps.  

7. [DONE] `high` - Expensive `submitblock` path has no route-level abuse throttling  
   - **Location:** `api_handlers.go` (`handleSubmitBlock`)  
   - **Problem:** PoW verification is expensive; endpoint lacks explicit per-client/per-window throttling.  
   - **Impact:** Authenticated abuse can degrade node responsiveness materially.  
   - **Required fix:** Add token/IP bucket rate limit + concurrent validation cap for this route.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Added route-scoped abuse controls for `POST /api/mining/submitblock`: per-client token-bucket limiting keyed by request IP (`2 req/s`, burst `4`, stale-entry TTL cleanup) plus a bounded concurrent validation gate (`2` in-flight submits). Over-limit and saturated requests now fail fast with `429` before calling `SubmitBlock`.  

8. [WONTFIX] `high` - Destructive purge endpoint password gate can be weakened by server state  
   - **Location:** `api_handlers.go` (`handlePurgeData`)  
   - **Problem:** Password compare is against server-held byte slice state; if not initialized as expected, it can degrade second-factor semantics.  
   - **Impact:** Inconsistent protection for chain-destructive operation.  
   - **Required fix:** Require non-empty loaded wallet state + non-empty password state, and reject purge otherwise; prefer dedicated admin secret separate from wallet password.
   - **Status:** wontfix (2026-02-12)  
   - **Rationale:** Enforcing wallet-loaded/password-state preconditions blocks expected walletless `--daemon` purge behavior, which is required for this deployment model.  

9. [DONE] `high` - Invalid-block senders are not aggressively penalized in all sync failure branches  
   - **Location:** `p2p/sync.go` (`handleNewBlock`, recovery/retry paths)  
   - **Problem:** Repeated invalid block delivery can be retried/ignored without deterministic peer penalty escalation.  
   - **Impact:** Malicious peers can repeatedly consume verification resources.  
   - **Required fix:** Penalize/ban policy on invalid block proof/data across all rejection branches.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Added deterministic invalid-block penalties in sync paths: `handleNewBlock` now penalizes non-duplicate/non-orphan invalid announcements; orphan-recovery now penalizes peers that return hash-matching parent blocks failing validation; and block-by-hash recovery fetch now penalizes empty/undecodable/mismatched-hash responses before trying other peers. Added source-peer tracking in sync download buffering so non-orphan block rejection during ordered sync processing can penalize the delivering peer when provenance is known.  
   - **Regression coverage:** deferred to `Deferred Test Backlog` per fix-first cadence.

### Medium

10. [DONE] `medium` - Chain validation and chain mutation use separate locking windows in some network paths  
    - **Location:** `daemon.go` (`handleBlock`, `processBlockData`)  
    - **Problem:** Validation occurs before the state-mutation lock is taken; chain context can drift between validation and insert attempt.  
    - **Impact:** Non-deterministic accept/reject behavior and edge-case inconsistency under high block race conditions.  
    - **Required fix:** Validate and process under a consistent state snapshot/lock or retry validation after lock acquisition.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Removed pre-lock `ValidateBlockP2P` calls from network ingest paths (`handleBlock`, `processBlockData`) so chain-aware validation and state mutation are performed together in the single authoritative `Chain.ProcessBlock` path under chain lock. This removes the pre-check/post-insert drift window and avoids duplicate validation work on accepted/rejected network blocks.  

11. [DONE] `medium` - Tx identity is not canonical across all call-sites  
    - **Location:** `transaction.go` (`TxID`), `crypto.go` (`ComputeTxHash`), builder callbacks in `api_handlers.go` and `cli.go`  
    - **Problem:** Different hash derivations may be used depending on decode success/fallback path.  
    - **Impact:** Potential tx-tracking mismatches and indexing inconsistency under malformed/edge payloads.  
    - **Required fix:** Define one canonical txid derivation and remove mixed fallback behavior.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Canonicalized txid derivation in wallet transfer wiring by changing `TransferConfig.ComputeTxID` to return `([32]byte, error)` and making builder transfer fail closed on txid derivation errors. API/CLI builder callbacks now use only `DeserializeTx(txData)` -> `tx.TxID()` and no longer fall back to `ComputeTxHash(txData)`, eliminating mixed hash behavior across decode paths.  

12. [DONE] `medium` - Explorer stats endpoint does unbounded historical iteration per request  
    - **Location:** `explorer.go` (`handleStats`)  
    - **Problem:** CPU-heavy full-chain scanning from unauthenticated route.  
    - **Impact:** Public endpoint DoS pressure as chain size grows.  
    - **Required fix:** Cache snapshot + cap traversal + background precompute.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added explorer stats snapshot caching with background precompute (`startStatsPrecompute` + periodic refresh), bounded per-refresh historical traversal (`explorerStatsMaxTraversal`), and request-path serving from cached snapshot in `handleStats`. Also removed per-request full emission scanning by making `getSupplyInfo` incremental and cached.

13. [DONE] `medium` - Storage layer assumes caller correctness for consensus-critical writes  
    - **Location:** `storage.go` (`CommitBlock`, `CommitReorg`, `SaveBlock`)  
    - **Problem:** No internal sanity checks on write path for block linkage/basic structure.  
    - **Impact:** Upstream bug in chain layer immediately persists corrupt state.  
    - **Required fix:** Add minimal invariant checks in storage write transaction (height/hash/tip linkage sanity).
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added storage-layer invariant enforcement in write transactions: `SaveBlock` now rejects nil blocks and non-genesis blocks whose parent is missing; `CommitBlock` now enforces non-nil commit/block, commit hash/height consistency with block header, parent existence for non-genesis, and strict main-tip linkage against current metadata (empty-chain genesis-only, otherwise `height = tip+1` and `prev = tip`). `CommitReorg` now validates reorg shape before mutation (current tip exists, new height math, disconnect set matches indexed main-chain hashes/heights, connect chain parent/height continuity, and `NewTip` consistency) before applying updates.  

14. [DONE] `medium` - Coinbase amount consensus enforcement remains structurally weak  
    - **Location:** `transaction.go` (`validateCoinbase`) + reward creation path  
    - **Problem:** Validation checks proof structure but does not strictly enforce minted amount against protocol reward schedule.  
    - **Impact:** Inflation-detection guarantees are weaker than explicit amount-consensus models.  
    - **Required fix:** Introduce enforceable coinbase-amount commitment rules compatible with privacy model.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Enforced deterministic coinbase amount consensus by deriving a public coinbase blinding from `tx_public_key + block_height + output_index`, switching `CreateCoinbase` to use that consensus blinding, and adding block-level validation (`validateCoinbaseConsensus`) that recomputes and verifies both the expected reward commitment and encrypted amount against `GetBlockReward(height)`. Tightened coinbase structural rules (`validateCoinbase`) to require zero fee and exactly one output, and updated wallet scanning to use the same deterministic derivation for coinbase output amount recovery.  

### Low

15. [DONE] `low` - Genesis treatment relies on bypass path rather than explicit rule branching  
    - **Location:** `block.go` (genesis creation vs regular validation paths)  
    - **Problem:** Genesis acceptance is handled by special call-path behavior, not explicit consensus branching in validator.  
    - **Impact:** Maintenance risk and future refactor hazards.  
    - **Required fix:** Make genesis validation explicit and deterministic in code.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added an explicit genesis branch in shared validator flow (`validateBlockWithContext` -> `validateGenesisBlock`) with deterministic rules (`height=0`, `PrevHash=GenesisPrevHash()`, fixed timestamp/difficulty/nonce, empty tx set, zero merkle root, size cap). Updated `addGenesisBlock` to call chain validation before persistence, removing the prior unvalidated bypass treatment.

16. [DONE] `low` - Serialization comments and invariants are partially inconsistent  
    - **Location:** `block.go` (`Serialize` comments and byte-size notes)  
    - **Problem:** Documentation mismatches can cause future consensus-serialization bugs.  
    - **Impact:** Engineering risk, not immediate exploit.  
    - **Required fix:** Correct comments and add invariant assertions for serialized lengths.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Replaced stale/misleading header-serialization notes with canonical size constants, removed dead placeholder buffer logic from `BlockHeader.Serialize`, and added explicit invariant assertions in both full-header and PoW-header serialization paths to guarantee written byte counts exactly match canonical serialized lengths. Also switched block size accounting to reuse the same canonical header-size constant.

17. [DONE] `low` - Sync `GetBlocksByHeight` request sanity checks are incomplete  
    - **Location:** `p2p/sync.go` (`handleGetBlocksByHeight`)  
    - **Problem:** Missing stricter validation around start height and range intent.  
    - **Impact:** Minor resource inefficiency and protocol noise potential.  
    - **Required fix:** Enforce range bounds relative to local tip.
   - **Status:** fixed (2026-02-12)  
   - **What changed:** Hardened `handleGetBlocksByHeight` request checks to fail fast on non-positive `max_blocks`, return empty responses when `start_height` is above local tip, and clamp requested block count to the locally available height span (`tip - start + 1`) before serving blocks.

18. [DONE] `low` - Explorer server path lacks the same body-size middleware used by API server  
    - **Location:** `explorer.go` startup/router setup  
    - **Problem:** Missing consistent request body cap hardening.  
    - **Impact:** Minor memory abuse surface.  
    - **Required fix:** Apply `MaxBytesReader`/equivalent middleware to explorer routes.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Updated explorer startup to wrap the handler with the same `maxBodySize(..., 1<<20)` middleware used by the API server, ensuring consistent `http.MaxBytesReader` request body caps across explorer routes.

19. [DONE] `high` - Dandelion stem path forwards unvalidated transaction payloads  
    - **Location:** `p2p/dandelion.go` (`HandleStemStream`, `handleStemTx`, `sendStem`)  
    - **Problem:** Stem transactions are accepted/cached/routed before deserialization or structural validation. Validation only occurs later when fluff handler reaches daemon/mempool path.  
    - **Impact:** Attackers can inject large volumes of malformed payloads into stem routing and cache/memory/relay bandwidth without paying validation cost.  
    - **Required fix:** Apply lightweight tx sanity checks (size + deserialize) before caching/routing in stem phase; penalize peers sending malformed stems.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added a stem-phase sanity validator hook in the Dandelion router and wired it from daemon startup to perform `DecodeTxWithAux` + `DeserializeTx` on incoming stem payloads before cache/relay. `HandleStemStream` now rejects malformed stem transactions early and applies peer penalty (`ScorePenaltyInvalid`) for invalid stem payloads.

20. [DONE] `high` - Dandelion tx cache limit is configured but not enforced  
    - **Location:** `p2p/dandelion.go` (`txCacheSize`, `BroadcastTx`, `handleStemTx`, `HandleFluffTx`)  
    - **Problem:** `txCacheSize` field exists but there is no eviction-by-size enforcement; only age-based cleanup runs every 5s with 30-minute retention.  
    - **Impact:** Memory growth under unique tx spam remains high for long windows.  
    - **Required fix:** Enforce strict max cache entries with deterministic eviction policy (LRU/time-bucketed).
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added strict tx-cache cap enforcement on all Dandelion insert paths (`BroadcastTx`, `handleStemTx`, `HandleFluffTx`) via a single locked helper that evicts oldest entries until `txCacheSize` is respected. Eviction is deterministic by `createdAt` with lexicographic tx-hash tie-breaking, retaining existing age-based cleanup as a secondary bound.

21. [DONE] `medium` - Dandelion randomness failures hard-crash the node  
    - **Location:** `p2p/dandelion.go` (`cryptoRandIntn`, `cryptoRandFloat64`)  
    - **Problem:** RNG failure triggers `panic`, taking down the process.  
    - **Impact:** Single entropy subsystem failure becomes total node outage.  
    - **Required fix:** Return errors/fallback behavior instead of panicking inside network message handling paths.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Replaced `panic`-based RNG helpers with error-returning variants and handled failures at each call site. `handleStemTx` now fails open to fluff when randomness is unavailable, stem-peer selection falls back deterministically to the first candidate peer, and epoch neighbor selection uses deterministic parity fallback instead of crashing.

22. [DONE] `high` - Banned-peer gating is explicitly disabled at host layer  
    - **Location:** `p2p/node.go` (`NewNode`, comment around gater disabled)  
    - **Problem:** Connection gater is not wired into libp2p host; ban lists may not be enforced at connection admission boundary.  
    - **Impact:** Banned peers can continue reconnect attempts and consume resources depending on upper-layer checks.  
    - **Required fix:** Re-enable and stabilize connection gater integration or equivalent hard admission filter.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Re-enabled host-layer banned-peer admission filtering by wiring `libp2p.ConnectionGater` in `NewNode` using existing `BanGater`. Also initialized `PeerExchange` before host construction so ban-state checks are available to the gater from startup onward.

23. `high` - Sync fetch decode paths trust unbounded header/block array counts within message budget  
    - **Location:** `p2p/sync.go` (`FetchHeaders`, `FetchBlocks`, `fetchBlocksByHeight`)  
    - **Problem:** Response arrays are fully unmarshaled without per-array element count caps.  
    - **Impact:** Peer can send array-heavy payloads that maximize decode overhead and memory churn within allowed message size.  
    - **Required fix:** Cap decoded element counts and reject over-limit responses before full processing.

24. `medium` - Wallet unlock endpoint has no brute-force throttling  
    - **Location:** `api_handlers.go` (`handleUnlock`)  
    - **Problem:** Unlimited password attempts over authenticated API channel, no delay/backoff/lockout logic.  
    - **Impact:** If API token leaks, online brute-force against wallet password is accelerated.  
    - **Required fix:** Add attempt counters, progressive delay, and temporary lockouts.

25. `medium` - Wallet scanner spent-detection is quadratic over wallet outputs and tx inputs  
    - **Location:** `wallet/scanner.go` (`ScanBlock`, key image check loop)  
    - **Problem:** For each key image in each tx, scanner iterates all spendable outputs and regenerates key images repeatedly.  
    - **Impact:** Large-wallet scan performance collapse under high-input blocks; practical local DoS during rescan/recovery.  
    - **Required fix:** Index wallet outputs by precomputed key image for O(1)/O(log n) spent detection.

26. `medium` - PEX peer-record parsing lacks strict record/address bounds beyond message size  
    - **Location:** `p2p/pex.go` (`exchangeWithPeer`, `json.Unmarshal` into `[]PeerRecord`)  
    - **Problem:** No explicit cap on number of records or addresses per record before decode/processing.  
    - **Impact:** Decode-time CPU/memory amplification from crafted peer lists.  
    - **Required fix:** Enforce hard limits on peer-record count and per-record address count.

27. `high` - Deep reorg/finality limit is defined but not enforced in fork choice  
    - **Location:** `block.go` (`MaxReorgDepth`, `IsFinalized`, `ProcessBlock`, `reorganizeTo`)  
    - **Problem:** The code defines finality depth (`MaxReorgDepth`) and exposes `IsFinalized`, but reorg acceptance path never enforces it.  
    - **Impact:** A higher-work alternative chain can rewrite arbitrarily deep history, which is a classic private-network PoW attack surface (low-hashrate chain rewrites).  
    - **Required fix:** Enforce reorg depth checks in `ProcessBlock`/`reorganizeTo` and reject chain switches that disconnect finalized heights.

28. `high` - Difficulty-to-target conversion is coarse and decouples claimed work from real work  
    - **Location:** `crypto-rs/src/pow.rs` (`blocknet_difficulty_to_target`), `block.go` (`ProcessBlock` cumulative work)  
    - **Problem:** Target mapping is bucketed by leading-zero bits rather than an exact `2^256 / difficulty` mapping. Many different difficulty values map to the same effective target while chainwork still sums raw difficulty values.  
    - **Impact:** Chain-selection weight can be inflated relative to actual PoW hardness, enabling work-accounting distortion and reorg leverage with less real hash effort than the numeric difficulty implies.  
    - **Required fix:** Replace target conversion with exact integer arithmetic (`target = floor((2^256-1)/difficulty)`) and ensure cumulative work metric is mathematically aligned with validation target.

29. `medium` - Cumulative chainwork uses unchecked `uint64` arithmetic  
    - **Location:** `block.go` (`addBlockInternal`, `ProcessBlock`, `loadFromStorage`)  
    - **Problem:** Chainwork accumulation (`parentWork + difficulty`) has no overflow checks or saturating math.  
    - **Impact:** Overflow/wrap can corrupt fork-choice ordering under extreme values or long-lived networks, producing invalid best-chain selection behavior.  
    - **Required fix:** Add overflow detection and reject/handle blocks that would overflow cumulative work; migrate chainwork to wider arithmetic if needed.

30. `critical` - Transaction validation does not prove ring members/commitments are canonical on-chain outputs  
    - **Location:** `transaction.go` (`ValidateTransaction`, `VerifyRingCT` call path)  
    - **Problem:** Validation checks cryptographic consistency of provided ring data but does not bind each `(RingMember, RingCommitment)` pair to a real historical UTXO in canonical chain state.  
    - **Impact:** A transaction can be constructed over attacker-chosen ring sets that are cryptographically self-consistent but not chain-grounded, creating spend-from-nowhere/inflation risk.  
    - **Required fix:** Extend validation to require every ring member+commitment pair resolves to an existing canonical output and matches chain state commitments.

31. `high` - Zero-length proof/signature slices can panic through FFI pointer dereference  
    - **Location:** `crypto.go` (`VerifyRangeProof`, `VerifyRingCT`, other `unsafe.Pointer(&slice[0])` call sites)  
    - **Problem:** Multiple wrappers pass `&slice[0]` into C without explicit non-empty checks; malformed transactions can carry empty proof/signature fields.  
    - **Impact:** Remote crash/DoS via panic (`index out of range`) before graceful rejection.  
    - **Required fix:** Add strict length checks before all FFI pointer conversions and return validation errors instead of panicking.

32. `high` - Chain cache mutates maps while holding read lock  
    - **Location:** `block.go` (`GetBlock`, `getBlockByHeightLocked`)  
    - **Problem:** Code writes to `c.blocks`/`c.byHeight` while under `RLock`, violating Go map concurrency safety guarantees.  
    - **Impact:** Concurrent map write panic/data race under load, resulting in node crash or undefined behavior.  
    - **Required fix:** Never mutate maps under `RLock`; promote to write lock or use dedicated synchronized cache structures.

33. `high` - Inbound fluff transaction path bypasses Dandelion fluff handler semantics  
    - **Location:** `p2p/node.go` (`ProtocolTx` -> `handleTxStream`), `p2p/dandelion.go` (`HandleFluffTx`)  
    - **Problem:** `ProtocolTx` stream currently dispatches directly to node tx handler path instead of passing through `HandleFluffTx` rebroadcast/cache logic.  
    - **Impact:** Reduced propagation robustness and privacy model drift (fluff handling behavior differs from intended Dandelion path).  
    - **Required fix:** Route inbound `ProtocolTx` through Dandelion fluff handler (or unify equivalent behavior in one path).

34. `medium` - Mempool admission does not explicitly reject coinbase transactions  
    - **Location:** `mempool.go` (`AddTransaction`)  
    - **Problem:** Coinbase txs skip normal validation branch but are not explicitly rejected at mempool boundary.  
    - **Impact:** Invalid object class can occupy mempool path and increase weird-state/edge-case risk.  
    - **Required fix:** Hard-reject `tx.IsCoinbase()` in mempool admission with explicit error.

## Giant Work Queue

### P0 - Must ship immediately

1. Refactor block acceptance into one mandatory validated chain-ingest function used by all paths.
2. Lock down `AddBlock` so non-genesis use cannot bypass consensus checks.
3. Harden `ValidateBlockP2P` for fork/side-chain context with strict chain-aware rules.
4. Add peer penalty escalation for invalid-block spam in all sync rejection branches.
5. Add route-level throttling and concurrency limits for expensive validation endpoints (`submitblock` first).
6. Enforce hard protocol payload limits per message type before allocation/decode.

### P1 - Next wave

7. Cap and stream-parse mempool sync payloads.
8. Add strict bounds/overflow checks to `findTxBoundary` and aux parsing logic.
9. Canonicalize txid derivation and remove multi-hash fallback behavior.
10. Add storage write-time invariants for consensus-critical mutations.
11. Harden destructive API operations with dedicated admin secret and explicit preconditions.

### P2 - Operational resilience

12. Add cache/precompute for expensive explorer/stat endpoints.
13. Introduce protocol-level abuse accounting for malformed tx/block streams.
14. Add explicit genesis validation branch in consensus validator.
15. Normalize serialization docs and invariant guards.
16. Tighten sync request parameter validation and quotas.
17. Add stem-phase tx sanity validation and malformed-stem peer penalties.
18. Enforce Dandelion cache size caps with deterministic eviction.
19. Remove panic-based failure handling from Dandelion RNG helpers.
20. Re-enable/replace connection admission gating for banned peers.
21. Add explicit decode limits for sync header/block response arrays.
22. Add wallet unlock brute-force protection controls.
23. Rework scanner spent-detection to indexed key-image lookup.
24. Add strict limits for PEX peer record and address list decoding.
25. Enforce finalized-depth reorg rejection in consensus fork-choice path.
26. Replace coarse difficulty-to-target mapping with exact integer conversion.
27. Add overflow-safe cumulative chainwork accounting.
28. Enforce on-chain canonical membership checks for all RingCT ring member/commitment pairs.
29. Add FFI wrapper guards for zero-length proof/signature/message slices.
30. Eliminate map mutations under read locks in chain cache code paths.
31. Route inbound `ProtocolTx` through Dandelion fluff semantics (or unified equivalent path).
32. Explicitly reject coinbase transactions at mempool admission boundary.

## Regression Check List (queued, not implemented here)

1. Ensure no path can call chain-state mutation without prior consensus validation.
2. Ensure malformed/oversized p2p messages are rejected before allocation pressure.
3. Ensure fork blocks undergo strict chain-context difficulty/timestamp checks.
4. Ensure txid is identical across API/CLI/mempool/storage code paths.
5. Ensure destructive endpoints fail closed when auth/password state is absent.
6. Ensure stem-phase malformed tx payloads are rejected before relay/cache.
7. Ensure Dandelion cache cannot exceed configured max entries under spam.
8. Ensure banned peers are denied at connection admission layer.
9. Ensure sync responses exceeding header/block count caps are rejected.
10. Ensure wallet unlock attempts trigger backoff/lockout policy.
11. Ensure reorg attempts beyond finality depth are rejected deterministically.
12. Ensure numeric difficulty and effective target correspond one-to-one.
13. Ensure cumulative work arithmetic cannot wrap.
14. Ensure ring members/commitments in every validated tx resolve to canonical chain outputs.
15. Ensure malformed empty proof/signature fields cannot trigger panics in FFI wrappers.
16. Ensure chain cache reads never perform map writes under `RLock`.
17. Ensure inbound fluff transactions follow one canonical Dandelion propagation path.
18. Ensure mempool rejects coinbase transactions unconditionally.

## Deferred Test Backlog (fix-first cadence)

1. (A) Add a regression test that directly calls `ProcessBlock` with an invalid block and proves mutation is rejected without caller-side pre-validation.
1. (B) Re-enable a production-faithful `TestProcessBlockData_ReorgRemovesTxsFromAllConnectedBlocks` that exercises the real `processBlockData` + `ValidateBlockP2P` path with valid PoW blocks.
1. (C) Re-enable a production-faithful `TestProcessBlockData_ReorgRequeuesTxsFromDisconnectedBlocks` that verifies requeue semantics through an actual reorg in daemon ingest.
2. (a) Add a regression test that proves `AddBlock` rejects non-genesis blocks once finding #2 is implemented.
2. (b) Add a regression test that proves `AddBlock` still accepts valid genesis only once and fails duplicate genesis insertion.
5. (a) Add a regression test that crafts a mempool sync response exceeding `MaxSyncMempoolTxCount` entries and proves the receiver truncates before processing.
5. (b) Add a regression test that crafts a mempool sync response exceeding `SyncMempoolResponseByteBudget` in decoded bytes and proves truncation before processing.
6. (a) Add a regression test that crafts tx data with `inputCount > 256` and proves `findTxBoundary` returns `len(data)` (no valid boundary).
6. (b) Add a regression test that crafts tx data with `outputCount > 256` and proves `findTxBoundary` returns `len(data)`.
6. (c) Add a regression test that crafts tx data with `ringSize > 128` in an input and proves `findTxBoundary` returns `len(data)`.
6. (d) Add a regression test that crafts tx data with `proofLen > 10240` in an output and proves `findTxBoundary` returns `len(data)`.
6. (e) Add a regression test that crafts tx data with `sigLen > 131072` in an input and proves `findTxBoundary` returns `len(data)`.
11. (a) Add a regression test that verifies API/CLI transfer builder `ComputeTxID` derives txid via `DeserializeTx(txData)` + `tx.TxID()` only, with no `ComputeTxHash` fallback path.
11. (b) Add a regression test that forces txid derivation failure in transfer flow and proves builder returns an error instead of emitting a fallback txid.
12. (a) Add a regression test that repeatedly calls explorer `/stats` on a long chain and proves request-path processing does not rescan full history each time (serves cached snapshot).
12. (b) Add a regression test that advances chain tip and proves stats refresh is bounded to configured traversal cap while background precompute updates served data.

### Deferred test restoration after bug crunch

- Rebuild deleted `daemon_reorg_mempool_test.go` coverage around daemon ingest + reorg mempool reconciliation.
- Rebuild deleted `sync_reorg_test.go` coverage around deep reorg sync recovery and near-tip overlap behavior.
- Rebuild deleted `mempool_reorg_test.go` coverage for mempool connect/disconnect behavior across reorganizations.
- Rebuild deleted `p2p/sync_recovery_test.go` coverage for orphan backfill and sync-manager recovery flow.
