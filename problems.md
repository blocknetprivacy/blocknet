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
   - **What changed:** Removed exported `AddBlock` usage path; introduced unexported `addGenesisBlock` for empty-chain genesis init only; added explicit fail-fast guards in `addBlockInternal` to reject any non-genesis or non-empty-chain unvalidated insertion and force non-genesis flow through `ProcessBlock`. Follow-up cleanup also removed stale non-genesis `addBlockInternal` usage from `tests.go` and switched those paths to validated `ProcessBlock` ingestion.  

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
   - **What changed:** Added `MaxSyncMempoolTxCount` (5000, aligned with default mempool capacity) in `p2p/util.go`. On the receiving side (`fetchAndProcessMempool`), mempool responses now run `ensureJSONArrayMaxItems(..., MaxSyncMempoolTxCount)` before `json.Unmarshal` and then apply decoded byte-budget trimming via `trimByteSliceBatch` before processing. On the sending side (`handleGetMempool`), replaced the no-op `len(txs)` count parameter with the same `MaxSyncMempoolTxCount` cap so honest nodes also bound entry count.  

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
   - **What changed:** Added deterministic invalid-block penalties in sync paths: `handleNewBlock` now penalizes non-duplicate/non-orphan invalid announcements; orphan-recovery now penalizes peers that return hash-matching parent blocks failing validation; and block-by-hash recovery fetch now penalizes empty/undecodable/mismatched-hash responses before trying other peers. Added source-peer tracking in sync download buffering so non-orphan block rejection during ordered sync processing can penalize the delivering peer when provenance is known. Follow-up hardening now preserves source-peer attribution for the fallback `fetchBlocksFromAnyPeer` rescue path as well, so invalid rescue batches can be penalized deterministically.
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

23. [DONE] `high` - Sync fetch decode paths trust unbounded header/block array counts within message budget  
    - **Location:** `p2p/sync.go` (`FetchHeaders`, `FetchBlocks`, `fetchBlocksByHeight`)  
    - **Problem:** Response arrays are fully unmarshaled without per-array element count caps.  
    - **Impact:** Peer can send array-heavy payloads that maximize decode overhead and memory churn within allowed message size.  
    - **Required fix:** Cap decoded element counts and reject over-limit responses before full processing.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added pre-decode JSON array element-count validation for `FetchHeaders`, `FetchBlocks`, and `fetchBlocksByHeight`. Each path now rejects over-limit responses (`MaxHeadersPerRequest` / `MaxBlocksPerRequest`) before unmarshaling into `[][]byte`, preventing unbounded decoded entry counts from peer responses.

24. [DONE] `medium` - Wallet unlock endpoint has no brute-force throttling  
    - **Location:** `api_handlers.go` (`handleUnlock`)  
    - **Problem:** Unlimited password attempts over authenticated API channel, no delay/backoff/lockout logic.  
    - **Impact:** If API token leaks, online brute-force against wallet password is accelerated.  
    - **Required fix:** Add attempt counters, progressive delay, and temporary lockouts.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added per-client-IP unlock attempt tracking in the API server with progressive backoff, temporary lockout after repeated failures, and automatic state expiry. `handleUnlock` now enforces pre-attempt backoff/lockout checks, returns `429` with `Retry-After` during enforced cooldown windows, applies delay on failed password checks, and resets attempt state on successful unlock.

25. [DONE] `medium` - Wallet scanner spent-detection is quadratic over wallet outputs and tx inputs  
    - **Location:** `wallet/scanner.go` (`ScanBlock`, key image check loop)  
    - **Problem:** For each key image in each tx, scanner iterates all spendable outputs and regenerates key images repeatedly.  
    - **Impact:** Large-wallet scan performance collapse under high-input blocks; practical local DoS during rescan/recovery.  
    - **Required fix:** Index wallet outputs by precomputed key image for O(1)/O(log n) spent detection.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added precomputed spendable-output key-image indexing in `ScanBlock` and switched spent detection to direct key-image lookups instead of nested output scans. Scanner now builds a key-image map once, updates it as newly owned outputs are discovered, marks spends by mapped one-time pubkeys, and removes consumed key-image entries after processing.

26. [DONE] `medium` - PEX peer-record parsing lacks strict record/address bounds beyond message size  
    - **Location:** `p2p/pex.go` (`exchangeWithPeer`, `json.Unmarshal` into `[]PeerRecord`)  
    - **Problem:** No explicit cap on number of records or addresses per record before decode/processing.  
    - **Impact:** Decode-time CPU/memory amplification from crafted peer lists.  
    - **Required fix:** Enforce hard limits on peer-record count and per-record address count.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added explicit inbound PEX response bounds in `exchangeWith` before full `[]PeerRecord` decode. The code now enforces a hard cap on total peer records (`MaxPeerRecordsPerResponse`) and stream-parses each record object so `addrs` arrays are counted token-by-token and rejected immediately once `MaxPeerAddrsPerRecord` is exceeded, avoiding full address-list materialization prior to rejection.

27. [DONE] `high` - Deep reorg/finality limit is defined but not enforced in fork choice  
    - **Location:** `block.go` (`MaxReorgDepth`, `IsFinalized`, `ProcessBlock`, `reorganizeTo`)  
    - **Problem:** The code defines finality depth (`MaxReorgDepth`) and exposes `IsFinalized`, but reorg acceptance path never enforces it.  
    - **Impact:** A higher-work alternative chain can rewrite arbitrarily deep history, which is a classic private-network PoW attack surface (low-hashrate chain rewrites).  
    - **Required fix:** Enforce reorg depth checks in `ProcessBlock`/`reorganizeTo` and reject chain switches that disconnect finalized heights.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added finality-boundary enforcement for fork switching in `block.go`. `ProcessBlock` now runs a reorg finality guard before attempting heavier-chain adoption, and `reorganizeTo` also enforces the same check defensively. The new guard computes the fork point and rejects any reorg whose divergence height is below `height - MaxReorgDepth`, preventing chain switches that would disconnect finalized history.

28. [DONE] `high` - Difficulty-to-target conversion is coarse and decouples claimed work from real work  
    - **Location:** `crypto-rs/src/pow.rs` (`blocknet_difficulty_to_target`), `block.go` (`ProcessBlock` cumulative work)  
    - **Problem:** Target mapping is bucketed by leading-zero bits rather than an exact `2^256 / difficulty` mapping. Many different difficulty values map to the same effective target while chainwork still sums raw difficulty values.  
    - **Impact:** Chain-selection weight can be inflated relative to actual PoW hardness, enabling work-accounting distortion and reorg leverage with less real hash effort than the numeric difficulty implies.  
    - **Required fix:** Replace target conversion with exact integer arithmetic (`target = floor((2^256-1)/difficulty)`) and ensure cumulative work metric is mathematically aligned with validation target.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Replaced the coarse leading-zero bucket conversion in `blocknet_difficulty_to_target` with exact 256-bit integer division (`floor((2^256-1)/difficulty)`) implemented via limb-wise long division. This restores a one-to-one difficulty-to-target mapping used by PoW validation, removing the prior bucket collapse that let multiple numeric difficulty values share the same effective target while cumulative work still accrued by difficulty.

29. [DONE] `medium` - Cumulative chainwork uses unchecked `uint64` arithmetic  
    - **Location:** `block.go` (`addBlockInternal`, `ProcessBlock`, `loadFromStorage`)  
    - **Problem:** Chainwork accumulation (`parentWork + difficulty`) has no overflow checks or saturating math.  
    - **Impact:** Overflow/wrap can corrupt fork-choice ordering under extreme values or long-lived networks, producing invalid best-chain selection behavior.  
    - **Required fix:** Add overflow detection and reject/handle blocks that would overflow cumulative work; migrate chainwork to wider arithmetic if needed.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added checked cumulative-work arithmetic in `block.go` via a shared helper that rejects `uint64` overflow before summing `parentWork + difficulty`. `addBlockInternal`, `ProcessBlock`, and `loadFromStorage` now fail closed on overflow instead of wrapping, and load-time work-offset adjustment now uses the same checked addition while also rejecting inconsistent stored tip-work metadata.

30. [DONE] `critical` - Transaction validation does not prove ring members/commitments are canonical on-chain outputs  
    - **Location:** `transaction.go` (`ValidateTransaction`, `VerifyRingCT` call path)  
    - **Problem:** Validation checks cryptographic consistency of provided ring data but does not bind each `(RingMember, RingCommitment)` pair to a real historical UTXO in canonical chain state.  
    - **Impact:** A transaction can be constructed over attacker-chosen ring sets that are cryptographically self-consistent but not chain-grounded, creating spend-from-nowhere/inflation risk.  
    - **Required fix:** Extend validation to require every ring member+commitment pair resolves to an existing canonical output and matches chain state commitments.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Extended transaction validation to enforce canonical ring binding by requiring each `(RingMember, RingCommitment)` pair to match an output stored in canonical chain state before RingCT verification. This was wired through both block validation and mempool admission by adding a shared ring-member checker callback and chain-backed canonical lookup, so non-chain-grounded ring sets are rejected consistently across consensus and ingress paths. Follow-up hardening now requires the matched output to resolve to the active main-chain block at its indexed height (not merely appear in historical output storage), preventing reorged-out outputs from being treated as canonical ring members.

31. [DONE] `high` - Zero-length proof/signature slices can panic through FFI pointer dereference  
    - **Location:** `crypto.go` (`VerifyRangeProof`, `VerifyRingCT`, other `unsafe.Pointer(&slice[0])` call sites)  
    - **Problem:** Multiple wrappers pass `&slice[0]` into C without explicit non-empty checks; malformed transactions can carry empty proof/signature fields.  
    - **Impact:** Remote crash/DoS via panic (`index out of range`) before graceful rejection.  
    - **Required fix:** Add strict length checks before all FFI pointer conversions and return validation errors instead of panicking.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added explicit nil/empty input guards in the FFI verification wrappers used by transaction validation (`VerifyRangeProof`, `VerifyRing`, `VerifyRingCT`). These paths now reject missing/empty proof, signature, ring, or message slices with validation errors before any `&slice[0]` conversion, preventing panic-based DoS from malformed payloads.

32. [DONE] `high` - Chain cache mutates maps while holding read lock  
    - **Location:** `block.go` (`GetBlock`, `getBlockByHeightLocked`)  
    - **Problem:** Code writes to `c.blocks`/`c.byHeight` while under `RLock`, violating Go map concurrency safety guarantees.  
    - **Impact:** Concurrent map write panic/data race under load, resulting in node crash or undefined behavior.  
    - **Required fix:** Never mutate maps under `RLock`; promote to write lock or use dedicated synchronized cache structures.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Removed cache-map mutations from the `RLock` read path. `getBlockByHeightLocked` is now strictly read-only, and `GetBlock` now upgrades to `Lock` only for cache insertion (with a re-check to avoid duplicate writes), preventing map writes while holding only a read lock.

33. [DONE] `high` - Inbound fluff transaction path bypasses Dandelion fluff handler semantics  
    - **Location:** `p2p/node.go` (`ProtocolTx` -> `handleTxStream`), `p2p/dandelion.go` (`HandleFluffTx`)  
    - **Problem:** `ProtocolTx` stream currently dispatches directly to node tx handler path instead of passing through `HandleFluffTx` rebroadcast/cache logic.  
    - **Impact:** Reduced propagation robustness and privacy model drift (fluff handling behavior differs from intended Dandelion path).  
    - **Required fix:** Route inbound `ProtocolTx` through Dandelion fluff handler (or unify equivalent behavior in one path).
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Updated `ProtocolTx` ingress in `p2p/node.go` so `handleTxStream` now routes inbound transaction payloads to `dandel.HandleFluffTx` instead of calling the node tx callback directly. This restores Dandelion fluff-path semantics (seen-cache handling, local callback, and rebroadcast behavior) for all inbound fluff transactions.

34. [DONE] `medium` - Mempool admission does not explicitly reject coinbase transactions  
    - **Location:** `mempool.go` (`AddTransaction`)  
    - **Problem:** Coinbase txs skip normal validation branch but are not explicitly rejected at mempool boundary.  
    - **Impact:** Invalid object class can occupy mempool path and increase weird-state/edge-case risk.  
    - **Required fix:** Hard-reject `tx.IsCoinbase()` in mempool admission with explicit error.
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added an explicit early guard in `mempool.go` `AddTransaction` that rejects `tx.IsCoinbase()` with a clear error before any mempool admission logic. The transaction validation path is now uniformly applied to admitted transactions only, with coinbase objects denied at the ingress boundary.

35. [DONE] `critical` - RingCT input fields are not bound to the externally validated tx input fields  
    - **Location:** `transaction.go` (`ValidateTransaction`, `verifyCommitmentBalance`), `crypto.go` (`VerifyRingCT`), `crypto-rs/src/ring.rs` (`blocknet_ringct_verify`)  
    - **Problem:** External `TxInput.KeyImage` and `TxInput.PseudoOutput` are used for spent/balance checks, while signature verification validates only bytes in `RingSignature`; Rust verify derives key image/pseudo-output from signature payload and does not enforce equality with external fields.  
    - **Impact:** Field-level tampering risk between signed payload and consensus-checked fields can enable spend/balance safety violations.  
    - **Required fix:** Cryptographically bind and/or explicitly equality-check external input fields (`KeyImage`, `PseudoOutput`) against values extracted from verified signature payload before spent and balance checks.  
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added explicit RingCT binding extraction in `crypto.go` (`ExtractRingCTBinding`) and enforced it in `ValidateTransaction` so each input now verifies that external `KeyImage` and `PseudoOutput` exactly match the key image and pseudo-output embedded in the verified RingCT signature payload. Spent-key-image checks now run only after this equality binding, ensuring double-spend and commitment-balance validation operate on cryptographically bound input fields.

36. [DONE] `high` - Side-chain key image reuse is not prevented across fork blocks  
    - **Location:** `block.go` (`ProcessBlock`, `validateBlockForProcessLocked`, key-image spent checks), storage key-image update paths  
    - **Problem:** Non-main-chain block validation checks spent state from main-chain view, and fork-accepted blocks do not reserve/update spent-key-image state until reorg adoption.  
    - **Impact:** Repeated key images can accumulate on side branches and survive validation until fork-choice transition.  
    - **Required fix:** Enforce branch-aware key-image uniqueness/spent tracking across candidate fork chains during validation and storage of side-chain blocks.  
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Updated `validateBlockForProcessLocked` to use a branch-aware spent checker for non-genesis blocks. New logic walks the candidate parent ancestry and treats key images from off-main-chain ancestors as already spent during validation, while still consulting canonical main-chain spent state. This prevents accepting side-branch blocks that reuse key images already spent earlier on that same fork branch before reorg adoption.
    - **Regression coverage:** Added `TestBranchAwareSpentCheckerIncludesSideBranchAncestry` in `block_branch_keyimage_test.go` to verify side-branch ancestor key images are treated as spent during candidate-branch validation, while unrelated side-branch key images are not.

37. [DONE] `high` - P2P gossip ingress still permits expensive-validation DoS with weak direct penalties on some paths  
    - **Location:** `daemon.go` (`handleBlock`, `handleTx`), expensive validation path in `block.go` (`validatePoW`), PoW params in `crypto-rs/src/pow.rs`  
    - **Problem:** Invalid gossip payloads on daemon handlers are often dropped/returned without immediate sender penalty, while block validation includes expensive Argon2id work.  
    - **Impact:** Attackers can repeatedly trigger costly validation work with limited deterrence in these ingress routes.  
    - **Required fix:** Apply deterministic peer penalties/rate controls on invalid gossip at all ingress handlers, and ensure expensive-validation paths are guarded by cheap prefilters where possible.  
    - **Status:** fixed (2026-02-13)  
    - **What changed:** Hardened daemon gossip ingress in `daemon.go` by adding deterministic peer penalties for malformed/invalid `handleBlock` and `handleTx` payloads, while still allowing duplicate tx gossip without penalty. Added cheap block prefilters (version/size/coinbase-shape checks) before `ProcessBlock` in both direct handler and sync ingest (`processBlockData`) so clearly-invalid blocks are rejected before expensive validation paths such as PoW. Added an explicit expensive-validation gate on gossip block handling: per-peer cooldown plus a global in-flight cap before entering `ProcessBlock`, with deterministic penalties for rate-limit/concurrency violations (`block gossip rate limit exceeded` / `block gossip validation busy`).  
    - **Regression coverage:** Added `TestHandleTxPenalizesMalformedPayload`, `TestHandleBlockPenalizesCheapPrefilterFailure`, and `TestHandleBlockPenalizesRateLimitExceeded` in `daemon_gossip_penalty_test.go`.

38. [DONE] `medium` - Ring-member canonicality check is O(total_outputs) per ring member  
    - **Location:** `block.go` (`isCanonicalRingMemberLocked`), `storage.go` (`GetAllOutputs`), `transaction.go` (`ValidateTransaction`)  
    - **Problem:** Canonicality checks repeatedly scan all outputs for each ring member/commitment pair.  
    - **Impact:** Validation cost scales poorly with chain growth and ring-member count, enabling practical computational DoS pressure.  
    - **Required fix:** Introduce indexed canonical output lookup (keyed by pubkey+commitment or equivalent) and use O(1)/O(log n) membership checks in validation paths.  
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Replaced per-call output scans in `isCanonicalRingMemberLocked` with a canonical main-chain membership index keyed by `(pubkey||commitment)` in `Chain`. The index is rebuilt from main-chain height mapping and cached for O(1) lookups, with automatic refresh on tip changes and explicit dirtying on chain-state transitions (add/reorg/truncate/load), so validation no longer performs O(total_outputs) scans per ring member.  
    - **Regression coverage:** Added `TestCanonicalRingIndexRefreshesAcrossReorgTipChange` in `block_canonical_index_test.go` to verify indexed canonical membership stays correct across tip changes/reorgs.

39. [DONE] `medium` - SSE subscriber lifecycle leak causes unbounded subscriber growth  
    - **Location:** `api_sse.go` (`handleEvents`), `daemon.go` (`SubscribeBlocks`, `SubscribeMinedBlocks`, notify paths)  
    - **Problem:** SSE requests append subscriber channels but disconnect paths do not unsubscribe/remove channels from daemon subscriber sets.  
    - **Impact:** Repeated connect/disconnect grows memory and fanout overhead over time.  
    - **Required fix:** Add unsubscribe lifecycle management (or context-bound auto-cleanup) for block/mined subscriber channels on client disconnect.  
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Added explicit unsubscribe APIs in `daemon.go` (`UnsubscribeBlocks`, `UnsubscribeMinedBlocks`) and wired `api_sse.go` `handleEvents` to defer unsubscribe on disconnect. This ensures SSE subscriptions are removed when request context closes, preventing unbounded subscriber-slice growth across repeated client reconnects.  
    - **Regression coverage:** Added `TestHandleEventsUnsubscribesOnClientDisconnect` in `api_sse_test.go` to verify subscribe-on-connect and unsubscribe-on-disconnect behavior for both block and mined-block channels.

40. [DONE] `medium` - Docker compose deployment defaults are insecure for exposed environments  
    - **Location:** `docker/docker-compose.yml`, API serving path in `api_server.go`  
    - **Problem:** Defaults expose API on `0.0.0.0` and use weak default wallet password (`changeme`) under plain HTTP assumptions.  
    - **Impact:** Elevated operational compromise risk for internet-exposed deployments.  
    - **Required fix:** Harden defaults (loopback bind, required strong password input, explicit secure deployment guidance) and make unsafe defaults opt-in.  
    - **Status:** fixed (2026-02-12)  
    - **What changed:** Hardened Docker defaults by removing weak password fallback in `docker/docker-compose.yml` (password now required), binding API/explorer published ports to localhost by default, and adding weak-password rejection in `docker/entrypoint.sh` unless explicitly overridden via `BLOCKNET_ALLOW_WEAK_WALLET_PASSWORD=true`. Added API bind safety warning in `api_server.go` for non-loopback listen addresses and updated `docker/README.md` with explicit secure-deployment guidance and localhost exposure defaults.

41. [TODO] `high` - `problems.md` work queue conflicts with finding status and can mislead launch triage  
   - **Location:** `problems.md` (`## Giant Work Queue`, items `33`-`38`)  
   - **Problem:** Queue items `33`-`38` remain marked `[TODO]` while corresponding findings in `## Findings` are already `[DONE]`.  
   - **Impact:** Operators/engineers can incorrectly treat fixed security work as still open, diluting launch-gate signal and creating process risk during relaunch.  
   - **Required fix:** Reconcile queue state with findings state and enforce one source of truth for open/closed status transitions.

42. [TODO] `medium` - Aux-era findings remain active-looking after aux path removal  
   - **Location:** `problems.md` entries that reference `tx_aux.go`, `DecodeTxWithAux`, `findTxBoundary`  
   - **Problem:** Historical findings tied to removed aux architecture are not clearly marked as superseded-by-removal in the current relaunch model.  
   - **Impact:** Readers may spend effort auditing/debating non-existent attack surfaces and miss memo-era risks that replaced them.  
   - **Required fix:** Annotate aux-era findings as "retired by architecture change" (with date/commit context) and separate historical notes from active threat surface.

43. [TODO] `medium` - TxID-canonicalization finding text is stale relative to current binary-canonical implementation  
   - **Location:** `problems.md` finding `11`  
   - **Problem:** Current finding text describes previous call-site canonicalization but does not reflect the stronger relaunch state where txid is derived from canonical binary serialization.  
   - **Impact:** Audit/docs drift around consensus-critical identity derivation can cause incorrect assumptions in future refactors/reviews.  
   - **Required fix:** Update finding narrative to match the current txid model and record the final relaunch canonicalization state explicitly.

44. [TODO] `high` - Memo-era risk backlog is incomplete after payment-id -> memo migration  
   - **Location:** `problems.md` (missing entries), affected code paths include `block.go`, `transaction.go`, `api_handlers.go`, `cli.go`  
   - **Problem:** No findings currently track newly introduced memo-era concerns (for example exact block-size accounting pressure after fixed 128-byte memo, memo input sanitization policy split, and strict tx-version gating expectations).  
   - **Impact:** Relaunch can ship with untracked security/safety gaps because the backlog no longer maps to the active protocol surface.  
   - **Required fix:** Add dedicated memo-era findings with clear ownership and acceptance criteria for consensus-level, API-level, and UX-safety-level controls.

45. [TODO] `low` - Compatibility-era wording remains in code/comments after relaunch-only decision  
   - **Location:** Cross-file comments/docs (for example legacy/compat notes in protocol and runbook-adjacent text)  
   - **Problem:** Some wording still reflects compatibility assumptions despite relaunch policy being no legacy support.  
   - **Impact:** Documentation ambiguity increases maintenance risk and can reintroduce compatibility behavior by mistake.  
   - **Required fix:** Run a terminology cleanup pass that marks legacy text as historical only or removes it where obsolete.

46. [TODO] `high` - Legacy tx builder path emits zeroed memo bytes, violating relaunch memo-uniformity policy  
   - **Location:** `transaction.go` (`CreateTransaction` output construction path)  
   - **Problem:** A reachable transaction-construction path initializes `EncryptedMemo` as all zeros (`[wallet.MemoSize]byte{}`) instead of encrypted envelope bytes.  
   - **Impact:** Transactions built via that path produce a deterministic memo ciphertext pattern, undermining the mandatory encrypted-and-padded uniformity objective.  
   - **Required fix:** Remove/disable legacy constructor path or make it use the same memo envelope encryption routine as wallet builder for every output.

47. [TODO] `medium` - Memo envelope validity is not consensus-enforced, allowing structurally invalid memo ciphertexts on-chain  
   - **Location:** `transaction.go` (`ValidateTransaction`), memo handling split across `wallet/memo.go` and scanner-only decrypt path  
   - **Problem:** Consensus currently enforces memo byte presence/length only; envelope semantics (version/length/checksum invariants) are checked only by wallet-side decrypt logic.  
   - **Impact:** Attackers can publish outputs with malformed memo envelopes that satisfy consensus shape but violate protocol-level memo semantics, creating interoperability and policy drift risks.  
   - **Required fix:** Decide and codify whether envelope semantics are consensus rules; if yes, add deterministic validation, if no, document non-consensus status explicitly and add guardrails for wallet behavior.

48. [TODO] `medium` - Scanner silently drops invalid memo decrypts without telemetry or operator visibility  
   - **Location:** `wallet/scanner.go` (`DecryptMemo` callsite in `ScanBlock`)  
   - **Problem:** Failed memo decrypt/validation returns `ok=false` and is ignored silently, with no counters/logging/diagnostic surface.  
   - **Impact:** Malformed or policy-violating memo activity can go unnoticed, weakening incident detection and making debugging of memo issues difficult.  
   - **Required fix:** Add explicit invalid-memo accounting (metrics/logs/debug counters) and expose it in wallet/diagnostic surfaces.

49. [TODO] `low` - OpenAPI memo contract is not machine-enforced for mutual-exclusion and length limits  
   - **Location:** `api_openapi.json` (`SendRequest` memo fields)  
   - **Problem:** Schema text states `memo_text` and `memo_hex` are mutually exclusive and size-bounded, but schema does not encode those invariants (`oneOf`/`maxLength`) for tooling enforcement.  
   - **Impact:** Client generators and validators can accept request shapes the server rejects, causing avoidable integration errors and contract drift.  
   - **Required fix:** Encode memo constraints directly in schema (`oneOf`, explicit `maxLength`/pattern bounds) to align machine validation with handler behavior.

50. [TODO] `low` - Memo KDF implementation does not include the documented domain-separation component from relaunch spec  
   - **Location:** `wallet/memo.go` (`deriveMemoMask`), `relaunch.md` encryption section  
   - **Problem:** Current memo-mask derivation uses `"blocknet_memo_mask" || shared_secret || output_index`, while relaunch spec describes an additional domain-separation component (`block_domain_sep`).  
   - **Impact:** Spec/implementation mismatch increases review/audit ambiguity and risks accidental cryptographic coupling if future derivations are added without clear separation.  
   - **Required fix:** Either implement the documented domain-separation term in code or update spec text to exactly match the chosen KDF inputs.

51. [TODO] `high` - Wallet send API path has no route-level abuse throttling despite expensive cryptographic work  
   - **Location:** `api_handlers.go` (`handleSend`)  
   - **Problem:** `POST /api/wallet/send` performs expensive tx construction (range proofs + ring signatures) but lacks explicit request rate limiting and in-flight concurrency guards.  
   - **Impact:** Authenticated or leaked-token abuse can trigger sustained CPU/resource pressure and degrade daemon responsiveness.  
   - **Required fix:** Add route-scoped rate limits and bounded concurrent build/submit semaphore for send path, similar to `submitblock` hardening pattern.

52. [TODO] `medium` - Pre-build fee estimate is stale under fixed memo overhead and may underprice transactions  
   - **Location:** `wallet/builder.go` (`Transfer`, `estimatedSize := 200 + len(recipients)*100`)  
   - **Problem:** Initial fee estimate does not account for fixed 128-byte memo per output plus realistic proof/signature sizes, increasing mismatch risk before final tx serialization.  
   - **Impact:** More transactions can fail mempool fee-rate admission or exhibit inconsistent UX due to avoidable fee underestimation.  
   - **Required fix:** Replace rough estimate with structure-aware size model that includes memo overhead and conservative proof/signature bounds before fee calculation.

53. [TODO] `medium` - Relaunch memo format is not gated by explicit transaction-version policy  
   - **Location:** `transaction.go` (`Transaction.Version`, `ValidateTransaction`, tx builders)  
   - **Problem:** Protocol changed materially (mandatory memo output field) without a strict version gate that encodes relaunch-format expectations in validation logic.  
   - **Impact:** Future upgrades and audits face ambiguity around format activation boundaries and acceptable version surface.  
   - **Required fix:** Define and enforce explicit supported tx version set for relaunch memo format, rejecting unsupported versions consistently across validation and ingress.

54. [TODO] `low` - Consensus-critical code depends on wallet package constants for memo size  
   - **Location:** `transaction.go`, `block.go` imports of `blocknet/wallet` for `MemoSize`  
   - **Problem:** Core consensus serialization/validation paths depend on wallet-layer constants, creating layering/coupling risk.  
   - **Impact:** Refactors in wallet package can inadvertently affect protocol-critical behavior; separation-of-concerns is weakened.  
   - **Required fix:** Move memo constants to consensus/common protocol params package and consume from both wallet and consensus paths.

55. [TODO] `low` - Block-template tx selection reserve remains hardcoded magic buffer after memo footprint change  
   - **Location:** `miner.go`, `api_handlers.go` (`GetTransactionsForBlock(MaxBlockSize-1000, ...)`)  
   - **Problem:** Template packing still uses a fixed `1000`-byte reserve instead of deriving reserve from canonical block serialization overhead and tx footprint changes.  
   - **Impact:** Packing efficiency and edge-size correctness can drift as protocol fields evolve, increasing maintenance and tuning risk.  
   - **Required fix:** Replace magic reserve with explicit overhead model tied to canonical block serialization and assert template size invariants.

56. [TODO] `high` - JSON block ingest can default missing memo fields to zero arrays without explicit rejection  
   - **Location:** `daemon.go` (`handleBlock`, `processBlockData`) with JSON unmarshal into tx outputs  
   - **Problem:** Missing `encrypted_memo` in JSON payload can deserialize to zero-valued fixed array, and current consensus checks do not explicitly reject this semantic defaulting.  
   - **Impact:** Mandatory encrypted-memo policy can be weakened at network ingest boundary through shape-valid but policy-invalid payloads.  
   - **Required fix:** Add explicit validation to reject policy-invalid memo ciphertext patterns/semantics on all outputs during transaction/block validation.

57. [TODO] `medium` - Coinbase memo semantics are not explicitly constrained by consensus policy  
   - **Location:** `transaction.go` (`CreateCoinbase`, coinbase validation path)  
   - **Problem:** Coinbase outputs include memo bytes but there is no explicit rule requiring an empty-envelope-only policy (if desired) or otherwise documenting allowed coinbase memo semantics.  
   - **Impact:** Miners can encode arbitrary payloads in coinbase memos, potentially creating unintended metadata channel variance.  
   - **Required fix:** Define and enforce coinbase memo policy explicitly (for example empty-envelope-only), or document permissive behavior as intentional consensus design.

58. [TODO] `low` - Memo envelope checksum is only 16-bit and weak as validity discriminator  
   - **Location:** `wallet/memo.go` (`checksum` bytes `2..3`)  
   - **Problem:** Short checksum provides limited collision resistance and can occasionally treat malformed payloads as valid.  
   - **Impact:** Wallet-side memo integrity signal is weaker than expected under adversarial/malformed data.  
   - **Required fix:** Increase checksum strength (or add stronger envelope integrity marker) if envelope validity is relied upon as a robust discriminator.

59. [TODO] `medium` - Memo padding path falls back to deterministic bytes on RNG failure instead of failing closed  
   - **Location:** `wallet/memo.go` (`buildMemoEnvelope`)  
   - **Problem:** If random padding generation fails, code substitutes deterministic bytes from mask derivation rather than aborting memo construction.  
   - **Impact:** Padding unpredictability guarantees degrade in rare entropy-failure conditions and behavior diverges from strict random-padding policy.  
   - **Required fix:** Fail closed on RNG failure (return error) and bubble to transaction build path instead of deterministic fallback.

60. [TODO] `medium` - Consensus does not currently enforce non-default memo ciphertext semantics beyond fixed length  
   - **Location:** `transaction.go` (`ValidateTransaction`), related memo policy in `relaunch.md`  
   - **Problem:** Validation enforces output structure but not stronger memo semantic invariants (for example rejecting legacy-style all-zero ciphertext patterns if policy requires encrypted envelope semantics).  
   - **Impact:** Policy-level guarantees around memo uniformity can drift from actual accepted chain data.  
   - **Required fix:** Decide and encode explicit memo semantic invariants in consensus validation, or narrow policy language to length-only guarantees.

61. [TODO] `high` - Transaction deserializer accepts trailing bytes after canonical parse  
   - **Location:** `transaction.go` (`DeserializeTx`)  
   - **Problem:** Parser returns success after field decode without enforcing full-byte consumption (`off == len(data)`), allowing extra trailing data on otherwise valid transactions.  
   - **Impact:** Non-canonical payload acceptance can create relay/validation ambiguity and opens policy-bypass surface now that aux trailers were removed.  
   - **Required fix:** Enforce exact parse consumption and reject any transaction payload with trailing bytes.

62. [TODO] `medium` - `DeserializeTx` proof/signature size caps remain loose relative to practical protocol bounds  
   - **Location:** `transaction.go` (`maxProofSize`, `maxSigSize` in `DeserializeTx`)  
   - **Problem:** Current parser caps are permissive enough to allow unnecessarily heavy allocation/verification work within transport limits.  
   - **Impact:** Residual CPU/memory pressure surface from oversized-but-accepted fields, especially under adversarial gossip/mempool load.  
   - **Required fix:** Tighten parser caps to realistic protocol ceilings and keep them aligned with signer/proof producer maxima.

63. [TODO] `medium` - Memo validation policy is not encoded as explicit transaction-level invariant  
   - **Location:** `transaction.go` (`ValidateTransaction`), memo policy defined in `relaunch.md`  
   - **Problem:** Transaction validation currently guarantees memo field shape via fixed-size serialization but does not enforce an explicit memo-policy invariant at validation boundary.  
   - **Impact:** Divergence risk between documented memo policy and accepted on-chain data if builders/ingest paths evolve.  
   - **Required fix:** Add explicit memo-policy checks in transaction validation (or formally scope consensus to shape-only and document that as authoritative).

64. [TODO] `low` - OpenAPI tx lookup schema underspecifies output memo field contract  
   - **Location:** `api_openapi.json` (`TxLookupResult.tx`)  
   - **Problem:** Transaction lookup response uses a generic object schema and does not explicitly define output fields including `encrypted_memo`.  
   - **Impact:** Client generators and integrators can drift from actual wire/API behavior, increasing integration and compatibility errors.  
   - **Required fix:** Define concrete transaction/output schemas in OpenAPI and include memo-related output fields explicitly.

65. [TODO] `low` - Relaunch default path/filename documentation can drift from enforced runtime defaults  
   - **Location:** user-facing docs (`README.md`, relaunch/operator docs) vs runtime defaults (`main.go`, `cli.go`, `daemon.go`)  
   - **Problem:** Relaunch introduced new conventions, but docs can still reflect pre-relaunch defaults in places unless continuously synchronized.  
   - **Impact:** Operator misconfiguration risk (wrong data dir/wallet file), especially during clean-network relaunch operations.  
   - **Required fix:** Add a relaunch-defaults doc consistency check process and keep README/operator docs aligned with compiled defaults.

66. [TODO] `medium` - No end-to-end regression coverage that trailing-byte transactions are rejected on all ingress paths  
   - **Location:** `transaction.go` (`DeserializeTx`), `mempool.go` (`AddTransaction`), `daemon.go` (`processTxData`, gossip tx handler path)  
   - **Problem:** Deserializer trailing-byte acceptance/rejection behavior is consensus-sensitive, but there is no full-path regression coverage from network ingest through mempool admission.  
   - **Impact:** Parser or ingress regressions can silently reintroduce non-canonical payload acceptance under real daemon paths.  
   - **Required fix:** Add integration tests that submit trailing-byte variants via direct validation, mempool, and daemon ingest handlers and assert deterministic rejection.

67. [TODO] `medium` - Missing regression tests that all transaction-construction paths populate non-default memo ciphertexts  
   - **Location:** `wallet/builder.go`, `transaction.go` (`CreateTransaction`, `CreateCoinbase`)  
   - **Problem:** Multiple construction paths exist; not all currently have explicit tests asserting encrypted memo bytes are populated per output and not left in default-zero state.  
   - **Impact:** Future refactors can accidentally reintroduce deterministic zero/default memo patterns and violate uniformity goals.  
   - **Required fix:** Add path-specific construction tests for recipient/change/coinbase outputs ensuring memo ciphertexts satisfy non-default envelope policy (or explicit policy for coinbase if empty-envelope-only).

68. [TODO] `medium` - Missing regression coverage for JSON block ingest with omitted `encrypted_memo` fields  
   - **Location:** `daemon.go` (`handleBlock`, `processBlockData`) and block JSON decoding paths  
   - **Problem:** JSON decoding can default absent fixed arrays; there is no explicit test ensuring omitted memo fields are rejected under relaunch policy.  
   - **Impact:** Policy-invalid payloads can pass ingest if validation semantics drift, weakening mandatory memo guarantees.  
   - **Required fix:** Add daemon ingest tests that submit block JSON with omitted/invalid memo fields and assert rejection before state mutation.

69. [TODO] `low` - Relaunch blocker prioritization is not explicit inside the findings list  
   - **Location:** `problems.md` triage process  
   - **Problem:** Memo/relaunch-critical issues are mixed with process/doc backlog items without a dedicated blocker marker.  
   - **Impact:** Launch-critical fixes can be delayed by queue noise and non-blocking cleanup tasks.  
   - **Required fix:** Add explicit relaunch-blocker tagging/section and maintain it as the launch gate source of truth.

70. [TODO] `low` - No automated consistency checks for docs/schema/runtime field defaults and memo contract  
   - **Location:** docs (`README.md`, `relaunch.md`), schema (`api_openapi.json`), runtime defaults/handlers (`main.go`, `cli.go`, `daemon.go`, `api_handlers.go`)  
   - **Problem:** Drift can recur between documented defaults/contracts and implemented behavior without automated checks.  
   - **Impact:** Integration/operator errors increase over time; regressions are discovered late.  
   - **Required fix:** Add lightweight CI checks for key default values and memo field naming/contract consistency across docs, OpenAPI, and handlers.

71. [TODO] `low` - Explorer/API memo rendering policy lacks explicit regression coverage for ciphertext-only display guarantees  
   - **Location:** `explorer.go`, API tx/history response shaping in `api_handlers.go`  
   - **Problem:** There is no dedicated regression suite ensuring public explorer/API surfaces do not accidentally expose unsafe/plaintext memo rendering semantics outside intended wallet context.  
   - **Impact:** UI/API regressions could leak or unsafely render memo content under future feature changes.  
   - **Required fix:** Add regression tests locking expected memo exposure policy (encrypted-only where intended, escaped/safe rendering behavior where decoded memo is presented).

72. [TODO] `medium` - Block-size accounting remains approximate across validation and cheap prefilter paths after memo footprint expansion  
   - **Location:** `block.go` (`Transaction.Size`, `Block.Size`, `ValidateBlock`), `daemon.go` (`validateBlockCheapPrefilters`)  
   - **Problem:** Size checks rely on approximate transaction sizing, which can diverge from canonical serialized bytes; memo overhead increases sensitivity to this mismatch.  
   - **Impact:** Oversized blocks may be inconsistently admitted/rejected across gossip prefilters and consensus validation boundaries.  
   - **Required fix:** Use canonical serialized-size accounting in block/tx size checks and align all ingress/validation size gates to the same exact metric.

73. [TODO] `medium` - Missing fuzz/property testing for `DeserializeTx` under memo-era wire format  
   - **Location:** `transaction.go` (`DeserializeTx`)  
   - **Problem:** Parser now handles additional fixed memo bytes and multiple length fields but lacks fuzz/property coverage for malformed/truncated/overlong variants.  
   - **Impact:** Parser edge-case regressions can slip through example-based tests and become DoS or consensus-divergence risks.  
   - **Required fix:** Add fuzz/property tests targeting parser invariants (no panic, exact-consumption, deterministic reject/accept behavior).

74. [TODO] `low` - Memo crypto interoperability invariants are not explicitly tested across implementations  
   - **Location:** `wallet/memo.go` and any external/tooling-facing memo producers/consumers  
   - **Problem:** No dedicated vector-based regression suite guarantees stable memo encrypt/decrypt outputs for fixed inputs across environments.  
   - **Impact:** Integration drift risk if non-Go tooling, indexers, or future clients implement memo handling independently.  
   - **Required fix:** Add deterministic test vectors for memo envelope/encryption/decryption and enforce compatibility in CI.

75. [TODO] `low` - Memo failure telemetry lacks explicit SLO/alert thresholds  
   - **Location:** wallet/daemon operational observability surfaces (memo decode/validation paths)  
   - **Problem:** Memo invalid/decrypt-failure concerns exist, but there is no defined operational thresholding/alert policy.  
   - **Impact:** Operational teams may miss memo-related degradation patterns until user-visible issues accumulate.  
   - **Required fix:** Define memo failure metrics and threshold-based alerting/SLO guidance in ops documentation and diagnostics.

76. [TODO] `low` - API/OpenAPI examples do not comprehensively cover memo edge-case response shapes  
   - **Location:** `api_openapi.json`, API docs/examples  
   - **Problem:** Current examples are limited and do not explicitly demonstrate empty memo, UTF-8 memo, and hex memo scenarios across send/history responses.  
   - **Impact:** Client implementers can mis-handle optional fields and edge cases due to ambiguous example coverage.  
   - **Required fix:** Add explicit examples for empty/non-empty memo_text/memo_hex paths and corresponding response field presence rules.

77. [TODO] `low` - Wallet persistence growth impact from memo storage is untracked  
   - **Location:** `wallet/wallet.go` persistence model (`OwnedOutput`, `SendRecord`)  
   - **Problem:** Memo payload persistence increases wallet file growth and IO, but no benchmark/monitoring guidance exists.  
   - **Impact:** Long-lived wallets may encounter avoidable storage/performance degradation without early visibility.  
   - **Required fix:** Add wallet-size growth benchmarks/monitoring guidance and define practical retention/pruning expectations.

78. [TODO] `medium` - Send API lacks idempotency protection for retry-safe client behavior  
   - **Location:** `api_handlers.go` (`handleSend`)  
   - **Problem:** `POST /api/wallet/send` has no idempotency key support, so client retries/timeouts can submit duplicate transfers.  
   - **Impact:** Operational duplicate-send risk under network/API retry behavior, especially for automated clients/integrators.  
   - **Required fix:** Add optional idempotency key handling with bounded replay window and deterministic response replay for duplicate keys.

79. [TODO] `medium` - Memo text normalization policy is undefined across interfaces  
   - **Location:** `api_handlers.go` (`memo_text` ingest), `cli.go` memo text path, docs/spec  
   - **Problem:** Memo text bytes are accepted as provided, with no explicit Unicode normalization policy (for example NFC/NFKC), allowing visually similar but byte-different payloads.  
   - **Impact:** Interop confusion and user-facing ambiguity for memo matching/indexing/display logic.  
   - **Required fix:** Define and enforce a canonical memo text normalization policy (or explicitly document raw-byte semantics as intentional and immutable).

80. [TODO] `medium` - No chain-level memo anomaly telemetry for operational abuse detection  
   - **Location:** daemon/metrics surfaces and wallet scanner diagnostics  
   - **Problem:** Memo activity lacks dedicated metrics for malformed rates, empty/non-empty distribution, and repeated-pattern anomalies.  
   - **Impact:** Abuse or regression patterns in memo handling can remain undetected until user-visible failures occur.  
   - **Required fix:** Add memo-focused metrics and dashboards/alerts for anomaly detection in relaunch operations.

81. [TODO] `low` - Missing deterministic memo edge-case fixture corpus for regression stability  
   - **Location:** test assets for memo handling (`wallet/memo.go`, tx serialization/tests)  
   - **Problem:** No maintained fixture corpus covers empty, max-length, non-UTF8, invalid checksum/version, and malformed envelope cases with fixed expected outcomes.  
   - **Impact:** Regression confidence relies too heavily on ad-hoc tests/fuzzing and can miss deterministic edge-case drift.  
   - **Required fix:** Add versioned memo fixture vectors and assert fixed outcomes across parser/encrypt/decrypt paths.

82. [TODO] `low` - Relaunch memo constants/policy are not frozen in a single canonical source  
   - **Location:** split across `wallet/memo.go`, `transaction.go`, and docs (`relaunch.md`)  
   - **Problem:** Memo constants/policy details (size, version, KDF labels, checksum semantics) are distributed across files/docs without a single frozen params authority.  
   - **Impact:** Spec/code drift risk increases during future refactors and audit efforts.  
   - **Required fix:** Centralize relaunch memo protocol constants in one canonical params module and reference it from both consensus code and documentation.

83. [TODO] `low` - Findings backlog lacks ownership/milestone metadata for execution tracking  
   - **Location:** `problems.md` process model  
   - **Problem:** Large active backlog has no owner/target milestone fields, making prioritization and accountability difficult.  
   - **Impact:** Critical relaunch issues may stagnate despite being documented.  
   - **Required fix:** Introduce lightweight owner + target release metadata for open findings and enforce updates during triage.

84. [DONE] `medium` - Runtime paths had widespread unchecked error returns in API/daemon/P2P/storage/wallet flows  
   - **Location:** `api_auth.go`, `api_handlers.go`, `api_server.go`, `api_sse.go`, `explorer.go`, `main.go`, `cli.go`, `daemon.go`, `block.go`, `storage.go`, `p2p/*`, `wallet/builder.go`, `wallet/memo.go`, `wallet/scanner.go`, `tests.go`  
   - **Problem:** Multiple file/network/storage/persistence/stream operations ignored returned errors, allowing silent failures in shutdown, persistence, stream I/O, and maintenance paths.  
   - **Impact:** Silent operational faults can mask degraded state, reduce auditability, and weaken fail-closed behavior on security-sensitive network/storage boundaries.  
   - **What changed:** Added explicit error handling on all errcheck-reported call sites in scope, using fail-closed returns where safety-critical, plus structured warning logs for non-fatal cleanup/best-effort paths; replaced hash-writer `binary.Write` calls with deterministic endian byte encoding to avoid ignored writer errors.

## Giant Work Queue

### P0 - Must ship immediately

1. [DONE] Refactor block acceptance into one mandatory validated chain-ingest function used by all paths.
2. [DONE] Lock down `AddBlock` so non-genesis use cannot bypass consensus checks.
3. [DONE] Harden `ValidateBlockP2P` for fork/side-chain context with strict chain-aware rules.
4. [DONE] Add peer penalty escalation for invalid-block spam in all sync rejection branches.
5. [DONE] Add route-level throttling and concurrency limits for expensive validation endpoints (`submitblock` first).
6. [DONE] Enforce hard protocol payload limits per message type before allocation/decode.

### P1 - Next wave

7. [DONE] Cap and stream-parse mempool sync payloads.
8. [DONE] Add strict bounds/overflow checks to `findTxBoundary` and aux parsing logic.
9. [DONE] Canonicalize txid derivation and remove multi-hash fallback behavior.
10. [DONE] Add storage write-time invariants for consensus-critical mutations.
11. [WONTFIX] Harden destructive API operations with dedicated admin secret and explicit preconditions.

### P2 - Operational resilience

12. [DONE] Add cache/precompute for expensive explorer/stat endpoints.
13. [DONE] Introduce protocol-level abuse accounting for malformed tx/block streams.
14. [DONE] Add explicit genesis validation branch in consensus validator.
15. [DONE] Normalize serialization docs and invariant guards.
16. [DONE] Tighten sync request parameter validation and quotas.
17. [DONE] Add stem-phase tx sanity validation and malformed-stem peer penalties.
18. [DONE] Enforce Dandelion cache size caps with deterministic eviction.
19. [DONE] Remove panic-based failure handling from Dandelion RNG helpers.
20. [DONE] Re-enable/replace connection admission gating for banned peers.
21. [DONE] Add explicit decode limits for sync header/block response arrays.
22. [DONE] Add wallet unlock brute-force protection controls.
23. [DONE] Rework scanner spent-detection to indexed key-image lookup.
24. [DONE] Add strict limits for PEX peer record and address list decoding.
25. [DONE] Enforce finalized-depth reorg rejection in consensus fork-choice path.
26. [DONE] Replace coarse difficulty-to-target mapping with exact integer conversion.
27. [DONE] Add overflow-safe cumulative chainwork accounting.
28. [DONE] Enforce on-chain canonical membership checks for all RingCT ring member/commitment pairs.
29. [DONE] Add FFI wrapper guards for zero-length proof/signature/message slices.
30. [DONE] Eliminate map mutations under read locks in chain cache code paths.
31. [DONE] Route inbound `ProtocolTx` through Dandelion fluff semantics (or unified equivalent path).
32. [DONE] Explicitly reject coinbase transactions at mempool admission boundary.
33. [TODO] Bind RingCT external input fields (`key_image`, `pseudo_output`) to verified signature payload values.
34. [TODO] Enforce side-chain/fork-aware key-image reuse prevention before reorg adoption.
35. [TODO] Add deterministic penalties/abuse controls on all invalid gossip ingress paths that can trigger expensive validation.
36. [TODO] Replace O(total_outputs) canonical ring-member scans with indexed lookup for validation paths.
37. [TODO] Add SSE subscriber unsubscribe/cleanup lifecycle to prevent channel leak growth.
38. [TODO] Harden docker-compose defaults for API exposure and wallet-password safety.
39. [DONE] Harden unchecked runtime error handling across API/daemon/P2P/wallet paths and remove silent errcheck failures.

## High-Risk Regression Test Plan (real paths only, no mocks)

Use real chain, daemon, mempool, p2p, wallet, and API handlers. Avoid fake validators or mocked consensus/storage objects.

### Shared Go Test Helpers (planned)

Place these in a common Go test helper file (suggested: `testhelpers_test.go`) so all `go test` cases reuse the same real setup paths.

- [DONE] `mustCreateTestChain(t *testing.T) (*Chain, *Storage, func())`  
  Real chain+storage bootstrap with cleanup.
- [DONE] `mustAddGenesisBlock(t *testing.T, chain *Chain)`  
  Canonical genesis initialization via production path.
- `mustMineAndProcessBlock(t *testing.T, chain *Chain, txs []*Transaction, miner *StealthAddress) *Block`  
  Builds valid block and ingests through `ProcessBlock`.
- `mustBuildCompetingBranch(t *testing.T, base *Block, count int, txSets [][]*Transaction) []*Block`  
  Real fork construction helper for reorg/finality tests.
- [DONE] `mustStartTestDaemon(t *testing.T, chain *Chain) (*Daemon, func())`  
  Real daemon init and teardown for ingest-path tests.
- [DONE] `mustSubmitBlockData(t *testing.T, d *Daemon, b *Block)`  
  Runs daemon ingest entrypoint (`processBlockData`/handler path).
- [DONE] `mustMakeHTTPJSONRequest(t *testing.T, handler http.Handler, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder`  
  Shared API/explorer handler request helper.
- [DONE] `mustStartLinkedTestNodes(t *testing.T) (*Node, *Node, func())`  
  Real libp2p node pair for gater/dandelion/sync behaviors.
- [DONE] `mustSendLengthPrefixedPayload(t *testing.T, s network.Stream, payload []byte)`  
  Stream writer for p2p cap tests.
- [DONE] `mustCraftMalformedTxVariant(t *testing.T, kind string) []byte`  
  Generates malformed tx bytes for FFI/ring/stem rejection tests.
- [DONE] `assertTipUnchanged(t *testing.T, chain *Chain, wantHash [32]byte, wantHeight uint64)`  
  Canonical assertion for reject-without-mutation checks.
- [DONE] `assertPeerPenalized(t *testing.T, n *Node, pid peer.ID, minPenalty int)`  
  Verifies peer penalty escalation in sync/dandelion tests.

1. [DONE] **ProcessBlock mandatory validation gate**
   - **Scenario:** Submit an invalid non-genesis block directly via `ProcessBlock`.
   - **Primary path:** `block.go` -> `Chain.ProcessBlock` -> `validateBlockForProcessLocked` -> `validateBlockWithContext`.
   - **Test setup:** Build a real chain with genesis, craft one invalid child (bad timestamp/difficulty/PoW), call `ProcessBlock`.
   - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `assertTipUnchanged`.
   - **Assertions:** Returns error, tip/height unchanged, block not inserted into `c.blocks`, storage tip unchanged.
   - **Suggested files:** `block_process_test.go`, `testhelpers_test.go`.
   - **Status:** implemented in Go test `TestProcessBlock_EnforcesValidationInternally` and passing via `go test`.

2. [DONE] **Daemon ingest reorg removes txs from all connected blocks**
   - **Scenario:** Real daemon receives competing valid branch and reorgs.
   - **Primary path:** `daemon.go` -> `processBlockData`/`handleBlock` -> `Chain.ProcessBlock` -> `reorganizeTo`.
   - **Test setup:** Mine/import valid PoW blocks on branch A and heavier branch B; include mempool txs across both branches.
   - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustBuildCompetingBranch`, `mustStartTestDaemon`, `mustSubmitBlockData`.
   - **Assertions:** Old-branch confirmed txs removed from chain indices, new-branch tx set is canonical, no stale confirmed entries remain.
   - **Suggested files:** `daemon_reorg_mempool_test.go`.

3. [DONE] **Daemon ingest reorg requeues disconnected transactions**
   - **Scenario:** Reorg disconnects blocks containing previously confirmed transactions.
   - **Primary path:** `daemon.go` reorg flow plus mempool reconciliation.
   - **Test setup:** Confirm txs on branch A, switch to heavier branch B that excludes them.
   - **Shared helpers:** `mustCreateTestChain`, `mustBuildCompetingBranch`, `mustStartTestDaemon`, `mustSubmitBlockData`.
   - **Assertions:** Eligible disconnected txs are re-added to mempool, invalid/coinbase txs are not re-added.
   - **Suggested files:** `daemon_reorg_mempool_test.go`.

4. [DONE] **Fork-context validation for non-tip blocks**
   - **Scenario:** Feed a validly-encoded fork block with wrong difficulty or MTP for its parent branch.
   - **Primary path:** `block.go` -> `ValidateBlockP2P` -> `validateBlockWithContext` -> `expectedDifficultyFromParent`/`medianTimestampFromParent`.
   - **Test setup:** Construct side branch with enough history for MTP window and LWMA context; alter fork-block header difficulty/time.
   - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustBuildCompetingBranch`.
   - **Assertions:** Rejected on fork path (not only tip-extension path).
   - **Suggested files:** `block_validation_test.go`.

5. [DONE] **Finality-depth guard blocks deep reorg**
   - **Scenario:** Competing chain attempts to fork below finalized boundary.
   - **Primary path:** `block.go` -> `ProcessBlock`/`reorganizeTo` -> `enforceReorgFinalityLocked`.
   - **Test setup:** Build main chain beyond `MaxReorgDepth`, then present heavier fork diverging before finality boundary.
   - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustBuildCompetingBranch`, `assertTipUnchanged`.
   - **Assertions:** Reorg rejected deterministically; canonical tip unchanged.
   - **Suggested files:** `block_finality_test.go`.

6. [DONE] **Sync invalid-block penalties across all rejection branches**
   - **Scenario:** Peer sends invalid new block, invalid orphan parent data, and invalid hash-fetch response.
   - **Primary path:** `p2p/sync.go` -> `handleNewBlock`, `recoverOrphanChain`, `fetchBlockByHashFromAnyPeer`, ordered sync processing.
   - **Test setup:** Use real sync manager + peer objects with malformed payloads (empty, undecodable, hash mismatch, invalid block).
   - **Shared helpers:** `mustStartLinkedTestNodes`, `mustCraftMalformedTxVariant`, `assertPeerPenalized`.
   - **Assertions:** Peer scoring/penalty applies in each branch; retry paths do not silently skip penalties.
   - **Suggested files:** `p2p/sync_penalty_test.go`.

7. [DONE] **Protocol/message-class payload caps enforced pre-decode**
   - **Scenario:** Oversized payloads on block/tx/dandelion/sync/PEX streams.
   - **Primary path:** `p2p/util.go` (`readLengthPrefixedWithLimit`, `readMessageWithLimit`) and callers in `p2p/node.go`, `p2p/dandelion.go`, `p2p/sync.go`, `p2p/pex.go`.
   - **Test setup:** Send payloads 1 byte over each class cap using real stream handlers.
   - **Shared helpers:** `mustStartLinkedTestNodes`, `mustSendLengthPrefixedPayload`.
   - **Assertions:** Fast reject before decode/allocation-heavy paths; connection/handler returns expected error.
   - **Suggested files:** `p2p/util_test.go`.

8. [DONE] **Sync response array-count and mempool budget enforcement**
   - **Scenario:** Header/block/mempool responses exceed item counts or byte budgets.
   - **Primary path:** `p2p/sync.go` (`ensureJSONArrayMaxItems`, `trimByteSliceBatch`, fetch handlers).
   - **Test setup:** Return oversized JSON arrays and oversized decoded `[][]byte` batches from real sync response handlers.
   - **Shared helpers:** `mustStartLinkedTestNodes`, `mustSendLengthPrefixedPayload`.
   - **Assertions:** Over-limit responses rejected or trimmed as designed; processing count/bytes stay within caps.
   - **Suggested files:** `p2p/sync_limits_test.go`.

9. [DONE] **Canonical ring-member enforcement on main chain only**
   - **Scenario:** Transaction ring references outputs that exist in storage but are reorged out of active chain.
   - **Primary path:** `transaction.go` `ValidateTransaction` callback, `block.go` `IsCanonicalRingMember`/`isOutputCanonicalOnMainChainLocked`.
   - **Test setup:** Create outputs on branch A, reorg to branch B, submit tx using A-only ring members.
   - **Shared helpers:** `mustCreateTestChain`, `mustBuildCompetingBranch`, `mustCraftMalformedTxVariant`.
   - **Assertions:** Transaction rejected in both mempool admission and block validation.
   - **Suggested files:** `transaction_validation_test.go`.

10. [DONE] **FFI wrapper zero-length guards cannot panic**
    - **Scenario:** Submit txs with empty proof/signature/message slices.
    - **Primary path:** `crypto.go` `VerifyRangeProof`, `VerifyRing`, `VerifyRingCT` via `transaction.go` `ValidateTransaction`.
    - **Test setup:** Build malformed tx payloads that previously reached `&slice[0]`.
    - **Shared helpers:** `mustCraftMalformedTxVariant`, `mustCreateTestChain`.
    - **Assertions:** Validation returns error (no panic/crash), node continues processing subsequent valid txs.
    - **Suggested files:** `crypto_ffi_guard_test.go`.

11. [DONE] **Dandelion realism: stem sanity, cache cap, fluff routing**
    - **Scenario:** Inbound stem malformed tx, high-volume unique tx spam, and inbound fluff on `ProtocolTx`.
    - **Primary path:** `p2p/dandelion.go` (`HandleStemStream`, `handleStemTx`, `HandleFluffTx`) and `p2p/node.go` (`handleTxStream`).
    - **Test setup:** Use real node+dandelion handlers; feed malformed stem payloads and >`txCacheSize` unique txs.
    - **Shared helpers:** `mustStartLinkedTestNodes`, `mustSendLengthPrefixedPayload`, `assertPeerPenalized`.
    - **Assertions:** Malformed stem penalized and dropped; cache never exceeds cap; fluff path goes through `HandleFluffTx` semantics.
    - **Suggested files:** `p2p/dandelion_integration_test.go`.

12. [DONE] **Wallet unlock brute-force controls in API handler**
    - **Scenario:** Repeated wrong-password unlock attempts from same client IP.
    - **Primary path:** `api_handlers.go` `handleUnlock` and `api_server.go` unlock attempt tracker.
    - **Test setup:** Real HTTP handler test with repeated requests; no mocked tracker.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** Progressive delay/backoff observed, `429` and `Retry-After` enforced, success resets state.
    - **Suggested files:** `api_unlock_test.go`.

13. [DONE] **Banned peer admission filtering at host layer**
    - **Scenario:** Known banned peer attempts reconnect.
    - **Primary path:** `p2p/node.go` host setup with `libp2p.ConnectionGater`, `p2p/gater.go` interceptors.
    - **Test setup:** Two real libp2p nodes; ban one peer and attempt dial/reconnect.
    - **Shared helpers:** `mustStartLinkedTestNodes`.
    - **Assertions:** Connection denied by gater path; peer cannot maintain session through normal admission.
    - **Suggested files:** `p2p/gater_test.go`.

14. [DONE] **Mempool boundary rejects non-admissible classes**
    - **Scenario:** Submit coinbase tx directly to mempool and through network tx ingest.
    - **Primary path:** `mempool.go` `AddTransaction`, daemon tx ingestion path.
    - **Test setup:** Generate real coinbase tx object; attempt direct add and network-path add.
    - **Shared helpers:** `mustCreateTestChain`, `mustStartTestDaemon`.
    - **Assertions:** Explicit rejection error in both ingress routes; mempool contents unchanged.
    - **Suggested files:** `mempool_test.go` and daemon tx ingest tests (`daemon_tx_test.go`).
    - **Status:** implemented in `TestMempoolRejectsCoinbaseTransaction` and `TestDaemonTxIngestRejectsCoinbaseTransaction` (Go tests).

15. [DONE] **RingCT binding extractor enforces signature layout and field decoding**
    - **Scenario:** Parse RingCT signature payload for key-image/pseudo-output binding from well-formed and malformed signature lengths.
    - **Primary path:** `crypto.go` `ExtractRingCTBinding`.
    - **Test setup:** Construct signature byte slices with expected RingCT layout and intentionally invalid lengths.
    - **Shared helpers:** none required.
    - **Assertions:** Valid payload returns extracted key image/pseudo-output exactly; malformed length is rejected with error.
    - **Suggested files:** `crypto_ffi_guard_test.go`.
    - **Status:** implemented in `TestExtractRingCTBindingReturnsEmbeddedFields` and `TestExtractRingCTBindingRejectsInvalidSignatureLength` (Go tests).

16. [DONE] **ValidateTransaction rejects tampered external key-image against signed RingCT payload**
    - **Scenario:** Transaction has a valid RingCT signature, but external `TxInput.KeyImage` is modified after signing.
    - **Primary path:** `transaction.go` `ValidateTransaction` binding check path + spent check sequencing.
    - **Test setup:** Build/sign a real RingCT input, then mutate only external `KeyImage` before validation.
    - **Shared helpers:** function checkers passed to `ValidateTransaction` (`isSpent`, `isCanonicalRingMember`).
    - **Assertions:** Validation fails specifically on key-image binding mismatch before spent-state acceptance.
    - **Suggested files:** `transaction_validation_test.go`.
    - **Status:** implemented in `TestValidateTransactionRejectsTamperedRingCTExternalKeyImage` (Go tests).

17. [DONE] **ValidateTransaction rejects tampered external pseudo-output against signed RingCT payload**
    - **Scenario:** Transaction has a valid RingCT signature, but external `TxInput.PseudoOutput` is modified after signing.
    - **Primary path:** `transaction.go` `ValidateTransaction` binding check path + `verifyCommitmentBalance`.
    - **Test setup:** Build/sign a real RingCT input, then mutate only external `PseudoOutput` before validation.
    - **Shared helpers:** function checkers passed to `ValidateTransaction` (`isSpent`, `isCanonicalRingMember`).
    - **Assertions:** Validation fails on pseudo-output binding mismatch, preventing tampered fields from reaching balance acceptance.
    - **Suggested files:** `transaction_validation_test.go`.
    - **Status:** implemented in `TestValidateTransactionRejectsTamperedRingCTExternalPseudoOutput` (Go tests).

18. [DONE] **Mempool ingress rejects tampered RingCT external key-image binding**
    - **Scenario:** Transaction reaches mempool admission with an otherwise-valid RingCT input but externally tampered `TxInput.KeyImage`.
    - **Primary path:** `mempool.go` `AddTransaction` -> `transaction.go` `ValidateTransaction` binding check.
    - **Test setup:** Build/sign a valid RingCT test transaction, mutate only external key image, submit via mempool add path.
    - **Shared helpers:** `mustBuildValidRingCTBindingTestTx`.
    - **Assertions:** Mempool rejects with binding-mismatch error and remains empty.
    - **Suggested files:** `mempool_test.go`.
    - **Status:** implemented in `TestMempoolRejectsTamperedRingCTExternalKeyImage`; passing via `go test ./... -run TestMempoolRejectsTamperedRingCTExternalKeyImage -count=1`.

19. [DONE] **Daemon tx ingest rejects tampered RingCT external key-image binding**
    - **Scenario:** Transaction reaches daemon tx ingest with an otherwise-valid RingCT input but externally tampered `TxInput.KeyImage`.
    - **Primary path:** `daemon.go` `processTxData` -> `mempool.go` `AddTransaction` -> `transaction.go` `ValidateTransaction` binding check.
    - **Test setup:** Build/sign a valid RingCT test transaction, mutate only external key image, submit via daemon tx ingest path.
    - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustStartTestDaemon`, `mustBuildValidRingCTBindingTestTx`.
    - **Assertions:** Daemon ingest does not admit transaction into mempool; mempool remains empty.
    - **Suggested files:** `daemon_tx_test.go`.
    - **Status:** implemented in `TestDaemonTxIngestRejectsTamperedRingCTExternalKeyImage`; passing via `go test ./... -run TestDaemonTxIngestRejectsTamperedRingCTExternalKeyImage -count=1`.

20. [TODO] **Relaunch tx parser rejects legacy no-memo wire shape and malformed memo-size outputs**
    - **Scenario:** Feed transactions encoded with pre-memo output layout (no `EncryptedMemo`) or truncated memo bytes.
    - **Primary path:** `transaction.go` `DeserializeTx`.
    - **Test setup:** Build raw tx byte variants that differ only in output wire shape and memo byte length.
    - **Shared helpers:** `mustCraftMalformedTxVariant` (extend with memo variants) or local byte constructors.
    - **Assertions:** Parser rejects all non-canonical output layouts; canonical memo layout is accepted.
    - **Suggested files:** `transaction_serialization_test.go`.

21. [TODO] **Block-size consensus check uses canonical serialized bytes under memo overhead**
    - **Scenario:** Construct blocks near `MaxBlockSize` where approximate accounting can diverge from real serialized bytes.
    - **Primary path:** `block.go` `Block.Size`, `ValidateBlock`, daemon ingest (`handleBlock`/`processBlockData`).
    - **Test setup:** Build transactions with realistic range-proof/signature sizes and fixed 128-byte memos, then assemble edge-size blocks.
    - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustMineAndProcessBlock` (or equivalent block constructors).
    - **Assertions:** Acceptance/rejection exactly tracks canonical on-wire size budget; no oversize block passes due to approximation.
    - **Suggested files:** `block_size_consensus_test.go`.

22. [TODO] **Memo input policy enforcement (control/bidi/zero-width) on API and CLI send paths**
    - **Scenario:** Submit memo text containing control chars, bidi controls, and zero-width characters.
    - **Primary path:** `api_handlers.go` `handleSend`, `cli.go` `cmdSend`.
    - **Test setup:** API handler requests with `memo_text` payloads and CLI command invocations with unsafe memo strings.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** Unsafe memo text is rejected at input boundary with deterministic errors; allowed memo text/hex paths still succeed.
    - **Suggested files:** `api_send_memo_policy_test.go`, `cli_send_test.go`.

23. [TODO] **Tx version-gating for relaunch memo format is enforced on all ingress paths**
    - **Scenario:** Submit transactions with unsupported `tx.Version` that otherwise satisfy structural checks.
    - **Primary path:** `transaction.go` `ValidateTransaction`, mempool admission (`mempool.go`), daemon tx ingest (`daemon.go`).
    - **Test setup:** Build valid tx then mutate version field across unsupported values; submit via direct validation, mempool, and daemon ingest.
    - **Shared helpers:** `mustCreateTestChain`, `mustStartTestDaemon`.
    - **Assertions:** Unsupported versions are rejected consistently in all ingress paths before state mutation.
    - **Suggested files:** `transaction_validation_test.go`, `mempool_test.go`, `daemon_tx_test.go`.

24. [TODO] **OpenAPI/handler parity for memo contract remains locked**
    - **Scenario:** API schema drifts from handler behavior for `memo_text`/`memo_hex`.
    - **Primary path:** `api_openapi.json`, `api_handlers.go` (`handleSend`, `handleHistory`).
    - **Test setup:** Contract test that validates documented fields against real handler responses/validation behavior.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** OpenAPI includes only active memo fields; requests/responses match documented required/optional semantics.
    - **Suggested files:** `api_openapi_contract_test.go`.

25. [TODO] **`problems.md` queue/finding status consistency guard**
    - **Scenario:** Finding status and queue status diverge (e.g., finding `[DONE]` while queue item remains `[TODO]`).
    - **Primary path:** `problems.md` integrity check in CI/test tooling.
    - **Test setup:** Parse `problems.md` sections and compare statuses for mirrored backlog items.
    - **Shared helpers:** none required.
    - **Assertions:** CI fails on status divergence to keep launch-triage source of truth accurate.
    - **Suggested files:** `problems_consistency_test.go`.

26. [TODO] **Trailing-byte transaction variants are rejected across validator, mempool, and daemon ingest**
    - **Scenario:** Feed canonical tx bytes with appended trailing junk bytes.
    - **Primary path:** `transaction.go` (`DeserializeTx`), `mempool.go` (`AddTransaction`), `daemon.go` (`processTxData` / tx handler path).
    - **Test setup:** Build a valid transaction, append bytes, submit via direct deserialize, mempool add, and daemon tx ingest.
    - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `mustStartTestDaemon`.
    - **Assertions:** All paths reject trailing-byte payloads deterministically; mempool remains unchanged.
    - **Suggested files:** `transaction_serialization_test.go`, `mempool_test.go`, `daemon_tx_test.go`.

27. [TODO] **All transaction-construction paths produce non-default memo ciphertext policy outputs**
    - **Scenario:** Build transactions via wallet builder, legacy constructor path (if still reachable), and coinbase constructor.
    - **Primary path:** `wallet/builder.go`, `transaction.go` (`CreateTransaction`, `CreateCoinbase`).
    - **Test setup:** Construct outputs in each path and inspect serialized `EncryptedMemo` bytes.
    - **Shared helpers:** `mustCreateTestChain` where chain context is needed.
    - **Assertions:** No path emits unintended default-zero memo bytes unless explicitly allowed by documented coinbase policy.
    - **Suggested files:** `transaction_serialization_test.go`, `wallet/builder_test.go`.

28. [TODO] **Daemon block JSON ingest rejects omitted/invalid memo fields under relaunch policy**
    - **Scenario:** Submit block JSON payloads that omit `encrypted_memo` or provide malformed memo field structure.
    - **Primary path:** `daemon.go` (`handleBlock`, `processBlockData`) and downstream block/tx validation.
    - **Test setup:** Start test daemon, submit crafted block JSON variants through ingest entrypoints.
    - **Shared helpers:** `mustCreateTestChain`, `mustStartTestDaemon`, `mustSubmitBlockData` (or JSON variant helper).
    - **Assertions:** Ingest rejects policy-invalid memo field payloads and does not mutate chain state.
    - **Suggested files:** `daemon_block_ingest_test.go`.

29. [TODO] **Relaunch blocker list is explicit and machine-checkable in `problems.md`**
    - **Scenario:** Critical relaunch blockers are not distinguishable from non-blocking process/doc items.
    - **Primary path:** `problems.md` triage structure.
    - **Test setup:** Add a relaunch-blocker section/tagging convention and validate presence/format via consistency check.
    - **Shared helpers:** none required.
    - **Assertions:** CI/check fails when blocker tagging is missing/inconsistent for designated relaunch-critical findings.
    - **Suggested files:** `problems_consistency_test.go`.

30. [TODO] **Docs/OpenAPI/runtime defaults and memo contract drift guard**
    - **Scenario:** Field names/defaults in docs and OpenAPI drift from handler/runtime behavior.
    - **Primary path:** `README.md`, `relaunch.md`, `api_openapi.json`, `api_handlers.go`, runtime default sources (`main.go`, `cli.go`, `daemon.go`).
    - **Test setup:** Add lightweight contract/consistency checks parsing schema/docs and comparing against handler/default constants.
    - **Shared helpers:** none required.
    - **Assertions:** Check fails on mismatch for memo fields (`memo_text`/`memo_hex`) and relaunch default path/filename values.
    - **Suggested files:** `api_openapi_contract_test.go`, `defaults_consistency_test.go`.

31. [TODO] **Explorer/API memo exposure policy regression guard (ciphertext-only where intended)**
    - **Scenario:** Future UI/API changes accidentally expose plaintext memo or unsafe rendering in public surfaces.
    - **Primary path:** `explorer.go`, `api_handlers.go` tx/history/public response shaping.
    - **Test setup:** Request explorer tx view/API tx endpoints for transactions with memo payloads and inspect rendered/serialized fields.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** Public surfaces only expose intended memo representation and preserve safe rendering policy.
    - **Suggested files:** `explorer_tx_memo_policy_test.go`, `api_tx_policy_test.go`.

32. [TODO] **Canonical serialized-size accounting is used consistently for block-size enforcement and cheap prefilters**
    - **Scenario:** Blocks near size limit produce different outcomes under approximate vs canonical size accounting.
    - **Primary path:** `block.go` (`Transaction.Size`, `Block.Size`, `ValidateBlock`), `daemon.go` (`validateBlockCheapPrefilters`).
    - **Test setup:** Construct edge-size blocks with realistic tx payloads (including fixed memo overhead) and run both prefilter and consensus validation paths.
    - **Shared helpers:** `mustCreateTestChain`, `mustAddGenesisBlock`, `assertTipUnchanged`.
    - **Assertions:** All size gates evaluate the same canonical size and produce consistent accept/reject decisions.
    - **Suggested files:** `block_size_consensus_test.go`, `daemon_gossip_penalty_test.go`.

33. [TODO] **`DeserializeTx` fuzz/property invariants hold for memo-era wire format**
    - **Scenario:** Randomized malformed/truncated/overlong transaction byte streams with memo fields.
    - **Primary path:** `transaction.go` (`DeserializeTx`).
    - **Test setup:** Add fuzz/property test harness over transaction bytes and targeted mutation corpus.
    - **Shared helpers:** parser corpus builders from serialization tests.
    - **Assertions:** No panics, deterministic accept/reject behavior, and exact-consumption invariant on successful parse.
    - **Suggested files:** `transaction_fuzz_test.go` (or Go fuzz target in `transaction_serialization_test.go`).

34. [TODO] **Memo crypto test vectors remain stable across environments**
    - **Scenario:** Fixed memo inputs/secrets/indexes must produce deterministic ciphertext/plaintext vectors.
    - **Primary path:** `wallet/memo.go` (`EncryptMemo`, `DecryptMemo`, envelope builder).
    - **Test setup:** Add fixed vector table and verify round-trip + exact byte outputs.
    - **Shared helpers:** none required.
    - **Assertions:** Vector outputs remain stable; decrypt rejects invalid vector mutations deterministically.
    - **Suggested files:** `wallet/memo_test.go`.

35. [TODO] **Memo failure telemetry is emitted and thresholded**
    - **Scenario:** Invalid memo envelopes/decrypt failures occur during scanner operation.
    - **Primary path:** `wallet/scanner.go` memo decrypt/validation path and diagnostics/metrics surfaces.
    - **Test setup:** Feed crafted blocks with invalid memo envelopes and assert telemetry counters/log hooks update.
    - **Shared helpers:** `mustCreateTestChain`, scanner test helpers.
    - **Assertions:** Failures are observable via metrics/log counters and can support alert thresholds.
    - **Suggested files:** `wallet/scanner_test.go`, diagnostics tests.

36. [TODO] **OpenAPI examples cover empty/utf8/hex memo edge cases**
    - **Scenario:** Client generation and docs rely on examples for optional memo behavior.
    - **Primary path:** `api_openapi.json` memo fields in send/history schemas.
    - **Test setup:** Validate examples against schema and compare against handler response behavior.
    - **Shared helpers:** schema validation helper and API request helper.
    - **Assertions:** Examples are schema-valid and cover empty, text, and hex memo cases with correct field presence.
    - **Suggested files:** `api_openapi_contract_test.go`.

37. [TODO] **Wallet persistence growth benchmark/regression guard for memo storage**
    - **Scenario:** Long-lived wallet accumulates outputs/send records with memo payloads.
    - **Primary path:** `wallet/wallet.go` persistence encode/decode/save paths.
    - **Test setup:** Benchmark and regression test with synthetic large output/send-history sets including memo data.
    - **Shared helpers:** wallet fixture builders.
    - **Assertions:** File growth and save/load latency remain within documented expectations; regressions are detectable.
    - **Suggested files:** `wallet_persistence_bench_test.go`, `wallet_persistence_test.go`.

38. [TODO] **Send API idempotency behavior is deterministic under retries**
    - **Scenario:** Client retries `POST /api/wallet/send` with same idempotency key under timeout/retry conditions.
    - **Primary path:** `api_handlers.go` (`handleSend`) plus idempotency key storage/replay path.
    - **Test setup:** Submit repeated send requests with identical idempotency key and payload; vary timing and retry order.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** Duplicate keyed requests return the same tx result without creating additional transfers; mismatched payload+same key is rejected deterministically.
    - **Suggested files:** `api_send_idempotency_test.go`.

39. [TODO] **Memo text normalization policy is enforced consistently across CLI and API**
    - **Scenario:** Equivalent Unicode memo strings in different normalization forms are submitted through both interfaces.
    - **Primary path:** `api_handlers.go` memo text ingest, `cli.go` memo text path.
    - **Test setup:** Submit normalization-variant memo_text values and compare stored/serialized memo bytes.
    - **Shared helpers:** `mustMakeHTTPJSONRequest`.
    - **Assertions:** Behavior matches declared policy (normalized equivalence or raw-byte distinction) consistently for CLI/API.
    - **Suggested files:** `api_send_memo_policy_test.go`, `cli_send_test.go`.

40. [TODO] **Memo anomaly metrics/telemetry emit expected counters under malformed inputs**
    - **Scenario:** Scanner/ingest paths process valid and malformed memo envelopes.
    - **Primary path:** memo decode/validation telemetry hooks in scanner/daemon diagnostics.
    - **Test setup:** Feed controlled batches with mixed memo validity and inspect metric/log outputs.
    - **Shared helpers:** scanner/daemon test helpers.
    - **Assertions:** Metrics/log counters reflect malformed rate and classification accurately enough for alerting.
    - **Suggested files:** diagnostics/metrics tests (for example `wallet/scanner_test.go`, daemon metrics tests).

41. [TODO] **Deterministic memo edge-case fixture corpus is enforced across memo parser/crypto paths**
    - **Scenario:** Run fixed fixtures for empty, max-length, non-UTF8, invalid checksum/version, and malformed envelopes.
    - **Primary path:** `wallet/memo.go` (`EncryptMemo`, `DecryptMemo`) and tx serialization/decode integration.
    - **Test setup:** Add versioned fixture table and run through parser/encrypt/decrypt and serialization round-trip checks.
    - **Shared helpers:** fixture loader/table helper.
    - **Assertions:** Fixture outputs remain stable and failures are deterministic for invalid vectors.
    - **Suggested files:** `wallet/memo_test.go`, `transaction_serialization_test.go`.

42. [TODO] **Relaunch memo constants/spec are synchronized from a canonical params source**
    - **Scenario:** Constants drift between docs and code during refactors.
    - **Primary path:** canonical params module + references in memo/tx/docs.
    - **Test setup:** Add consistency check asserting memo size/version/domain labels in code and docs match canonical values.
    - **Shared helpers:** none required.
    - **Assertions:** CI fails on mismatch across canonical params, implementation, and documented relaunch spec.
    - **Suggested files:** `defaults_consistency_test.go`, `problems_consistency_test.go`.

### Deferred test restoration after bug crunch

- [DONE] Rebuilt `daemon_reorg_mempool_test.go` coverage around daemon ingest + reorg mempool reconciliation.
- [DONE] Rebuilt `p2p/sync_reorg_test.go` coverage around near-tip overlap behavior (sync start overlap window).
- [DONE] Rebuilt `mempool_reorg_test.go` coverage for mempool connect/disconnect behavior across reorganizations.
- [DONE] Rebuilt `p2p/sync_recovery_test.go` coverage for orphan backfill and sync-manager recovery flow.
