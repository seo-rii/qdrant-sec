# qdrant-sec Large Work Plan

이 문서는 `RISK_REGISTER.md`의 대형 작업을 구현 순서대로 정리한다. 작은 방어 패치는 이미 별도 커밋으로 일부 처리됐고, 여기서는 설계, migration, 테스트 인프라, 구조 변경이 필요한 작업만 다룬다.

기준 브랜치: `sec`
최종 갱신: 2026-07-28

## 작업 원칙

- 각 단계는 독립 커밋 또는 작은 PR 단위로 끝낸다.
- 보안 기능은 fail-closed 테스트를 먼저 추가하고 구현한다.
- collection config 변경, key lifecycle, snapshot/replication 동작은 문서와 테스트 없이 코드만 바꾸지 않는다.
- legacy `params.ckks`는 더 이상 호환성 표면으로 유지하지 않고, collection config는 canonical `params.encryption`만 허용한다.
- `RISK_REGISTER.md`는 추적 문서이고 커밋 대상이 아니다.

## 현재 상태 요약

완료되었거나 현재 브랜치에서 fail-closed로 고정된 영역:

- Payload server-side encrypt-before-storage는 public upsert/set/overwrite/batch ingress에 연결되어 있다.
- Client-side zero-trust payload insert는 `$qdrant_client_aead`, mandatory Ed25519 signature, stable crypto identity, RK id/epoch/kdf-domain policy, request/process/collection-local persisted nonce replay cache를 사용한다.
- Server/client payload envelope provenance는 direct enum variant 조립 없이 safe constructor와 runtime-verified envelope key proof를 통해 collection write guard로 전달된다.
- Generic MK/RK material, wrapped RK, explicit opaque `material_fingerprint_id`, `rk_id`/`rk_epoch` envelope metadata, retired-material decrypt path, MK rewrap primitive가 들어가 있다.
- Public params diff와 direct config validation은 encryption/ckks mutation을 migration path 밖에서 거부한다.
- `ApplyCryptoMigration` meta operation과 migration plan validation/apply primitive가 있으며, dry-run은 config를 변경하지 않는다.
- Payload index/filter/order/group/formula/facet은 encrypted content에 대해 fail-closed 된다.
- CKKS encrypted vector dense ingest/update는 payload sidecar storage로 연결되어 있고, plaintext vector는 dense vector storage에서 제거된다.
- REST/gRPC legacy `search`, root direct `query`, raw-dense recommend/discover/context는 CKKS sidecar scoring으로 연결되어 있다. Nearest-neighbor `hnsw_ef` 요청은 segment-level CKKS ciphertext HNSW index primitive를 사용하며, graph cache는 in-memory와 collection-local disk cache로 보존된다.
- Quantization/ACORN/indexed-only search params와 plaintext-vector `HNSWIndex` file-format reuse는 아직 unsupported 상태에서 fail-closed 된다. Client-supplied encrypted CKKS query ciphertext, search matrix, prefetch/fusion/MMR, point-id recommend/discover/context examples, grouped variants는 문서화된 범위에서 sidecar scoring으로 라우팅된다.
- Snapshot/restore preflight, shard-transfer/replication/resharding start, dead-replica recovery source selection, readiness gate는 encrypted collection의 runtime crypto parity mismatch를 fail-closed 한다.
- OpenFHE bridge path/hash validation, parent-dir checks, env secret stripping, timeout/stdout/stderr malicious-behavior coverage, worker crash retry, worker pool, batch protocol, Linux Landlock write-deny and optional network-namespace egress-deny backend kinds가 들어가 있다.
- CKKS parameter allowlist는 정적 profile registry를 통해 관리하며, 현재 registry에는 `ckks-128-n16384-d4-scale50`만 포함한다.
- Encrypted payload read policy는 raw/redacted/decrypted 모드로 연결되어 있다. `decrypted`는 server-side `$qdrant_sec` payload text와 metadata value AEAD markers에만 적용되고 runtime settings와 global manage 또는 collection-scoped `payload_decrypt` 권한이 필요하며, client-side `$qdrant_client_aead`는 계속 raw/redacted만 지원한다.
- Metadata value AEAD와 client-generated blind-index token field는 canonical provider로 들어갔다. Blind-index token은 exact-match 전용이고 range/geo/full-text searchable encryption은 계속 unsupported다.
- `vector/private-hnsw-oram@v1`와 `payload/private-result-oram@v1`는 Phase 11 provider/API/store/SDK helper surface까지 연결되어 있다. Qdrant는 private HNSW ORAM에서 encrypted bucket store, manifest/signature validation, non-empty verifier registry validation, session lease, fixed-budget read/commit, epoch/root CAS만 수행하고, client SDK가 HNSW traversal, distance 계산, top-k, result payload ORAM fetch planning을 수행한다.
- Private ORAM REST/gRPC surface, OpenAPI Beta paths, metrics endpoint labels, snapshot/restore preflight, active-session snapshot/recovery/update/delete guard, ordinary search/upsert/payload read fail-closed guard, redaction/leakage tests가 들어가 있다.

남은 대형 작업:

- CKKS encrypted vector production-grade indexing: sidecar storage/search, segment-level ciphertext HNSW graph primitive, and client-supplied encrypted query ciphertext scoring are implemented, but plaintext-vector `HNSWIndex` file-format reuse, score decryption, and broader distributed rebuild/recovery coverage are still not implemented.
- OpenFHE checked bridge execution is Linux-only: runtime construction requires SHA-256 pinning and fd-backed `/proc/self/fd` execution, while non-Linux builds fail closed instead of using path-based validation/hash/exec.
- Crypto migration workflow: admin plan/rewrite/decrypt endpoints, point scan, verified checkpoint, decrypt completion, and re-encrypt primitive are implemented. 남은 범위는 background orchestration, persisted resume scheduling, rollback automation, and old-key disable/destroy retirement gate다.
- Cluster-wide client nonce replay ledger: request/process/collection-local/reload cache는 있지만 consensus-backed global ledger는 없다. Clustered client payload writes와 client-supplied CKKS encrypted query envelopes는 ledger가 구현될 때까지 fail-closed 된다.
- Metadata encryption: server-side metadata value AEAD와 client-generated exact-match blind-index token field provider/query integration은 들어갔다. Metadata value AEAD는 `encrypted_payload=decrypted` read mode와 `payload_decrypt` 권한을 공유한다. Server-computed tokens, range/geo/full-text searchable encryption, and dedicated metadata RBAC는 아직 없다.
- Encrypted payload read policy: raw envelope 반환은 기본값이고, REST/gRPC redacted/decrypted modes와 collection-scoped `payload_decrypt` capability는 연결되어 있다. 남은 범위는 export/read dump 정책과 SDK-side client envelope decrypt flow다.
- KMS/Vault key providers: local/env/file/fd/`unix_socket`/`vault_kv2`/wrapped material 기반은 있지만 external KMS lifecycle은 future work다.
- Broader distributed integration: current unit/integration coverage는 많지만 multi-node parity/restore/replay ledger e2e는 남아 있다.
- Private HNSW ORAM productionization: read-only bulk-built consensus-backed single-writer MVP, result ORAM fetch path, fixed multi-shard owner-union replication, per-shard manual/automatic `stream_records` preinstall, ReplicateShard/MoveShard/automatic recovery process E2E, partial live-preinstall failure/retry, active transfer abort/retry, exact active marked fixed-layout 및 reshard transfer restart/repreinstall, active reshard source hard-crash 상태 보존과 target-triggered automatic fresh-preinstall resume, existing-peer active-reshard Raft snapshot topology recovery, topology-only non-owner, exact scale-up target, 그리고 `MigratingPoints`의 redundant non-endpoint pre-layout owner와 transfer-complete single-shard scale-down endpoint snapshot bootstrap, durable exact-reshard rollback marker, precommitted recovery layout CAS, chunked internal full-store transport, 63-bucket large-bundle process benchmark, durable collection-level layout CAS, typed scale-up/scale-down reshard start/progress/finish, exact active `resharding_stream_records` preinstall, existing/new-owner custom shard-key create와 non-final drop, HNSW-only 및 HNSW+result process E2E 기반은 들어갔다. Fixed-target resume의 source-side durable preinstall intent, crash-point, stale root/signature process fault matrix도 닫혔다. Non-redundant owner external restore에는 signed checkpoint, consensus lease, bounded staging, read-only full-topology preflight, durable install marker, lifecycle tombstone, rollback/commit CAS와 REST commit route까지 들어갔다. 남은 release gate는 RF=1 single/multi-shard hard-crash process E2E와 첫 proof-verified read/writeback이며, 그 다음 v2 범위는 새 provider의 fixed-capacity append-only insertion이다. True multi-writer는 v3로 분리한다.
- 2026-07-29 snapshot 상태 교정: fixed-layout active transfer는 ordered index checkpoint와 consensus-bound pre/post layout을 검증한다. 모든 로컬 shard에 다른 `Active` replica가 있는 wiped fixed-transfer source/owner와 transfer-complete scale-down endpoint는 durable exact-abort marker 뒤 stable automatic recovery를 수행하며, multi-shard endpoint는 shard별 generation-`+1` CAS로 복구한다. Pre-layout owner가 아니고 다른 pre-layout shard도 소유하지 않는 fresh `Partial` target은 collection 전체 또는 모든 configured ORAM store가 사라졌을 때 durable exact-resume marker 뒤 source의 새 reservation/full-store preinstall과 same-key restart로 복구한다. Partial store loss, stale existing store, already-active target은 계속 fail closed 한다. RF=1 비중복 owner/source의 same-peer external recovery install/commit primitive는 구현됐지만 process-level restore/restart/readback gate가 끝날 때까지 experimental fail-closed 경계로 유지한다.

## Phase 0: 기준선 고정

목표: 이후 대형 변경이 현재 보안 계약을 깨뜨리지 않도록 최소 regression suite를 고정한다.

작업:

- `cargo test -p qdrant-ckks --test aead_security --test payload_security --test vector_security`를 기본 crypto regression으로 고정한다.
- `cargo test -p collection ckks`를 collection config regression으로 고정한다.
- 현재 문서화된 미지원 범위가 실제 API/schema와 어긋나지 않는지 확인한다.
- `RISK_REGISTER.md`의 이미 처리된 항목은 별도 후속 정리에서 상태를 `완료`로 바꾼다.

완료 조건:

- 기준 테스트 명령이 로컬에서 통과한다.
- 향후 phase별 PR 설명에서 이 기준 테스트를 재사용할 수 있다.

## Phase 1: Crypto Schema와 Migration State Machine

대상 리스크: `CONF-001`, `SEC-003`, `TEST-001`

목표: encryption rule 변경을 일반 config update가 아니라 명시적 migration workflow로 모델링한다.

작업 순서:

- collection config에 `crypto_schema_version` 또는 `encryption_epoch`를 추가한다.
- encrypted payload marker와 CKKS vector envelope에 schema/epoch를 기록한다.
- migration 상태를 `Disabled`, `Encrypting`, `Active`, `Rotating`, `Decrypting`으로 정의한다.
- 일반 collection update에서는 encryption enable/disable/rule 변경을 계속 거부한다.
- admin-only migration plan/rewrite/decrypt command를 유지하고, point scan과 verified checkpoint를 completion gate로 사용한다.
- completion checkpoint는 모든 shard id를 커버해야 하며, local shard가 있는 node에서는 checkpoint `total_points`가 실제 local shard point count와 일치해야 한다.
- migration dry-run이 변경 대상 point 수, selector 충돌, key availability를 보고하도록 유지한다.
- disable/decrypt migration은 client-side opaque envelope와 blind-index token을 건드리지 않으며, server-side decrypt completion은 verified checkpoint를 요구한다.
- 남은 작업은 migration run을 background task로 예약/재개하고, 실패 rollback과 old-key disable/destroy retirement gate를 운영 API로 묶는 것이다.

테스트:

- migration 없이 encryption config 변경 시 실패한다.
- migration 시작 후 collection 상태가 `Encrypting` 또는 `Rotating`으로 저장된다.
- rewrite/decrypt endpoint가 verified checkpoint를 반환하고 completion plan이 shard coverage와 local shard point count를 검증한다.
- 중단 후 재시작 시 background scheduler가 저장된 checkpoint부터 재개한다.
- 잘못된 key/runtime instance가 있으면 migration 시작 전에 실패한다.

완료 조건:

- 동일 collection 안에서 plaintext/ciphertext schema가 silent mixing되지 않는다.
- migration 없는 enable, disable, selector 변경, key 변경이 모두 fail-closed다.

## Phase 2: Key Lifecycle, Versions, and Rotation

대상 리스크: `SEC-003`

목표: active/retired key를 구분하고, rotation과 old key retirement를 안전한 상태 전이로 만든다.

작업 순서:

- runtime crypto material에 `key_version` 또는 `material_fingerprint`를 추가한다.
- AEAD envelope와 CKKS vector metadata에 `key_version` 또는 `material_fingerprint`를 기록한다.
- decrypt path는 active key와 retired key를 허용하되, encrypt path는 active key만 사용한다.
- re-encrypt primitive를 Phase 1 migration framework 위에 유지하고, endpoint가 stale envelope를 active RK로 reseal한다.
- old key retirement 전 full scan verification과 verified checkpoint를 요구한다.
- inline key material은 production/security mode에서 거부하거나 warning/audit event를 남긴다.
- KMS/Vault key source는 interface만 먼저 고정하고 구현은 provider별로 분리한다. File descriptor, Unix socket, Vault KV v2 direct material source는 운영용 fallback으로 유지한다.

테스트:

- old key로 암호화된 payload/vector envelope를 retired key로 복호화할 수 있다.
- 새 write는 active key로만 암호화된다.
- old key 제거 전 검증 실패 시 retirement가 중단된다.
- wrong key, wrong key_id, wrong key_version은 fail-closed다.

완료 조건:

- rotation 중 read/write가 어느 key를 쓰는지 문서와 코드에서 명확하다.
- key retirement는 검증 없이는 성공할 수 없다.

## Phase 3: Storage Path Threat Model and Plaintext Leakage Tests

대상 리스크: `SEC-004`, `TEST-001`

목표: WAL, segment, payload index, snapshot, shard transfer 경로에서 plaintext 노출 여부를 테스트로 증명한다.

작업 순서:

- `docs/ckks.md`에 ingress, WAL, segment, payload index, HNSW, snapshot, shard transfer, telemetry/log 경로별 plaintext/ciphertext 표를 추가한다.
- encrypted payload collection에 sentinel string을 upsert하는 integration fixture를 만든다.
- WAL, segment files, optimizer temp segment, snapshot archive에서 sentinel string이 검색되지 않는 테스트를 추가한다.
- vector plaintext byte pattern 또는 deterministic fixture vector가 segment/snapshot에 남지 않는지 검사한다.
- payload index 생성 시 encrypted field는 거부하거나 blind index 요구로 fail-closed한다.
- telemetry/log/audit output에 plaintext embedding/request body가 들어가지 않는지 smoke test를 추가한다.

테스트:

- plaintext string leakage scan.
- embedding byte pattern leakage scan.
- encrypted field index creation reject.
- snapshot archive scan.
- optimizer temp path scan.

완료 조건:

- `encrypt before storage` 주장이 테스트로 방어된다.
- plaintext가 남는 경로가 발견되면 해당 경로는 코드 수정 전까지 문서상 unsupported로 표시된다.

## Phase 4: Snapshot, Restore, Replication, and Cluster Fail-Closed

대상 리스크: `SEC-004`, `TEST-001`

목표: snapshot restore, shard transfer, replica sync에서 key/context 불일치가 silent partial success로 끝나지 않게 한다.

작업 순서:

- snapshot metadata에 필요한 crypto schema, key id/version, CKKS context digest summary를 기록한다.
- restore preflight에서 runtime key registry와 OpenFHE context availability를 검증한다.
- missing key, wrong key, wrong key_id, wrong context 정책을 정의한다.
- partial restore 허용 여부를 명시하고 기본은 fail-closed로 둔다.
- cluster node별 crypto instance registry health check를 추가한다.
- shard transfer 전 송신/수신 node의 crypto capability parity를 확인한다.

테스트:

- snapshot restore with missing key 실패.
- snapshot restore with wrong key 실패.
- snapshot restore with wrong CKKS context 실패.
- node A has key, node B missing key 상태에서 write/read/shard transfer 실패.
- replica join 전에 crypto registry mismatch가 health check에 노출된다.

완료 조건:

- key/context가 맞지 않는 cluster operation이 데이터 일부만 살리고 성공하지 않는다.
- 운영자가 restore 전에 어떤 runtime material이 필요한지 알 수 있다.

## Phase 5: OpenFHE Bridge Pool, Backpressure, and Protocol Efficiency

대상 리스크: `SEC-002`, `PERF-001`

목표: bridge worker를 단일 mutex 직렬 처리에서 process pool로 바꾸고, timeout/restart 경로를 검증한다.

작업 순서:

- `CryptoBackendConfig.size`가 실제 process pool size로 동작하도록 backend factory를 연결한다.
- worker pool abstraction을 추가한다.
- pool saturation은 caller를 무제한 queue에 쌓지 않고 worker request lock/timeout 경로에서 fail-closed 또는 backpressure semantics를 유지한다.
- worker별 stdin/stdout reader lifecycle을 독립 관리한다.
- timeout, EOF, invalid JSON, huge stdout/stderr, process exit 후 worker 재시작을 pool 단위로 처리한다.
- batch encrypt request/response protocol을 추가한다.
- successful first request 이후 같은 worker/context에서는 context/public key를 재전송하지 않는 cache protocol을 유지한다.
- binary framing 또는 MessagePack/CBOR 전환은 batch protocol 안정화 후 별도 단계로 진행한다.

테스트:

- concurrent encrypt N개가 pool size만큼 병렬 처리된다.
- queue 초과 시 bounded error가 반환된다.
- timeout worker만 재시작되고 다른 worker는 유지된다.
- no newline, huge stdout, huge stderr, invalid JSON, exit-after-write가 모두 fail-closed다.
- batch encrypt가 point-by-point 결과와 같은 envelope semantics를 유지한다.

완료 조건:

- bridge throughput이 단일 worker mutex에 의해 전역 직렬화되지 않는다.
- malicious bridge behavior가 pool 전체를 고착시키지 않는다.

## Phase 6: CKKS Parameter Profiles and OpenFHE Security Verification

대상 리스크: `SEC-005`

목표: 임의 raw parameter가 아니라 검증된 profile 중심으로 CKKS parameter를 받는다.

작업 순서:

- `ckks-128-d4` 같은 allowlisted profile enum을 정의한다.
- 기존 raw params는 `experimental_raw_params` 또는 feature flag 뒤로 이동한다.
- OpenFHE bridge가 security level, chain depth, scale/noise budget 검증 결과를 response에 포함하도록 protocol을 확장한다.
- Qdrant 쪽은 bridge 검증 결과가 없거나 mismatch면 collection create/update를 거부한다.
- known-safe profile table을 문서화한다.

테스트:

- allowlisted profile은 통과한다.
- raw params는 experimental flag 없이는 실패한다.
- OpenFHE security level mismatch는 실패한다.
- depth/scale/profile mismatch는 context digest와 validation에서 동시에 잡힌다.

완료 조건:

- 사용자가 임의 범위값만으로 unsafe CKKS context를 만들 수 없다.
- profile과 OpenFHE 검증 결과가 collection config에 명확히 남는다.

## Phase 7: Metadata Encryption and Blind Index Design

대상 리스크: `DOC-001`, `TEST-001`

목표: metadata encryption을 값 암호화와 exact-match 검색용 blind index로 분리해서 구현한다.

작업 순서:

- `metadata/aes-256-gcm@v1` metadata value AEAD와 `metadata/blind-index-hmac@v1` exact-match token provider contract를 분리한다. Exact-match blind-index token field는 `metadata/blind-index-hmac@v1` + `metadata-exact-match-token/v1`로 구현되어 있고, Qdrant는 token을 계산하지 않는다.
- metadata value envelope schema는 server-side `$qdrant_sec` AEAD marker를 사용하며 payload text와 동일한 write-provenance/fail-closed guard와 `encrypted_payload=decrypted` read policy를 탄다.
- exact-match token은 client/SDK가 deterministic HMAC/HKDF subkey로 만들고 원문 값을 저장하지 않는다.
- payload filter planner가 encrypted metadata field에 range/geo/full-text filter를 요청하면 거부한다.
- exact-match filter는 별도 blind-index token field를 대상으로 할 때만 허용한다.
- API docs에 지원/비지원 filter matrix를 추가한다.

테스트:

- metadata value는 retrieve/search/scroll에서 기본 raw marker로 반환되고, `encrypted_payload=decrypted`와 collection `payload_decrypt` 권한이 함께 있을 때 서버가 복호화해 반환한다.
- exact-match filter는 blind index token으로 동작한다.
- range/geo/full-text filter는 실패한다.
- metadata value selector는 `metadata-value/v1` binding과 `metadata/aes-256-gcm@v1` provider일 때만 허용하고, unsupported metadata bindings/providers는 계속 fail-closed 한다.

완료 조건:

- "metadata encryption 지원"이라는 문구가 실제 API 동작과 일치한다.
- AEAD-only metadata field가 검색 가능한 것처럼 보이지 않는다.

## Phase 8: Search Semantics Decision and Executor

대상 리스크: `ARCH-001`, `DOC-002`

목표: encrypted vector collection이 어떤 검색 모델을 지원하는지 타입과 API로 강제한다.

선택지:

- A안: at-rest encryption only. 검색은 plaintext vector 또는 별도 surrogate vector만 사용한다.
- B안: similarity-preserving/searchable encryption. 별도 보안 모델과 leakage profile을 문서화한다.
- C안: CKKS sidecar scoring. Qdrant dense vector storage에는 plaintext를 남기지 않고 `$qdrant_sec_vectors` sidecar ciphertext를 score한다.
- D안: native segment CKKS ciphertext HNSW index. Segment-level graph/index primitive는 들어갔지만, plaintext-vector `HNSWIndex` file format 재사용과 full collection optimizer lifecycle 통합은 별도 작업이다.

작업 순서:

- C안 sidecar storage/search는 현재 canonical 구현으로 선택됐다.
- `VectorCryptoBackend` capability는 encrypt, batch encrypt, encrypted-query scoring, stored-ciphertext scoring을 제공한다.
- collection create/update path는 encrypted dense vectors를 payload sidecar envelope로 저장하고 plaintext vector write를 제거한다. Sparse/multi-dense vector는 fail-closed 한다.
- query API는 plaintext dense query vectors를 bridge에서 encrypted query ciphertext로 변환할 수 있고, client-supplied encrypted CKKS query ciphertext도 sidecar scoring path로 받는다.
- Nearest-neighbor `search`/root direct `query`는 brute-force sidecar scoring 또는 `hnsw_ef` 기반 segment-level CKKS ciphertext HNSW graph를 사용한다. Serving records는 payload sidecar에서 읽고, graph primitive는 segment index type으로 관리한다.
- retrieve with/without decrypt, query failure modes, unsupported Qdrant flows는 `docs/ckks.md` 지원 matrix에 맞춰 계속 유지한다.

테스트:

- encrypted vector collection에서 unsupported search path는 명확한 error를 반환한다.
- Sidecar ingest/search/query/recommend/discover/context는 raw sidecar payload 반환, `with_vector` fail-closed, score threshold, wrong OpenFHE context fail-closed, plaintext vector leakage scan으로 검증된다.
- Segment-level CKKS ciphertext HNSW graph cache는 build, in-memory cache, disk persistence, pruning, hardening, stale/asymmetric cache ignore, and segment index file exposure tests로 검증된다.
- Plaintext-vector `HNSWIndex` file-format reuse와 score decrypt lifecycle은 아직 unsupported contract로 남긴다.

완료 조건:

- 사용자가 sidecar HNSW graph cache를 native Qdrant segment `HNSWIndex`로 오해할 수 없다.
- 지원되는 검색 모델과 unsupported 모델이 API validation, runtime capability, docs matrix, regression tests로 강제된다.

## Phase 9: Internal Crypto Module Split

대상 리스크: `ARCH-002`, `CONF-003`

목표: CKKS 중심 crypto layer를 `lib/crypto`의 공통 crypto layer와 provider-specific layer로 나눈다.

작업 순서:

- 내부 canonical type을 generic crypto plan으로 고정한다.
- legacy `params.ckks` REST/gRPC/schema 표면을 제거하고, canonical `params.encryption`만 받아들인다.
- 공통 AEAD envelope, key derivation, runtime registry를 `lib/crypto` 또는 equivalent module로 이동한다.
- CKKS vector provider를 `crypto-openfhe-ckks` 성격으로 분리한다.
- payload AEAD provider와 blind-index provider를 독립 모듈로 둔다.
- public exports와 docs를 새 경계에 맞춘다.

테스트:

- legacy config와 generic config가 같은 compiled plan으로 normalize된다.
- legacy projection은 key_id를 잃지 않는다.
- provider별 tests가 공통 crypto tests와 분리된다.

완료 조건:

- CKKS 고유 코드와 공통 crypto 코드의 책임 경계가 명확하다.
- 새 provider 추가가 CKKS 전용 모듈 경계에 계속 결합되지 않는다.

## Phase 10: User-Facing Examples and Release Gate

대상 리스크: `DOC-002`, `TEST-001`

목표: 운영자가 실제로 collection 생성부터 query/retrieve/failure mode까지 따라 할 수 있게 한다.

작업 순서:

- runtime config 예제를 generic `crypto.instances/materials/backends` 기준으로 갱신한다.
- collection create 예제를 legacy와 generic 중 canonical 하나로 정리한다.
- point upsert, retrieve, decrypt, query 예제를 작성한다.
- unsupported 기능 목록을 API docs와 `docs/ckks.md`에 맞춘다.
- PR 전 release gate checklist를 추가한다.

테스트:

- 문서 예제 JSON/YAML이 schema validation을 통과한다.
- smoke test가 예제 collection create/upsert/retrieve 경로를 실행한다.

완료 조건:

- 문서만 보고도 현재 지원 범위와 실패 모드를 이해할 수 있다.
- release gate가 security tests, migration tests, cluster tests, bridge tests를 모두 요구한다.

## Phase 11: Strict Zero-Trust Search with Private HNSW ORAM

목표: `vector/private-hnsw-oram@v1` provider를 추가해 strict zero-trust profile에서 검색 가능한 server-blind ANN path를 제공한다. Qdrant는 encrypted ORAM bucket store와 epoch/root CAS만 수행하고, client SDK가 HNSW traversal, distance 계산, top-k 결정을 수행한다.

작업 순서:

- Phase A: control-plane provider/binding const, runtime allowlist, strict-profile validation, collection binding validation, normal vector write/search fail-closed guard를 추가한다.
- Phase B: `PrivateHnswOramManifest` 타입, manifest signature format, collection-local `private_hnsw_oram/{vector}` store, bucket read/write primitive, epoch `current.json` CAS primitive를 추가한다.
- Phase C: REST/gRPC manifest, session open/close, ORAM `read_paths`, `commit`, session lease, single-writer lock, fixed request-size validation을 추가한다.
- Phase D: Rust 또는 Python reference SDK로 read-only bulk build, Path ORAM client, client-led HNSW traversal, known-answer fixtures를 제공한다.
- 현재 Rust helper는 f32 reference neighbor graph build, explicit-level f32 layered graph build, deterministic node-id level assignment, HNSW-style redundant-neighbor pruning, prebuilt node-block ORAM packing, encrypted bucket sealing/Merkle root generation, signed upload bundle packaging/preflight, manifest-aware writeback commit planning, verified encrypted traversal wrapper, optional post-commit signed manifest refresh, client state snapshot export/import, RK-derived encrypted client-state backup을 제공한다. Bulk build는 duplicate node id뿐 아니라 duplicate point token과 duplicate payload fetch token도 fail closed 하고, HNSW node block codec은 empty/non-contiguous level mask, out-of-mask neighbor level, self-neighbor, duplicate same-level neighbor, malformed/empty/non-finite `f32_le` vector bytes를 fail closed 하며, plaintext bucket codec과 client Path ORAM access도 decrypted path block을 stash에 흡수하기 전에 duplicate point/payload fetch token을 거부한다. 서버 테스트는 SDK-packaged manifest/bucket bundle이 REST/gRPC bucket upload와 같은 manifest epoch/root, fixed ciphertext size, Merkle commitment 계약을 만족하는지도 검증하고, crypto crate와 collection store fixture는 context-bound client key derivation으로 SDK upload/read_paths/verified-search/writeback-commit round trip을 검증한다. REST JSON DTO와 gRPC protobuf DTO fixture도 context-bound SDK-built manifest/buckets/session/read_paths/commit wire package를 round trip하고, gRPC fixture는 Merkle proof가 포함된 read response를 SDK verifier에 통과시킨다. REST/gRPC live route fixtures는 Dispatcher-backed collection에서 manifest upload, bucket upload, session open, `read_paths`, SDK proof verification, commit, close, manifest refresh 없이 committed epoch session reopen과 live epoch/root `read_paths`를 통과한다. SDK distribution packaging은 serde-compatible `PrivateHnswOramUploadBundle` API와 `validate_private_hnsw_oram_upload_bundle` preflight로 완료했다.
- Phase E: `ids_visible` result privacy를 문서화하고, `private_payload_oram_required` payload/result fetch 설계를 별도 provider 또는 index-token 확장으로 구체화한다.
  - 현재 working MVP는 `ids_visible`과 `private_payload_oram_required` private HNSW result mode를 구분하고, manifest/session policy도 runtime result privacy와 불일치하는 manifest를 거부한다. Runtime schema와 server-side HNSW manifest upload, bucket upload, session open, snapshot restore preflight는 `private_payload_oram_required`를 collection의 `private-result-oram/v1` payload rule이 `payload/private-result-oram@v1` provider에 함께 묶인 경우에만 허용하고, binding이 없으면 fail closed 한다. HNSW snapshot restore preflight도 paired result ORAM snapshot manifest의 `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누는지 확인해 restored index가 partial final `read_buckets` batch를 만들지 못하게 한다. 일반 Qdrant search/query API는 계속 client-led private session 요구 오류를 반환한다.
  - HNSW SDK search hit은 node block의 `payload_fetch_token`을 전달하기 시작했고, `validate_private_hnsw_search_result_privacy` helper는 `private_payload_oram_required`에서 token 없는 hit을 fail closed 한다. SDK fetch-plan helper는 hit token을 정확히 `fixed_result_k`개 payload/result ORAM fetch token batch로 패딩하되 distinct dummy-token pool을 요구해 중복 logical fetch token, duplicate hit node/point, non-finite hit distance를 거부한다. Collection runtime은 `private_payload_oram_required`에서 result ORAM `oram.path_batch_size`가 private HNSW `fixed_budget.fixed_result_k`를 나누지 못하면 거부해 SDK가 partial final `read_buckets` batch를 만들 수 없게 한다. result ORAM client fetch planner와 verified fetch wrapper도 token batch 길이가 `oram.path_batch_size`의 정확한 배수가 아니면 fail closed 한다. private result ORAM fetch planner는 이 token batch와 client-held token-position map을 session `read_buckets` bucket-id sequence로 바꾸며, shared path bucket 중복을 제거하지 않고 보존해 fixed ORAM path volume이 overlap에 따라 줄어들지 않도록 한다. 서버 read validator도 duplicate bucket id를 허용하되 non-empty, whole-path-shaped, canonical Path ORAM heap path, 정확한 fixed-budget batch만 받는다. crypto crate는 collection/key lineage, index epoch, root hash, bucket count, exact padded bucket-id sequence를 묶는 canonical `read_buckets` message/sign/verify helper도 제공하고, REST/gRPC `read_buckets` API는 이 signed read request를 필수로 검증한 뒤 encrypted bucket read 또는 detailed path-shape error로 진행한다. planner는 missing position, duplicate token, duplicate position entry, out-of-range leaf를 fail closed 한다. private result ORAM client-only payload block/plaintext bucket codec도 추가되어 payload bytes, payload fetch token, point token, generation, deletion state를 fixed-size encrypted bucket body 안에 넣을 수 있다. bucket AEAD seal/open helper는 collection/key/epoch AAD, context-bound bucket commitment, ciphertext hash check, Merkle-proof-before-open read batch 검증까지 제공한다. SDK-side result ORAM state/access helper는 token position map/stash로 payload fetch token을 Path ORAM path에서 꺼내고 새 leaf로 remap한 뒤 commit용 plaintext writeback bucket을 만들며, duplicate payload fetch token과 duplicate point token은 plaintext bucket codec과 stash 흡수 경계에서 fail closed 한다. Verified token-fetch helper는 client position map에서 expected bucket path sequence를 재구성해 read plan과 일치해야만 planned encrypted bucket batches를 열고, fetched payload block의 duplicate point token을 token-fetch result 생성 전에 거부하며, batched Path ORAM access 사이의 local writeback overlay를 적용하고 payload blocks와 result ORAM commit planner용 unique resealed writeback buckets를 반환한다. REST/gRPC result ORAM commit guard는 owner-signed `updated_buckets`를 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget으로 제한해 commit volume이 manifest `bucket_count`까지 확장되지 않게 하고, multi-batch result fetch는 반복 fixed-size read/commit window로 처리한다. empty/duplicate/stale/malformed/invalid-signature commit은 계속 fail closed 한다. HNSW SDK finalizer는 real HNSW hit만 fetched payload block에 매핑하고 fetched token set, point-token binding, deleted payload rejection을 검증한다. HNSW padded fetch-token plan이 result ORAM ordered read planner의 fixed-size batch로 들어간 뒤 reordered fetch 결과를 finalizer가 real hit 순서로 복원하는 연결 테스트도 고정했다. result ORAM client-state plaintext snapshot shape도 추가해 token position map/stash backup shape를 검증하고, duplicate stash payload token과 duplicate stash point token을 import 경계에서 거부한다. encrypted snapshot helper는 client-derived state key와 collection/key/epoch/root AAD로 backup ciphertext를 seal/open한다.
  - Result ORAM `read_buckets` SDK ordered planner `plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens`는 token-position leaf collision을 가능한 다른 fixed batch로 분산하고, configured batch count로 수용할 수 없는 repeated full ORAM path만 fail closed 한다. Verified fetch wrapper, server request validator, crypto message builder는 shared prefix bucket 중복은 보존하되 같은 fixed batch 안의 repeated full ORAM path는 fail closed 한다. 이 invariant는 unschedulable token-position leaf collision이나 stale/malicious read plan이 서버 `read_buckets` 요청으로 나가기 전에 잡히도록 한다.
  - Ordered planner는 작은 Path ORAM fixture의 모든 feasible leaf-count 분포를 스케줄할 수 있는지도 회귀 테스트로 고정해, 대표 collision 케이스뿐 아니라 greedy batch distribution invariant를 폭넓게 검증한다.
  - Ordered result ORAM read plan Debug 표면도 payload fetch token list와 token count를 반사하지 않는 redaction fixture에 포함했다.
  - Result ORAM `read_buckets` crypto message builder/signer/validator는 signed `bucket_count`에서 canonical Path ORAM tree height를 역산하고, non-canonical tree size, partial path, invalid root-to-leaf bucket sequence를 signature acceptance 전에 거부한다.
  - REST/gRPC result ORAM `read_buckets` route fixtures now also assert that signed malformed path-shape errors and out-of-range bucket-id signature failures do not reflect submitted root hashes, session ids, read signatures, or bucket ciphertext bodies.
  - REST/gRPC result ORAM `read_buckets`와 `commit` request signature key id도 session manifest의 `owner_signing_key_id`와 달라도 fail closed 한다. Runtime `signature_public_keys`에 등록된 다른 key id만으로는 해당 private result index의 read/writeback request를 authorize하지 않는다.
- `payload/private-result-oram@v1` runtime provider validation은 초기 E2에서 열렸고 현재 REST/gRPC session/read/commit 표면까지 연결됐다. runtime instance는 server materials/backend 없이 `key_id`, `expected_rk_id`, pinned RK epoch, Path ORAM shape, integrity booleans, signature public key registry만 허용한다. `private-result-oram/v1` collection binding validation은 provider `payload/private-result-oram@v1`만 허용하며 ordinary point upsert/sync/delete/delete-by-filter/payload write/delete/clear plan과 payload index/schema plan에는 들어가지 않는다. 그런 요청은 private result ORAM session API 안내와 함께 fail closed 한다. Ordinary point upsert/sync는 payload 내용이 public-looking이더라도 private result ORAM epoch contract 밖에서 point payload state를 만들거나 교체할 수 있으므로 binding이 있으면 닫고, key-less `overwrite_payload`는 full payload replacement로 취급한다. key-less `set_payload`도 protected path의 parent/child key overlap을 건드리면 fail closed 하며, exact child-only public payload merges만 일반 경로에서 허용한다. Ordinary retrieve/scroll/search/query raw payload reads도 `with_payload`가 private result ORAM payload path를 반환하려 하면 같은 session API 안내와 함께 fail closed 하고, payload 생략 또는 redacted encrypted payload output만 일반 read 경로에서 허용한다. Trusted-bridge CKKS sidecar fallback, point-id resolution, grouped sidecar search, CKKS search matrix는 이제 full raw payload 대신 reserved vector sidecar와 필요한 group key만 요청해 private result ORAM payload path를 실수로 건드리지 않는다. Filter/order-by/group-by/facet/formula selector가 private result ORAM payload path를 inspect하려는 경우도 blind-index 안내 대신 private result ORAM session API 안내로 fail closed 한다. REST/gRPC manifest/bucket upload API, session open/close, signed session-bound `read_buckets`, signed writeback `commit` API도 열었고, live route fixtures는 manifest refresh 없이 committed epoch session reopen과 live epoch/root `read_buckets`를 통과한다.
  - `PrivateResultOramManifest`, `PrivateResultOramBucket`, `PrivateResultOramSignature`, canonical manifest/commit signature message, Ed25519 signature verification/signing helpers, collection/key/epoch/capacity context validation, Path ORAM tree_height/bucket_count validation, encrypted bucket shape/hash validation, context-bound bucket commitment validation, bucket commitment Merkle root/proof verifier, client writeback commit planning helper, manifest-aware writeback commit planning helper, signed upload bundle packaging/preflight, optional post-commit signed manifest refresh helper는 crypto crate에 contract surface로 들어갔다. collection-local `PrivateResultOramStore` 구현은 `private_result_oram/manifest.json`, `manifest.sig`, encrypted buckets, Merkle commitment metadata, epoch `current.json` CAS, canonical `merkle_path_batch/v1` read proof DTO, initial upload bundle ingest, signed initial upload bundle ingest, writeback commit helper를 private HNSW ORAM store와 같은 fail-closed hardening으로 다룬다. initial upload bundle ingest는 crypto crate의 같은 preflight helper를 사용한 뒤 store runtime ciphertext size cap을 추가로 적용하고, signed ingest entrypoint는 owner Ed25519 manifest signature를 검증한 뒤에만 layout/bucket/current epoch 파일을 쓴다. writeback commit helper는 stale current epoch, bucket count, bucket commitment context를 bucket/Merkle writeback 전에 preflight하고, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있는지 Merkle prepare 전에 검증해 실패한 stale/tampered commit이 저장 파일을 먼저 바꾸지 않도록 한다. collection snapshot은 configured `private-result-oram/v1` binding이 있을 때만 `private_result_oram/`을 포함하고, collection restore와 CLI/REST/storage recovery preflight는 manifest/current epoch, buckets, Merkle metadata, runtime Ed25519 signature를 fail-closed로 검증한다. runtime session은 single-writer lock과 active snapshot/upload guard를 사용하며, read/commit은 active session epoch/root와 current store epoch/root가 맞을 때만 수행된다.
  - Phase E rollout은 네 단계로 나눈다. E1은 provider/binding/result privacy enum을 예약하고 store/crypto contract를 fail-closed contract로 고정했다. E2는 runtime provider validation만 열되 collection binding과 API는 계속 닫아 provider options, signature registry, RK pinning, ORAM capacity, ciphertext cap 정책을 먼저 고정했다. E3는 collection binding, snapshot/restore preflight, manifest/bucket upload/read API를 열되 private HNSW `private_payload_oram_required`와 연결하지 않았다. E4는 private result ORAM session/read/commit API와 HNSW result fetch-token SDK linkage를 열었고, HNSW manifest/session/snapshot policy는 collection에 result ORAM binding이 있을 때만 `private_payload_oram_required`를 허용한다.
  - OpenAPI Beta surface는 private HNSW ORAM과 private result ORAM manifest upload/read, bucket upload, session open/close, read, commit REST paths를 노출하고 `docs/redoc/master/openapi.json` 생성물과 consistency endpoint count를 갱신했다. Consistency check는 14개 private ORAM REST method/path/operationId와 14개 generated gRPC method path도 직접 고정한다. REST/gRPC request metrics whitelist도 같은 private ORAM fixed endpoint labels를 포함하되 path labels, bucket ids, session ids, ciphertext, client-state fields는 metric labels에 넣지 않는다. gRPC metrics canonicalization fixture는 HNSW/result manifest get/upload, HNSW bucket upload, read, commit, close-session의 동적 suffix도 fixed method label로만 축약되는지 검증한다.
- Phase F: upper-layer client cache, speculative neighbor prefetch, neighbor clustering, graph-tailored ORAM 실험을 benchmark와 함께 추가한다.
  - upper-layer client cache는 `PrivateHnswClientNodeCache`와 `*_with_cache` search helper로 시작했다. 캐시 hit는 local node copy로 traversal/distance를 수행하되 `padding_node_id` ORAM access를 소비해 fixed-step request volume을 유지한다. Client traversal pending queue도 `VecDeque` 기반 FIFO로 유지해 fixed-step search hot path가 queue pop마다 앞쪽 원소를 shift하지 않는다.
  - search access metrics는 `PrivateHnswSearchResult::access_metrics`와 `PrivateHnswSearchAccessMetrics`로 시작했다. SDK benchmark가 fixed-budget ORAM search의 path access 수, unique leaf 수, budget exhaustion 여부를 plaintext 노출 없이 기록할 수 있다. zero-step params나 malformed access leaf-label이 있는 결과는 빈도/길이가 맞아도 exhausted로 보고하지 않는다. Strict SDK caller용 `validate_private_hnsw_strict_search_result` helper도 추가해 result privacy, canonical access leaf-label shape, finite hit distance, duplicate hit node/point, fixed-step budget exhaustion을 함께 fail-closed로 검증한다. Private result ORAM fetch planner와 payload finalizer도 같은 hit-shape 검증을 반복한다.
  - layered f32 builder는 u64 `level_mask` 경계를 fail-closed로 다룬다. level 63은 `u64::MAX` mask로 표현하고, level 64 이상은 panic/overflow 없이 invalid `levels` config로 거부한다.
  - benchmark harness는 `cargo bench -p qdrant-sec --bench private_hnsw_oram_bench`로 시작했다. 현재는 64x32 f32 fixture의 plaintext index build, fixed-budget plaintext ORAM-HNSW traversal, upper-layer client-cache traversal, client-AEAD encrypted bucket traversal, speculative prefetch planning, neighbor-clustered leaf planning, directional neighbor filtering, graph-traversal path batch planning with retained/path stats를 잰다. Benchmark fixture도 collection/vector/RK epoch context-bound client key derivation을 사용한다.
  - speculative neighbor prefetch는 `plan_private_hnsw_oram_speculative_prefetch` helper로 시작했다. SDK가 client position map에서 후보 node leaf를 deduplicate하고 고정 path 수까지 server `read_paths` duplicate-label guard와 호환되는 unique dummy leaf로 padding한 label 묶음을 만들 수 있다. Leaf-label bucket-path helper도 duplicate label을 bucket sequence 생성 전에 거부한다.
  - neighbor clustering은 `plan_private_hnsw_oram_neighbor_clustered_leaves` helper로 시작했다. bulk build 전에 entry에서 graph-order BFS를 수행해 관련 node chain을 인접 leaf에 배정하는 실험용 leaf planner이며, entry node id가 build block set에 없으면 fallback하지 않고 fail closed 한다. BFS queue는 `VecDeque` 기반이라 planner 자체가 fixture 규모 증가에 따라 불필요한 O(n²) queue shift 비용을 내지 않는다.
  - directional neighbor filtering은 `plan_private_hnsw_oram_directional_neighbor_filter` helper로 시작했다. client가 현재 노드/neighbor block/query vector를 로컬에서 해독한 뒤 query 방향으로 진행하는 neighbor만 거리순으로 고르는 실험용 planner다.
  - graph-traversal tailored ORAM은 `plan_private_hnsw_oram_graph_traversal_path_batch` helper로 시작했다. directional neighbor filter 결과를 client position map과 speculative prefetch padding에 연결해 fixed-size `read_paths` batch를 만든다. `*_with_stats` variant는 directional filter retained count와 실제 position-map-backed path count를 분리해 benchmark가 graph-filter selectivity와 ORAM path volume을 따로 기록할 수 있게 한다.
  - graph traversal/prefetch planner는 real candidate가 0개이거나 directional filter가 모든 neighbor를 버리는 경우에도 dummy leaf로 정확한 fixed-size path batch를 만들고, padding leaf도 중복 없이 순환하는지 회귀 테스트로 고정한다.
  - Strict SDK search result validator는 `ids_visible` result mode에서도 fixed-budget exhaustion을 요구하고, zero-step budget을 invalid config로 거부한다.
- Phase G: cluster parity fingerprint, private-ORAM transfer fail-closed, shard-local epoch ownership, consensus-backed epoch/root CAS를 설계하고 e2e 테스트한다.
  - cluster parity fingerprint는 기존 crypto runtime capability fingerprint에 private HNSW ORAM과 private result ORAM options/signing verifier policy가 포함되는 테스트로 고정했다. ORAM tree shape, private HNSW signing verifier drift, private result ORAM signing verifier drift는 peer parity mismatch로 실패한다. mismatch 오류, `/readyz` readiness mismatch 출력, distributed telemetry mismatch summary는 peer id만 남기고 local/peer fingerprint 문자열이나 private ORAM verifier key sentinel을 반사하지 않는다.
  - App telemetry와 anonymized app telemetry는 private HNSW ORAM과 private result ORAM `signature_public_keys` registry 원문을 직렬화하지 않고 non-secret runtime capability fingerprint만 내보내며, anonymized telemetry에서는 fingerprint도 제거한다. private ORAM verifier public key sentinel fixture로 회귀를 고정한다.
  - private-ORAM cluster gate는 고정 layout의 수동 `move_shard`/`replicate_shard`, automatic dead-replica recovery, exact active fixed-layout/reshard restart, reserved single-`Active` replica removal, custom shard-key create/non-final drop을 지원한다. Typed scale-up/down resharding은 별도 start/finish Raft operation과 active `ReshardState`에 정확히 대응하는 source-coordinated `ReplicateShard(resharding_stream_records)`만 연다. 이동 경로는 configured HNSW/result index의 동일 consensus reservation 아래 target에 current epoch/root/writeback digest와 전체 encrypted bucket bundle을 설치한 뒤 `private_oram_preinstalled` marker를 제출한다. Existing-owner shard-key 변경은 같은 reservation과 layout CAS만 사용하고, new-owner create는 모든 configured store의 exact live install ACK를 받은 peer 차집합을 typed descriptor에 묶은 뒤에만 layout CAS를 제출한다. 미표시·filtered·wrong-stage·wrong-endpoint·wrong-method transfer/restart, `replicate_points`, snapshot/WAL transfer, final shard-key drop, dead/transitional/batch/final replica removal은 fail closed 한다.
  - replica-state update guard는 private ORAM collection에서 active `MigratingPoints` reshard와 정확히 일치하는 scale-up target `Resharding -> Active` 또는 scale-down receiver `ReshardingScaleDown -> Active`만 허용한다. 그 밖의 resharding transition은 fail closed 하고, unrelated non-resharding state-only transition은 기존 동작을 유지한다.
  - consensus snapshot apply도 private ORAM bucket store collection에서는 exact supported shape와 `private_oram_preinstalled` marker를 가진 transfer state만 허용한다. Unmarked/unsupported transfer, unsupported resharding state, shard layout config 변경, unrelated shard id set/shard-key mapping/replica membership 변경, resharding replica-state 주입은 fail closed 한다. Empty transfer/resharding cleanup state와 non-resharding replica state-only sync는 허용하고, `Dead`/`Partial`/`Initializing`/`Listener`/`PartialSnapshot`/`Recovery`/`ActiveRead`/`ManualRecovery` 상태 적용이 guard에 막히지 않는지 테스트로 고정했다.
  - Storage consensus apply guard 오류도 private HNSW/result ORAM collection id/name, runtime key id, rule id, instance id, binding id, collection-local store directory name 같은 config sentinel을 반사하지 않는지 transfer/resharding/shard-key/replica-remove fixture로 고정한다. Cluster submit guard 오류도 같은 store directory sentinel을 반사하지 않는지 검증한다.
  - Private ORAM resharding/shard-key authorization guard는 consensus submit과 collection-local layout 변경 경계 모두에서 호출자가 넘긴 operation label을 오류에 반사하지 않고 고정 오류만 반환한다.
  - 수동 shard snapshot 생성/stream/download/recovery와 partial snapshot manifest 조회도 private ORAM bucket store collection에서는 fail closed 한다. partial snapshot recovery는 recovery lock 상태를 관찰하기 전에 같은 guard로 먼저 닫는다. guard 오류는 호출자가 넘긴 operation label, private ORAM key id, rule id, instance id, binding id, collection-local store directory name을 반사하지 않는다. 현재 private index는 collection-local `private_hnsw_oram/` 또는 `private_result_oram/` bucket store이므로 shard snapshot만으로는 epoch/root parity를 보존할 수 없다.
  - distributed private ORAM session open/read/commit/close는 Dispatcher consensus coordinator가 있을 때 recovery, per-index hashed lease CAS, all-replica encrypted writeback, digest-bound epoch/root CAS를 거친다. Consensus coordinator가 없는 distributed REST/gRPC fixture와 common direct 호출은 기존 consensus-backed CAS guard에서 계속 fail closed 한다.
  - Raft persistent state에는 private HNSW/result ORAM index identity를 domain-separated digest로 키잉한 internal epoch/root CAS record가 추가됐다. CAS operation은 initial ownership 등록, exact old epoch/root precondition, monotonic epoch, canonical root hash를 검증하고, optional writeback digest로 provider-domain canonical signed commit message 전체의 SHA-256을 새 epoch에 결합한다. 이 digest는 lineage, old/new epoch/root, ordered encrypted bucket hash를 묶되 bucket id와 ciphertext 자체는 Raft에 저장하지 않는다. Initial ownership과 구형 persisted/Raft snapshot state는 digest `None`으로 호환된다. 이미 current state가 digest까지 정확히 requested new state인 동일 old→new replay는 no-op success로 처리하되, 같은 epoch/root라도 digest가 다른 writeback과 다른 new state를 가진 conflicting stale replay는 거부한다. 따라서 consensus apply 직후 응답 전에 중단된 coordinator가 같은 CAS를 안전하게 재제출할 수 있으며, state는 restart와 Raft snapshot apply를 통과한다. Dispatcher에는 local Raft apply 결과까지 기다리는 internal CAS submit/read bridge와 durable local prepare → awaited Raft CAS → idempotent local finalize 순서를 강제하는 internal writeback coordinator가 있다. CAS가 거부되면 coordinator는 abort callback을 호출하고, HNSW/result store abort는 owner-signed journal을 재검증한 뒤 local epoch, old Merkle tree, 모든 target bucket이 old view와 일치할 때만 journal을 삭제한다. 일부 bucket/Merkle/final epoch 반영이 시작된 상태에서는 abort가 journal을 보존하고 fail closed 한다. 실제 Raft loop fixture는 prepare 실패 시 consensus/finalize 미실행, conflicting stale CAS 시 abort 실행/finalize 미실행, consensus apply 뒤 local finalize 실패, 동일 operation retry가 exact CAS no-op을 거쳐 finalize를 다시 수행하는 경로를 검증하며, persistent/raft-snapshot fixture도 exact replay idempotence와 digest mismatch를 포함한 conflicting stale rejection을 고정한다. 이 internal state/coordinator만으로 encrypted bucket ownership/movement가 해결되는 것은 아니므로 distributed manifest/upload/session/read/commit guard는 bucket replication과 API commit 연동이 완료될 때까지 계속 닫혀 있다.
  - HNSW/result collection store는 owner-signed durable journal에서 old/new epoch, encrypted bucket batch, bucket count, commit signature만 담은 replication batch와 canonical consensus transition을 export할 수 있다. Receiver prepare primitive는 manifest-derived fixed writeback budget을 먼저 강제하고, canonical digest가 expected consensus transition과 정확히 일치하는지 journal 생성 전에 확인한 뒤, receiver 자신의 old Merkle tree에서 new tree를 재계산해 durable pending journal을 만든다. Merkle tree 파일은 transport payload로 신뢰하거나 복사하지 않는다. Dispatcher provider-specific CAS builder는 현재 Raft record를 읽어 local transition의 old epoch/root와 대조하고, 이전 writeback digest를 expected state에 그대로 보존하면서 새 digest를 new state에 넣는다. Source/replica fixture는 consensus mismatch가 receiver journal 생성 전에 거부되고 valid encrypted batch가 양쪽에서 같은 transition과 final bucket을 만드는지 검증하며, 연속 Raft writeback fixture는 이전 digest 보존을 고정한다. 아직 peer fan-out/ack, owner assignment, restart recovery orchestration, network transport는 연결되지 않았으므로 distributed API guard는 계속 닫혀 있다.
  - Dispatcher replicated-writeback coordinator는 required replica peer set과 정확히 일치하고 canonical writeback digest가 같은 prepare ACK를 모두 받은 뒤에만 Raft CAS를 제출한다. Remote prepare 실패, missing/duplicate/extra ACK, digest mismatch, CAS rejection은 remote/local abort를 모두 시도한다. Raft apply 뒤에는 remote finalize를 먼저 수행하고 local owner finalize를 마지막에 수행해 remote retry가 필요한 동안 owner journal을 보존한다. ACK Debug와 오류는 digest를 반사하지 않는다. 실제 Raft fixture는 incomplete ACK가 abort 후 consensus를 유지하는 경로와 exact ACK set이 remote-before-local finalize 순서로 다음 digest를 commit하는 경로를 고정한다. Collection-local ORAM store의 v1 peer set은 모든 shard가 동일한 non-empty `Active` replica membership을 가지며 current peer를 포함하고 모든 remote internal address가 알려진 경우에만 Dispatcher가 derive한다. Transitional replica state, shard별 membership 차이, local ownership 누락, unknown remote address는 fan-out 전에 fail closed 한다. HNSW/result receiver finalize/abort primitive는 expected old/new epoch/root와 writeback digest가 owner-signed pending journal의 canonical transition과 정확히 같아야 하며 mismatch 시 journal과 old state를 보존한다. 별도 consensus-backed private-ORAM ownership record와 owner-side ChannelService fan-out 연결은 아직 없으므로 distributed route guard는 계속 닫혀 있다.
  - Internal protobuf에는 HNSW/result index kind, collection identity, exact old/new epoch/root와 canonical digest, typed encrypted bucket batch, owner commit signature를 분리한 private ORAM prepare/completion wire DTO를 추가했다. Opaque JSON payload는 사용하지 않는다. QdrantInternal prepare/finalize/abort RPC는 stable collection identity, runtime binding, manifest/owner signature, fixed writeback budget, bucket hash/commitment, Merkle transition, canonical digest를 receiver에서 재검증하고 node-local service lock으로 journal mutation을 직렬화한다. Finalize/abort는 exact pending transition만 처리한다. Finalize 응답 유실 후 prepare 재시도는 current epoch/root, Merkle tree, 모든 updated encrypted bucket이 signed batch와 정확히 같을 때만 digest ACK를 재전송하고 새 journal을 만들지 않는다. Wire bound 오류는 ciphertext/digest/signing-key를 반사하지 않는다. Owner-side ChannelService fan-out과 multi-peer e2e 전까지 distributed route guard를 유지한다.
  - ChannelService는 단일 peer private ORAM prepare/finalize/abort RPC를 호출하고 transport/server 오류를 peer id만 남기는 고정 메시지로 sanitize한다. Dispatcher provider-specific request builder는 encrypted batch old/new와 canonical transition의 exact match를 serialization 전에 강제한다. High-level HNSW/result coordinator wrapper는 collection shard layout에서 exact remote peer set을 derive하고 prepare를 병렬 전송한 뒤 모든 future를 끝까지 수집하며, exact peer/digest ACK 검증 → Raft CAS → remote-before-local finalize 순서를 기존 coordinator에 연결한다. Abort/finalize fan-out도 한 peer 실패로 다른 peer 호출을 취소하지 않는다. Finalize는 `completed=true`를 요구하고 abort no-op은 idempotent하게 허용한다. Public client commit route 연결과 multi-peer e2e 전까지 distributed route guard를 유지한다.
  - HNSW/result collection store는 persisted current epoch/root가 signed manifest epoch/root와 같은 initial state이고 durable pending writeback이 없을 때만 complete encrypted upload bundle을 export한다. Export는 manifest ORAM tree에서 canonical bucket count를 재계산하고 caller-provided aggregate memory budget을 allocation 전에 강제한 뒤 모든 bucket과 full upload bundle, persisted Merkle leaf set을 다시 검증한다. Writeback으로 epoch가 진행된 store, manifest epoch에 남아 있어도 pending journal이 있는 store, oversized bundle은 initial export와 exact idempotent install에서 root/digest/ciphertext를 반사하지 않고 fail closed 한다.
  - QdrantInternal initial install RPC는 existing typed HNSW/result manifest/signature/bucket protobuf를 provider-discriminated oneof로 전달한다. Receiver는 decode/aggregate bounds, provider kind/oneof/vector convention, stable collection identity, runtime binding, manifest owner signature, full upload bundle을 node-local mutation lock 아래 재검증하고 exact existing bundle만 idempotent success로 인정한다. ChannelService install 오류는 peer id만 남긴다. Dispatcher initial coordinator는 derived remote replica 전체에 병렬 install을 보내고 실패 뒤에도 모든 future를 수집하며, 모든 ACK epoch/root가 expected state와 같을 때만 `expected=None`, digest-free initial ownership CAS를 Raft에 제출한다. CAS 실패 시 validated encrypted bundle은 exact retry를 위해 유지한다.
  - Public REST/gRPC initial manifest route는 Dispatcher consensus state가 있을 때만 coordinator-local staging helper를 사용한다. Complete bucket route는 persisted manifest/current epoch, 전체 canonical bucket set, Merkle leaves를 bounded export로 다시 검증하고 typed initial install을 모든 derived active replica에 fan-out한 뒤 initial ownership CAS가 apply되어야 성공을 반환한다. Consensus coordinator가 없는 distributed TOC와 common upload 직접 호출은 기존 single-node guard에서 계속 fail closed 한다. Manifest staging은 initial CAS 전까지 node-local이므로 client는 manifest와 bucket request를 같은 coordinator node에 보내고 불확정 응답에는 exact signed bundle을 재시도해야 한다. Session/read/writeback route guard는 유지한다.
  - Provider-neutral distributed recovery classifier는 local current state, optional signed pending transition, Raft ownership epoch/root/writeback digest를 비교한다. Pending이 없으면 local과 consensus exact epoch/root만 clean으로 인정하고, pending이 있으면 local+consensus가 old일 때만 abort, consensus가 exact new epoch/root/digest일 때만 finalize를 허용한다. Missing ownership, unrelated state, digest drift, local new/consensus old rollback 상태는 root/digest를 반사하지 않고 fail closed 한다. 다음 단계는 HNSW/result pending journal validation과 remote/local completion fan-out을 이 결정에 연결하는 것이다.
  - HNSW/result recovery context는 runtime/manifest owner/current epoch/signed pending replication batch를 재검증하고 context lifetime 동안 existing upload/session mutation reservation을 유지한다. Internal recovery orchestrator는 Raft classifier 결과에 따라 active replica set 전체에 exact abort/finalize completion을 remote-first로 fan-out한 뒤 같은 transition을 local에 적용한다. Clean initial context inspection은 두 provider route fixture로 고정했다.
  - Signed finalize는 pending journal을 제거하기 전에 canonical epoch commit file에 epoch/root/writeback digest completion record를 durable하게 기록한다. Pending이 없는 finalize replay는 current epoch/root, validated Merkle epoch/root, completion record의 exact digest가 모두 일치할 때만 idempotent success이고, same epoch/root의 conflicting digest는 fail closed 한다. Legacy digest-less commit은 signed pending journal과 최종 bucket/Merkle 상태를 재검증한 crash recovery에서만 exact digest record로 승격한다. Snapshot source/restore preflight는 canonical digest-bearing commit을 허용하지만 `current.json` digest와 malformed digest를 redacted 오류로 거부한다. 이로써 partial remote-finalize recovery 재시도 경계는 해소됐고, 다음 단계는 consensus-backed session ownership과 public commit route 연결이다.
  - Raft persistent/snapshot state에는 epoch map과 분리된 per-index private ORAM session lease map을 추가했다. Lease는 owner peer, opaque lease id의 SHA-256 hash, bounded issued/expires time만 저장하고 index identity는 기존 domain-separated key digest 뒤에 숨긴다. Exact CAS는 initial acquire, same-owner renewal, exact release, `new.issued_at >= old.expires_at`인 deterministic expired takeover만 허용하며 early takeover/stale release/overlong lease/malformed hash를 fail closed 한다. Restart와 Raft snapshot restore, legacy snapshot default, debug/log redaction 테스트를 추가했고 Dispatcher에 awaited apply 및 current lease 조회 bridge를 연결했다. Public session open/renew/close와 replicated commit은 이 lease hash를 사용한다.
  - Resharding용 collection-level private ORAM layout 합의 레코드 기반을 추가했다. Stable collection identity는 별도 domain-separated SHA-256 map key로만 persistent/Raft snapshot에 저장되고, 값은 generation, canonical sorted owner-peer union, shard-layout digest, layout transition 시점의 전체 private ORAM index epoch/root/writeback-completion-set digest를 보존한다. Initial generation 1과 이후 정확한 `+1` CAS만 허용하고 exact replay는 idempotent하며, empty/unsorted/duplicate/oversized owner set과 malformed digest, stale precondition, generation skip을 fail closed 한다. Persistent reload, legacy/new snapshot restore, 실제 single-peer Raft proposal/apply, Dispatcher bridge, raw/redacted Debug 비노출 회귀가 들어갔다. Shard-layout/index-state digest는 각각 별도 domain 아래 stable collection id, sharding mode, sorted shard/typed shard-key/per-shard active owners와 sorted provider kind/name/epoch/root/optional writeback digest를 length-prefixed 및 fixed big-endian encoding으로 묶고 KAT로 고정했다. Replica-removal coordinator는 모든 configured index의 동일한 live consensus reservation을 전후로 재확인하고, record가 없으면 stable pre-layout을 generation 1로 bootstrap한다. 이후 exact lease/current index-state 검증, generation `+1` layout CAS, reserved single-replica metadata 제거, post-layout 검증을 하나의 Raft operation apply 경계로 묶었다. Pure pre/post classifier와 persistent/ConsensusManager replay 테스트는 이미 제거된 topology의 exact replay를 허용하고 shard/owner/digest/lease drift를 redacted fail-closed로 고정한다. 일반 ORAM writeback 뒤 기존 record의 index-state digest가 오래된 것은 허용하되 topology exact match와 새 generation의 current index-state binding을 요구한다. Fixed-layout `stream_records` Move/Replicate도 같은 record를 사용한다. 모든 index reservation 아래 exact current state와 pre/post topology를 capture하고, record가 없으면 generation 1을 bootstrap한 뒤 expected/new layout과 sorted index-state checkpoint를 typed transfer metadata로 영속화한다. 전용 start Raft operation은 exact lease/state를 검증해 marker를 등록하고, 전용 finish operation은 captured state를 재검증해 layout CAS를 먼저 적용한 뒤 target activation/source removal과 post-layout 검증을 수행한다. Start/finish의 pre/post classifier와 CAS는 post-apply 오류 및 exact replay에 안전하고, restart는 metadata를 보존하며 abort는 layout을 진행하지 않는다. Transfer bootstrap 이후 임시 차단은 제거했다. 일반 untyped start/finish apply guard는 유지하고, public cluster route는 검증된 typed private-ORAM reshard operation만 제출한다.
  - Qdrant lease coordinator는 node-local session id를 별도 domain의 SHA-256 hash로 변환하고, absent/expired lease acquire, current owner/hash/expiry 검증, monotonic renewal, exact release를 Dispatcher awaited CAS에 연결한다. Public REST/gRPC open은 recovery와 local session 생성 뒤 consensus epoch/root를 재확인하고 lease 획득 실패 시 local writer를 정리한다. Read와 close는 exact live lease를 요구하고, commit은 write 권한/owner signature/budget 검증으로 local session을 busy 상태에 고정한 뒤에만 lease를 갱신한다. Coordinator가 old consensus에서 실패하면 remote/local journal을 abort하고 busy를 해제하며, exact new epoch/root/digest까지 진행됐으면 remote/local finalize를 재시도한다. 그 외 상태는 fail closed 한다. Oversized lease id, mismatch, recovery 오류는 session id/root/digest를 반사하지 않는다.
  - 실제 single-peer Raft proposal/apply 루프를 사용하는 HNSW/result ORAM 통합 테스트는 분산 create가 생성한 stable collection UUID로 client key/bucket/manifest를 다시 바인딩한 뒤 각 index의 initial ownership CAS, session lease acquire, signed fixed-path read, digest-bound commit, consensus epoch 확인, close lease release를 순서대로 검증한다. Dispatcher의 별도 replicated-writeback fixture가 exact remote ACK set과 remote-before-local finalize를 검증한다.
  - 실제 2-peer Qdrant process E2E는 SDK primitive로 생성한 context-bound encrypted fixture를 public REST route에 업로드하고, HNSW/result ORAM 각각 session open, owner-signed fixed-volume read, replicated digest-bound commit, close를 수행한 뒤 다른 replica에서 committed epoch session을 재개방한다. 별도 RF=1 process E2E는 source에서 두 store를 epoch 43으로 진행한 뒤 public `ReplicateShard(stream_records)`와 `MoveShard(stream_records)`를 각각 호출해 live bundle preinstall, marked target `SyncPoints`, shard activation을 완료하고 target에서 두 committed session을 재개방한다. 각 테스트는 source/target local shard ownership도 최종 operation 의미와 일치하는지 검증한다. Partial-preinstall E2E는 target result ORAM current state를 malformed로 만들어 HNSW install 뒤 result install만 실패시키고, transfer 미등록, 오류 root/signature/ciphertext redaction, source reservation 해제, malformed target 제거 뒤 exact idempotent retry 성공을 검증한다. Post-submit abort E2E는 staging transfer delay로 marked transfer를 active 상태에 유지하고 source session 차단을 확인한 뒤 abort한다. Abort가 transfer marker를 제거하고 target replica를 `Dead`로 남기며 preinstalled encrypted stores를 보존하는지, source session이 즉시 재개방되는지, 동일 ReplicateShard exact retry가 target activation과 session 재개방까지 완료하는지를 검증한다. Exact restart E2E는 같은 marked transfer가 active인 동안 target의 HNSW/result store를 제거하고 source에서 same-key `RestartTransfer(stream_records)`를 호출해 fresh reservation 기반 full-store reinstall, replacement marker의 session 차단, target activation과 두 committed session 재개방을 검증한다. Runtime capability fingerprint는 중첩 JSON object key를 canonical sort해 같은 설정을 읽은 별도 process가 map insertion order 때문에 parity mismatch를 내지 않도록 고정했다. 3-peer/RF=3 장애 E2E는 HNSW/result ORAM 각각 비리더 replica를 prepare 직전에 종료하고 commit이 fail closed 되는지, 오류가 session/root/signature/ciphertext를 반사하지 않는지, 기존 signed read와 old epoch session 재개방이 유지되는지를 검증한다. 3-peer/RF=2 partial-finalize E2E는 remote bucket finalize만 filesystem permission으로 실패시켜 Raft CAS 이후 owner/replica journal이 남은 상태를 만들고, coordinator process 재시작 뒤 remote-first/local finalize와 completed pending recovery 뒤 current-peer orphan consensus lease의 즉시 exact release를 거쳐 epoch 43 session을 재개방한다. Opt-in 2-peer large-bundle E2E는 tree height 5의 63-bucket HNSW/result store와 각각 10.504/5.254 MiB base64 ciphertext fields를 epoch 43까지 진행해 ReplicateShard target에서 session을 재개방한다. 별도 3-peer/2-shard/RF=1 owner-union E2E는 initial upload와 epoch-43 writeback이 서로 다른 두 shard owner에만 복제되는지 확인하고, non-owner target으로 한 shard를 ReplicateShard한 뒤 두 private ORAM session을 재개방한다. 3-peer/2-shard/RF=2 automatic recovery E2E는 비리더 target을 중단하고 일반 point write로 replica를 `Dead` 처리한 뒤 target의 HNSW ORAM store를 제거하고 같은 peer로 재시작한다. Target의 background recovery request, source-side signed full-store preinstall, marked per-shard transfer를 거쳐 replica들이 다시 `Active`가 되고 committed epoch 43 session이 target에서 재개방되는지 검증한다. 추가 2-peer HNSW-only 및 HNSW+result process E2E는 public typed scale-up과 scale-down을 각각 실행해 active reshard 동안 session이 닫히고, exact `resharding_stream_records` migration 뒤 layout generation 2와 최종 owner union이 모든 peer에 남으며, committed epoch session과 일반 point retrieval이 유지되는지 검증한다. 별도 source hard-crash E2E는 marked scale-up migration 중 source process를 종료하고 target 두 encrypted store를 제거한 뒤, target의 bounded internal resume request가 재기동 source에서 exact state/task 부재를 검증하고 fresh full-store preinstall과 same-key restart를 자동 수행하는지 검증한다. 추가 3-peer scale-up E2E는 stable pre-state follower가 compacted Raft snapshot으로 active topology를 복원하고 target shard 생성과 정상 finish까지 진행하는지 검증하며, 4-peer/RF=3 scale-down E2E는 같은 active reshard snapshot의 replay와 final owner session 재개방을 검증한다. Fixed-layout multi-shard ownership, exact restart, scale-up/down, paired result-ORAM reshard, source hard-crash automatic recovery, bounded existing-peer active-reshard Raft snapshot recovery, topology-only non-owner 및 exact scale-up target new-peer snapshot bootstrap 공백은 닫혔다. 신규 3-peer bootstrap E2E는 빈 비소유 피어가 local shard/store 없이 remote topology를 복원하는 경로와, encrypted store 및 point shard가 삭제된 exact `MigratingPoints` scale-up target이 snapshot apply 뒤 source 재기동을 통해 full-store preinstall과 same-key migration을 자동 재개하는 경로를 각각 검증한다. Fixed-layout active transfer snapshot은 exact ordered index checkpoint, signed pre/post transition, pre-layout consensus를 별도로 검증하며, collection이 없는 peer는 owner/replica/source/target 어디에도 속하지 않는 topology-only 역할일 때만 mutation 전에 통과한다. Pre-layout owner, transfer source/target, scale-down endpoint, already-active target snapshot bootstrap은 계속 fail closed 한다.
  - 2026-07-29 snapshot recovery E2E는 위 초기 경계를 확장했다. Fixed-layout checkpoint의 전환 증거는 owner signature가 아니라 exact consensus-bound pre/post layout이다. Pre-layout owner가 아니고 다른 pre-layout shard를 소유하지 않는 fresh active-transfer target은 collection 전체 또는 모든 configured store가 함께 삭제된 경우 exact resume marker와 source fresh-preinstall로 복구한다. 일부 store만 삭제된 target은 계속 거부한다. 모든 로컬 shard에 대체 `Active` replica가 있는 fixed-transfer source/owner는 exact transfer abort 뒤 복구한다. Transfer-complete scale-down endpoint도 같은 redundancy 조건으로 단일·다중 shard를 복구하며, RF=1 endpoint는 collection 생성 전 거부되고 root/signature/ciphertext를 로그에 남기지 않는다.
  - Scale-up/down process E2E는 후속으로 HNSW-only와 paired HNSW+result 구성을 각각 실행하도록 매개변수화했다. Paired case는 두 index를 epoch 43까지 commit한 뒤 active reshard 동안 HNSW/result session이 모두 닫히는지, exact `resharding_stream_records` migration과 layout generation 2 이후 모든 final owner에서 두 root가 재개방되는지, 두 encrypted bucket store가 남는지 검증한다. Reshard batch가 사용하는 `UpsertPoints`는 exact marked active reshard transfer에만 blanket guard를 통과하며, 이후 per-field peer validation은 private HNSW vector와 private-result payload path를 계속 거부한다. HNSW-only case는 일반 point record 보존 검증을 유지한다.
  - Exact active reshard restart는 유일한 marked `resharding_stream_records` transfer의 key, source/target shard, peers, method와 `MigratingPoints` state가 모두 일치할 때만 source coordinator에서 허용한다. Fresh consensus reservation으로 target의 HNSW/result full store를 먼저 재설치하고, Raft apply는 old transfer task만 중단해 active reshard를 보존한 채 `to_shard_id`와 marker를 유지한 replacement transfer를 시작한다. 2-peer scale-up process E2E는 active migration 중 target의 두 store를 제거한 뒤 exact restart로 재설치하고, session 차단, 정상 reshard finish, layout generation 2와 두 committed session 재개방을 검증한다. Staging transfer delay는 `stream_records`와 `resharding_stream_records` 양쪽 batch에 같은 테스트 전용 cfg로 적용된다.
  - Fixed-layout transfer E2E는 모든 peer의 persisted private ORAM layout record도 직접 확인한다. 정상 Replicate/Move 완료는 generation 2와 최종 owner union을 요구하고, post-submit abort는 generation 1/pre-owner를 유지한 뒤 exact `Dead` target만 pre-layout에서 제외하는 동일 transfer retry로 generation 2까지 진행해야 한다. Exact restart는 active replacement 전후 generation 1을 유지하고 최종 activation에서 generation 2/두 owner로 진행해야 한다. 별도 3-peer/RF=3 E2E는 replica 제거로 existing layout을 generation 2로 만든 뒤 제거된 peer에 `ReplicateShard(stream_records)`를 수행해 generation 3과 전체 owner union, target HNSW/result session 재개방을 검증한다.
  - 별도 2-peer/RF=2 replica-removal E2E는 active HNSW session이 consensus reservation을 막는지, close 뒤 exact single remove가 성공하는지, 제거 peer에 ciphertext store가 남아도 HNSW/result session이 모두 거부되는지, 남은 owner에서는 committed session이 계속 열리는지를 검증한다.
  - HNSW/result collection store에는 signed manifest lineage와 현재 epoch/root/consensus writeback digest, 전체 encrypted bucket set을 묶는 live-replication bundle export/install primitive가 추가됐다. Export는 pending journal을 거부하고 mixed bucket epoch를 current 이하로 제한하며 각 bucket commitment와 persisted Merkle tree를 재검증한다. 따라서 manifest가 live epoch로 refresh된 뒤에도 untouched old-epoch bucket을 안전하게 이동할 수 있다. Install은 owner manifest signature와 expected Raft epoch/root/digest를 exact-match로 확인하고 전체 commitment에서 Merkle root를 재계산한 뒤 completion record와 `current.json`을 마지막에 기록한다. Exact existing store 재설치는 idempotent하고 다른 current state 교체는 fail closed 한다. Store fixture는 writeback으로 epoch 43까지 진행한 HNSW/result index를 빈 replica에 설치하고 untouched old-epoch bucket과 updated bucket이 같은 current root를 구성하는지 고정한다. Initial/live peer install은 최대 512 MiB의 완성된 typed protobuf request를 결정적인 1 MiB 이하 프레임으로 나눠 client-streaming internal RPC로 전송한다. Receiver는 frame version, exact sequence/count, aggregate length, request SHA-256을 bounded decoder에서 검증하고 완전한 request만 기존 install validator에 넘긴다. Chunked full-store receiver permit은 하나이며 atomic install 완료까지 유지되고, 30초 inter-frame idle timeout과 5분 permit-wait/전체-decode timeout을 적용하므로 partial/reordered/stalled/corrupt stream은 mutation 전 fail-closed되고 aggregate decode buffer가 여러 개 누적되지 않는다. Full-store install은 전용 5분 internal RPC deadline과 1회 retry를 사용하고, receiver의 signature/full-store hash/filesystem/fsync 작업은 blocking worker에서 수행해 Tokio health check와 Raft heartbeat를 막지 않는다.
  - 별도 typed `InstallPrivateOramLiveReplica` internal RPC와 ChannelService source transport가 HNSW/result live bundle에 연결됐다. Receiver는 wire aggregate bound, local Raft ownership epoch/root/digest exact match를 확인하고, active consensus lease가 있으면 shard-transfer coordinator가 보낸 canonical reservation hash와 정확히 일치할 때만 node-local private-ORAM mutation lock 아래 provider signature/full-store install을 수행한다. Target의 local Raft apply가 source보다 늦을 수 있으므로 receiver는 exact reservation의 적용만 bounded-wait하고, 누락되거나 다른 reservation은 그대로 거부한다. Source helper도 export 결과와 local Raft record를 대조하고 target ACK의 epoch/root/digest exact match를 요구하며 transport/ACK 오류는 peer id 외 root/digest/ciphertext를 반사하지 않는다. Public cluster update는 지원되는 fixed-layout per-shard Move/Replicate에서 이 helper를 호출해 preinstall ACK 뒤 marked transfer를 제출한다.
  - Automatic dead-replica recovery는 typed `RequestPrivateOramShardRecovery` internal RPC로 source peer에 위임한다. Target scheduler는 collection sync lock 밖의 background task에서 요청해 source의 reservation proposal이 target에 apply될 수 있게 하고, shard별 pending set으로 중복 요청을 합친다. Source는 configured shard count와 실제 fixed layout의 일치, local source `Active`, target `Dead`, no resharding/competing transfer를 검증하며, exact marked retry는 idempotent하게 인정하고 그 외에는 full-store preinstall 뒤 marked `ReplicateShard(stream_records)`를 제출한다.
  - Resharding layout foundation은 stable pre-layout과 `ReshardKey`에서 scale-up/scale-down 이후 canonical shard-layout digest와 owner union을 계산하는 fail-closed helper로 시작했다. Scale-up의 기존 shard id 재사용, scale-down의 missing shard/wrong owner/shard-key mismatch, 마지막 auto shard 또는 custom shard-key의 마지막 shard 제거는 거부한다. `PrivateOramReshardingLayoutTransition`은 exact reshard key, expected/new generation과 digest, target shard owner set, index epoch/root/writeback state를 묶고 scale-up/down pre/post topology를 replay-safe하게 분류하며 Debug에서는 collection/index/root/shard-key를 redaction한다. Persistent validator는 typed start/finish envelope의 모든 index에 동일한 exact consensus lease가 잡혀 있고 canonical 순서의 epoch/root/writeback state와 layout index-state digest가 현재 Raft state에 일치하는지 검증한다. Start는 expected layout에서만, finish는 expected 또는 idempotently applied new layout에서만 허용된다. 전용 `StartPrivateOramResharding`/`FinishPrivateOramResharding` Raft operation과 collection topology classifier도 연결되어 start는 layout을 바꾸지 않고 reshard meta만 적용하며, finish는 layout generation CAS 뒤 meta를 적용하고 두 단계 모두 post-apply failure에서 idempotent하게 replay된다. Scale-up target의 `Resharding` transitional replica와 scale-down의 `ReshardingScaleDown` owner는 start replay에서만 제한적으로 인정하며 finish 전에는 모든 replica와 hash-ring stage가 finalizable 상태여야 한다. Start coordinator는 fully-active stable layout에서 모든 index의 동일 reservation을 잡고 exact expected/new transition을 생성하며, scale-up은 기존 live-replica RPC로 target full-store를 먼저 설치하고 scale-down은 existing owner recovery를 완료한다. Finish coordinator는 `WriteHashRingCommitted` 상태와 exact reshard key, fully-active replica topology를 요구하고 모든 index를 다시 예약한다. Scale-up은 target full-store를 idempotently 재설치하며 self-target은 로컬 recovery로 검증하고, scale-down은 surviving coordinator의 로컬 recovery를 마친 뒤 pre/post layout과 generation CAS를 생성한다. 두 coordinator 모두 reshard 전후 owner union에 남아야 한다. Public cluster start/finish는 이 typed coordinator에 연결됐으며 일반 untyped meta-op은 계속 거부된다.
  - Typed private-ORAM resharding apply authority는 persistent lease/layout/index-state 검증과 topology classification을 통과한 `PrivateOramReshardingOperation`만 전용 `CollectionContainer` 경로로 전달한다. 실제 collection mutation은 private ORAM binding을 다시 확인하는 start/finish 메서드로 분리했고, 일반 `CollectionMetaOperations::Resharding(Start/Finish)`는 TOC와 collection 양쪽의 기존 guard에서 계속 거부된다. Typed authority는 commit/abort나 일반 collection에는 사용할 수 없도록 단위 테스트로 고정했다.
  - Private ORAM resharding의 중간 단계는 ORAM layout을 바꾸지 않는 exact transition만 허용한다. `CommitRead`/`CommitWrite`는 collection의 active reshard key와 stage 검사를 그대로 거치며, replica promotion은 `MigratingPoints`에서 scale-up exact target의 `Resharding -> Active` 또는 같은 shard-key scale-down receiver의 `ReshardingScaleDown -> Active`만 허용한다. Point migration transfer는 source coordinator가 active reshard key, same shard key, source/destination replica state, `sync=true`, no filter, no layout transition, `ReshardingStreamRecords`를 모두 만족할 때만 전체 ORAM store를 preinstall하고 marker를 붙인다. Wrong peer/shard/stage/current-state와 그 밖의 transitional state 변경은 collection 계층에서 fail closed다. Active resharding이나 shard transfer가 하나라도 있으면 새 HNSW/result ORAM session coordinator를 거부하므로 start부터 finish까지 consensus epoch/root와 layout index-state digest가 고정된다.
  - Phase G의 현재 gate는 다음과 같다. Dispatcher consensus state와 모든 shard가 fully active인 고정 layout의 owner-peer union이 있는 REST/gRPC 경로에서는 initial upload와 session open/read/commit/close가 열려 있다. 각 shard의 수동 `stream_records` Move/Replicate, source-coordinated automatic dead-replica recovery, 남는 owner/replica를 보장하는 reserved exact single-`Active` replica removal, typed scale-up/down start/progress/finish, exact marked `resharding_stream_records` point migration과 same-method active restart가 열려 있다. Empty custom collection의 최초 shard key는 store 생성 전 `Active` bootstrap으로 허용한다. 그 뒤 create는 existing-owner placement를 바로 layout CAS에 묶고, 새 owner placement는 모든 configured HNSW/result store를 동일 reservation 아래 먼저 설치한 뒤 canonical new-owner 차집합 marker와 typed layout CAS로 묶는다. Drop은 coordinator를 포함한 non-empty post-layout만 허용한다. Exact marked active reshard의 source restart는 transfer/reshard를 보존하고, target이 source에 bounded internal resume request를 보내면 source가 exact active state와 missing task를 재검증한 뒤 fresh preinstall과 same-key restart를 자동 수행한다. Existing-peer active-reshard Raft snapshot topology apply는 stable crypto identity, configured index epoch/root, canonical pre-layout, exact reshard key, monotonic stage/replica state를 모두 검증한 bounded 경로에서만 열린다. 컬렉션이 없는 신규 피어는 local consensus map이 empty/exact인 상태에서 topology-only non-owner이거나, pre-layout owner가 아니면서 `MigratingPoints`의 sole `Resharding` replica 및 sole exact marked incoming transfer target인 scale-up peer일 때만 bootstrap할 수 있다. 후자는 store 없이 topology를 만든 뒤 session을 차단하고 target-triggered resume로 모든 configured store와 migration을 복원한다. Consensus coordinator가 없는 distributed TOC, unsupported/unmarked/method-changing transfer restart, pre-layout owner/transfer source/scale-down endpoint/already-active target snapshot bootstrap, `Partial` shard-key create, final shard-key drop, dead/transitional/batch/final replica removal은 계속 fail closed 한다. 위의 “distributed route guard 유지” 문구들은 각 하위 primitive 구현 당시의 단계 기록이며 이 현재 gate가 최종 상태를 정의한다.
  - Private HNSW/result ORAM active-session epoch/root mismatch guard는 `read_paths`/`read_buckets`/`commit` 같은 operation label을 오류에 반사하지 않고 고정 active-session mismatch 메시지만 반환한다.
  - Private HNSW/result ORAM initial upload epoch mismatch guard는 store helper에 전달되는 `upload bundle` operation label을 오류에 반사하지 않고 고정 initial-epoch mismatch 메시지만 반환한다.
  - Private HNSW ORAM initial upload bucket commitment context guard는 `initial upload` operation label을 오류에 반사하지 않고 고정 bucket commitment mismatch 메시지만 반환한다.
  - Private result ORAM ordinary payload read guards는 retrieve/search/query/group lookup 같은 operation label을 오류에 반사하지 않고 고정 payload-read mismatch 메시지만 반환한다.
  - Private result ORAM payload selector overlap guards는 filter/order/group/facet/index/formula 같은 operation label을 오류에 반사하지 않고 고정 selector-overlap 메시지만 반환한다.
  - Private result ORAM payload write guards는 upsert/set/overwrite/delete/clear 같은 operation label을 오류에 반사하지 않고 고정 payload-write mismatch 메시지만 반환한다.
  - Private HNSW ORAM read-only vector write guards는 delete/sync 같은 operation label을 오류에 반사하지 않고 고정 read-only vector write 메시지만 반환한다.
  - Private HNSW ORAM point-level vector read guards는 retrieve/scroll 같은 operation label을 오류에 반사하지 않고 고정 point-level vector read 메시지만 반환한다.
  - Collection-level private HNSW ORAM fail-closed integration helper도 retrieve/scroll/search/query/recommend/discover/delete/sync/upsert/update-vectors 같은 ordinary operation label을 공통으로 금지한다.

테스트:

- runtime strict mode에서 private HNSW/result ORAM provider는 허용되고 server materials/backend, unsupported top-level/nested options, non-client-led search, loose fixed budget, unpinned RK id/epoch은 거부된다. unsupported option 값 자체는 validation error에 반사되지 않는다.
- runtime과 signed manifest는 `oram.path_batch_size`가 Path ORAM leaf count를 넘거나 `fixed_budget.paths_per_round`와 다르면 duplicate-label-free `read_paths` budget을 만들 수 없으므로 fail closed 한다.
- SDK Path ORAM leaf/bucket helper도 HNSW와 result ORAM 모두에서 `tree_height = 0` degenerate tree를 거부해 manifest/runtime validation과 같은 하한을 유지한다.
- runtime은 현재 MVP의 bounded JSON Merkle metadata store가 감당할 수 있는 범위로 private HNSW/result ORAM `tree_height`를 20 이하로 제한해, 지원 불가능한 대형 tree가 manifest/session/restore 경계까지 내려가지 않게 한다.
- runtime은 `path_batch_size * (tree_height + 1)`와 fixed bucket ciphertext size에서 계산한 단일 fixed ORAM read batch decoded ciphertext 총량도 제한해, 과도한 `read_paths`/`read_buckets` 응답을 만드는 private HNSW/result ORAM 정책을 거부한다.
- runtime과 signed manifest는 `dim`, `hnsw.fixed_neighbor_slots`, `oram.block_size_bytes` 조합이 fixed-size f32 node block을 담을 수 없는 경우도 fail closed 한다.
- manifest upload는 `hnsw`, `oram`, `fixed_budget` signed policy가 runtime instance policy와 다르면 fail closed 한다.
- collection config와 runtime validation은 `private-hnsw-oram/v1` binding과 rule당 단일 vector name만 허용하고, 같은 vector name에 대한 다른 vector binding overlap, provider/binding mismatch, vector dim/distance와 runtime options mismatch를 거부한다.
- private HNSW ORAM collection config, manifest, read/commit signature context는 vector name을 collection-local store path component로도 안전한 형태로 제한해 `/`, `:`, `.`, `..`, 128바이트 초과 이름이 bucket-store path construction까지 내려가지 않게 한다.
- normal `upsert`/`update_vectors` plaintext write, `delete_points`, `delete_vectors`, server-side search/scoring은 private ORAM session API 안내 메시지로 fail closed 된다. 실제 `do_upsert_points`/`do_update_vectors`/`do_delete_points`, runtime settings가 없는 vector write fallback, inference-derived vector write, collection peer/internal write guard, peer `SyncPoints`, `delete_vectors` point/filter targets, legacy search/batch search, root `do_query_points`, universal query prefetch/fusion/context/MMR, `lookup_from`/point-id reference-vector resolution, recommend/discover, grouped search/query, 그리고 search matrix 경계도 같은 fail-closed 메시지로 고정했다.
- private HNSW ORAM vector에 대한 `retrieve`/`scroll` `with_vector` 요청은 CKKS sidecar payload 안내가 아니라 private HNSW ORAM session API 안내로 fail closed 된다.
- REST payload export의 `with_vector` 거절 메시지는 private HNSW ORAM 사용자를 일반 read API로 안내하지 않고 provider-appropriate vector read/private session API만 안내한다.
- private HNSW/result ORAM gRPC telemetry wrapper는 collection label만 붙이고 vector name, session id, path label, bucket id/root hash sentinel을 telemetry extension으로 복사하지 않는 회귀 테스트를 둔다.
- REST close-session path의 session id 길이/문자 검증은 actix path validator가 아니라 공통 private ORAM session validator를 타게 해서 129/257바이트 oversized sentinel과 malformed id 모두 redacted `session_id is invalid` 오류로 고정한다.
- Common/gRPC read fixtures는 private HNSW ORAM collection에서도 vector를 요청하지 않는 허용 경로를 열어 두어, no-vector retrieve/scroll 요청이 private HNSW session을 요구하지 않는지도 고정한다.
- runtime crypto settings가 없는 ordinary query/search/recommend/discover/group/search-matrix fallback도 private HNSW ORAM vector에서는 CKKS/OpenFHE runtime 안내가 아니라 private HNSW ORAM session API 안내로 fail closed 된다.
- collection 내부 direct query/search/search-matrix entrypoint도 `private-hnsw-oram/v1` binding을 CKKS sidecar runtime 안내와 구분해 private HNSW ORAM session API 안내로 fail closed 한다.
- private ORAM bucket store는 missing canonical layout을 `NotFound`로 fail-closed 처리하고, directory chmod 전에 symlink/type을 검사하며, symlink bucket과 Unix group/world-accessible bucket directory/file을 fail-closed로 거부한다.
- private ORAM initial epoch upload는 같은 epoch/root 재업로드만 idempotent하게 허용하고, mismatched manifest epoch/root 재업로드는 기존 `current.json`을 덮지 않고 fail closed 한다.
- initial signed manifest upload는 manifest/signature write가 성공한 뒤에만 initial `current.json`을 publish하므로, manifest write 실패가 current epoch만 남기는 부분 상태를 만들지 않는다.
- current epoch/root와 stored manifest가 이미 일치하는 manifest 재업로드는 byte-identical no-op만 허용하고, commit 후 `current.json`이 stored manifest보다 앞선 refresh window에서는 새 signed manifest upload를 허용한다.
- crash window에서 bucket/Merkle writeback이 epoch CAS보다 먼저 보이더라도 old current epoch와 new bucket/root를 섞어 serving하지 않고 fail closed 한다.
- collection snapshot은 client-sealed private HNSW bucket ciphertext를 포함하되 private ORAM snapshot source root/nested symlink, client-owned ORAM state files, non-empty temp write state, bucket plaintext sentinel bytes를 archive에 허용하지 않고, empty temp subtree도 archive에서 제외한다. Client-owned state detection은 snake_case/camelCase/kebab-case/dot-separated alias를 포함한다. Restore preflight는 result privacy, collection/vector context, vector dim/distance, manifest signature key id, Path ORAM tree_height/bucket_count mismatch, current epoch/root, manifest-derived fixed bucket ciphertext size mismatch, collection/vector/key lineage에 묶이지 않은 bucket commitment, bucket commitments로 재계산한 manifest root mismatch, manifest bucket range 전체의 bucket presence mismatch, bucket symlink, weak bucket file mode를 fail-closed로 거부한다.
- REST/gRPC ORAM commit fixture는 non-increasing new_epoch, invalid Ed25519 commit signature, successful commit 이후 stale old_epoch replay를 모두 fail-closed로 검증한다. Read path와 commit path는 bucket read 또는 bucket/Merkle writeback 전에 store current epoch/root도 active session의 epoch/root와 일치하는지 preflight한다.
- REST/gRPC ORAM bucket upload/commit path는 encoded bucket ciphertext 길이를 decode 전에 제한하고, decoded bucket ciphertext 길이가 manifest의 `oram.bucket_size`와 `oram.block_size_bytes`에서 계산한 fixed bucket ciphertext 크기와 정확히 일치하는지 확인한다. commit path는 updated bucket writeback도 bucket `ciphertext_sha256`와 collection/vector/key lineage/bucket epoch context에 묶인 commitment인지 Merkle prepare/write 전에 검증한다.
- REST/gRPC ORAM session fixture는 strict mode `fixed_budget=false`, non-current desired epoch, result privacy mismatch를 session open에서 거부한다.
- REST/gRPC manifest upload fixture는 route settings가 `private_payload_oram_required` runtime mode로 drift되면 collection-level result ORAM binding requirement 또는 HNSW manifest policy에서 fail closed 되는지 검증한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 두 번째 session open을 `ConcurrentWriter`로 거부한다.
- session open은 registry에 active session을 등록한 뒤 stored manifest/signature/current epoch가 open 중 바뀌지 않았는지 다시 확인하고, drift가 있으면 방금 연 session을 닫은 뒤 fail closed 한다. Private HNSW ORAM과 private result ORAM common tests 모두 epoch drift, manifest drift, missing Merkle metadata, and missing bucket files를 sanitized error로 고정한다.
- REST/gRPC session open은 signed manifest/current epoch만 있고 encrypted bucket/Merkle upload가 아직 완료되지 않은 상태도 fail closed 한다.
- session registry는 lease가 만료된 session을 제거하면서 같은 private index의 single-writer lock도 해제하고, 만료된 session id 재사용은 read/commit/close 모두에서 fail closed 한다.
- session registry는 failed session action이나 wrong collection/vector close 요청 이후에도 active session과 single-writer lock을 보존한다. private HNSW와 private result ORAM 모두 잘못된 close가 session id를 제거하거나 writer lock을 고아 상태로 남기지 않는지 회귀 테스트로 고정했고, registry guard 오류가 session id, client id, key id, root hash, collection-local path sentinel을 반사하지 않는지도 검증한다.
- REST/gRPC ORAM session fixture는 active session이 있는 같은 private index에 대해 signed manifest upload와 initial encrypted bucket upload도 거부하고, active-session upload guard 오류가 session id, root hash, bucket ciphertext를 반사하지 않는지 검증한다.
- session registry는 signed manifest upload와 initial encrypted bucket upload가 write window를 잡는 동안 같은 private index의 새 session open과 중복 upload도 거부한다.
- collection snapshot guard는 private HNSW 또는 private result ORAM manifest/bucket upload write window가 열린 collection에서도 fail closed 한다.
- collection snapshot recovery도 기존 private ORAM collection의 active session/upload window와 동시에 진행되지 않도록 recovery 시작 전에 같은 guard를 잡고, guard 오류는 manifest root/signature/binding 값을 반사하지 않는다.
- collection update/delete도 private ORAM lifecycle guard를 잡아 active session/upload/snapshot window가 있는 collection 설정 변경이나 삭제를 fail closed 하고, update/delete 중 새 private ORAM session/upload 또는 collection/full snapshot이 열리지 않게 한다.
- REST/gRPC ORAM session fixture는 active private HNSW ORAM session이 있는 collection의 collection/full snapshot 생성도 거부하고, collection/full snapshot guard가 잡힌 동안 새 session open과 manifest/bucket upload도 거부한다. 오류는 session id, root hash, bucket ciphertext sentinel, collection-local `private_hnsw_oram` path를 반사하지 않는지 검증한다. Registry-level active-session/upload/snapshot guards는 collection id suffix/prefix 또는 다른 vector upload와 충돌 없이 exact collection/vector index marker만 막는지도 회귀 테스트로 고정한다.
- REST/gRPC private result ORAM live fixture도 collection/full snapshot guard가 잡힌 동안 session open, manifest upload, bucket upload를 거부하고, active result ORAM session이 있는 collection의 collection/full snapshot 생성도 거부한다. 오류는 session id, result root hash, bucket ciphertext, collection-local `private_result_oram` path를 반사하지 않는지 검증한다. Registry-level upload/snapshot guards는 collection id suffix/prefix 충돌 없이 exact collection marker만 막는지도 회귀 테스트로 고정한다.
- REST/gRPC snapshot route fixture는 collection/full snapshot creation과 active lifecycle window 및 active private HNSW/result ORAM session의 상호배제, shard snapshot list/create/stream/download/delete/recover, partial snapshot manifest, partial recover_from route가 private ORAM bucket store collection에서 fail closed 되는지도 고정한다. REST collection recovery route fixture는 active private ORAM snapshot/upload window 및 active private HNSW/result ORAM session과 recovery의 상호배제를 고정한다. 오류는 submitted snapshot location, operation label, root hash, bucket ciphertext, collection-local private ORAM store path를 반사하지 않는다.
- SDK/client state, upload bundles, REST/common wire DTO, canonical signature input/context, bucket validation context, AEAD/commitment context, verifier public key, collection-local private ORAM store의 Rust `Debug` surface도 session id, root hash, decoded epoch root hash, path label, bucket id, ORAM epoch, ciphertext length/body, signature key id/body, RK id, client position/stash, client ORAM tree/ciphertext sizing config, manifest-build HNSW/ORAM/fixed-budget policy internals, node deleted/generation/token-presence state, build-point vector length, upload/build/batch/proof/read-signature/store-Merkle bucket counts, search access metrics, common session bucket/tree/path-batch/ciphertext-budget values and embedded manifests, payload bytes, collection-local filesystem path를 반사하지 않도록 수동 redaction으로 바꿨고, qdrant-sec/qdrant/collection unit tests가 client-state/client-states, position-map, stash, ciphertext/hash/sha256 alias family의 sentinel leak absence를 검증한다.
- collection snapshot 생성은 archive 작성 전에 private HNSW ORAM manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- collection snapshot 생성은 private result ORAM store도 archive 작성 전에 manifest/current epoch/bucket/Merkle restore-layout parity를 preflight하고, configured binding 없는 orphan store나 누락 bucket 같은 layout 오류를 collection-local path나 root hash 반사 없이 fail closed 한다.
- private HNSW ORAM과 private result ORAM restore preflight는 manifest bucket range 전체를 검사하며 first/middle/last bucket 누락과 storage-level restore 경로를 bucket filename, collection-local path, root hash, signature/ciphertext-like base64url token 반사 없이 fail closed 한다.
- private ORAM snapshot source preflight와 archive append도 canonical store layout 외 파일을 거부한다. restore preflight는 추가 bucket/layout 파일, malformed current/epoch commit file, missing temp directory archive 형태를 회귀 테스트로 고정했고, current/epoch commit file은 bounded JSON epoch/root shape와 canonical root hash를 요구하며 commit file은 filename epoch 일치도 요구한다.
- REST/gRPC ORAM session fixture는 writeback commit 이후 manifest 재업로드 없이 새 epoch session을 열고 그 live epoch/root로 `read_paths`/`read_buckets`를 수행할 수 있으며, closed session id는 `read_paths`와 `commit`에 재사용할 수 없음을 검증한다.
- REST/gRPC `read_paths`와 `commit` 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC session close 오류 응답은 unknown session id sentinel을 반사하지 않는다.
- REST/gRPC `read_paths`, `commit`, `close`는 oversized/malformed session id를 registry lookup 전에 거부하고 submitted session id를 반사하지 않는다. well-shaped unknown session id는 기존 missing/expired-session 오류로 fail closed 된다.
- REST access log와 JSON/path validation boundary도 private ORAM 경로를 별도 sanitize한다. Access log는 session id, read path label, bucket/manifest/read/commit tail, private ORAM query string을 redaction하고 exact marker lookalike는 일반 경로로 유지한다. Marker detection is segment-position aware (`/collections/{collection}/private-hnsw...` or `/private-result-oram...` only), so ordinary collections named `private-hnsw` or `private-result-oram` do not get private-ORAM log/query/body-error handling. Private ORAM JSON body validation/deserialization 오류는 unknown field와 malformed body sentinel을 반사하지 않으며, REST path parameter validation도 vector/session-like path segment sentinel을 반사하지 않는다. gRPC route parameter validation도 oversized collection/vector 값과 malformed private ORAM collection-name sentinel을 오류 메시지에 넣지 않는다.
- REST/gRPC private HNSW/result ORAM route의 missing-encryption guard도 collection name을 반사하지 않는 고정 메시지로 fail closed 한다.
- REST/gRPC bucket upload, `read_paths`, `commit`은 submitted root hash를 canonical 32-byte base64url shape로 먼저 검증하고 malformed root hash를 registry/storage epoch 비교 전에 값 반사 없이 거부한다.
- REST/gRPC `read_paths`, `commit` client signature는 fixed 64-byte Ed25519 base64url 길이를 decode/verification 전에 검증하고 oversized/malformed signature body를 반사하지 않는다.
- private HNSW runtime verifier public key도 fixed 32-byte Ed25519 base64url 길이를 decode/verification 전에 검증하고 malformed public key body를 반사하지 않는다.
- REST/gRPC manifest read fixture는 uploaded manifest/signature를 runtime policy와 Ed25519 검증을 거쳐 반환하고, 이후 runtime `hnsw`, `oram`, `fixed_budget` 또는 private-result `result_privacy` policy가 drift된 settings에서도 fail closed 되는지 검증한다. Manifest upload 전 manifest read, bucket upload, session open은 sanitized `NotFound`로 fail closed 되고, manifest/bucket upload fixture는 signed manifest collection/vector/key lineage/vector metadata context mismatch, Path ORAM tree_height/bucket_count mismatch, invalid manifest Ed25519 signature, bucket `ciphertext_sha256` mismatch, incomplete bucket set, duplicated bucket id를 upload 경계에서 fail closed로 거부한다. Bucket upload도 manifest upload 이후 runtime `hnsw`, `oram`, `fixed_budget` 또는 private-result `result_privacy` policy가 drift된 settings를 fail closed로 거부하고, 정상 runtime settings로는 계속 upload를 완료할 수 있음을 검증한다.
- private HNSW initial bucket upload는 manifest Merkle root뿐 아니라 각 bucket commitment가 collection/vector/key lineage/bucket epoch context와 `ciphertext_sha256`에 묶여 있는지도 서버 validation에서 확인한다.
- REST/gRPC manifest upload, `read_paths`, `commit` signature key id lookup 오류 응답은 submitted key id sentinel을 반사하지 않는다.
- REST/gRPC manifest upload unsupported signature algorithm 오류 응답은 submitted algorithm sentinel을 반사하지 않는다.
- REST/gRPC manifest upload malformed signature 오류 응답은 submitted signature sentinel을 반사하지 않는다.
- REST/gRPC private ORAM manifest upload unsupported/malformed/tampered signature 오류 응답은 submitted signature key/body와 manifest root도 반사하지 않는다.
- REST/gRPC private HNSW ORAM `read_paths`와 `commit`의 unsupported request signature algorithm 오류 응답도 submitted algorithm, session/root/path, signature key/body, bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`의 unsupported request signature algorithm 오류 응답도 submitted algorithm, session/root, signature key/body, bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC manifest upload는 signature key lookup 전에 unsupported algorithm과 malformed signature body를 먼저 검증해 malformed signed request가 registry lookup 경계까지 가지 않는다. Crypto manifest signature validators도 manifest shape를 canonical message construction 전에 검증한다.
- REST/gRPC private HNSW manifest upload/read, bucket upload, session open, snapshot restore preflight는 stored manifest signature shape와 `owner_signing_key_id` 일치를 runtime `signature_public_keys` lookup 전에 검증하므로, non-owner manifest signature key id는 configured 여부와 무관하게 owner-mismatch 오류로 fail closed 되고 submitted key id를 반사하지 않는다.
- REST/gRPC private result ORAM manifest upload/read, bucket upload, session open, snapshot restore preflight는 stored manifest signature shape와 `owner_signing_key_id` 일치를 runtime `signature_public_keys` lookup 전에 검증하므로, non-owner manifest signature key id는 configured 여부와 무관하게 owner-mismatch 오류로 fail closed 되고 submitted key id를 반사하지 않는다.
- runtime `signature_public_keys` registry는 동일 Ed25519 public key를 여러 key id alias로 등록하는 설정을 거부해 private HNSW v1 manifest의 `owner_signing_key_id` authorization이 verifier alias로 재바인딩되지 않도록 한다. 같은 registry validator를 쓰는 private result ORAM과 client envelope provider도 동일한 key-id uniqueness invariant를 공유한다.
- REST/gRPC private result ORAM manifest upload/read, bucket upload, session open은 runtime ORAM tree policy drift도 fail closed 하며 drifted option name이나 submitted bucket ciphertext를 반사하지 않는다.
- SDK manifest/read_paths/read_buckets/commit signing helpers와 read_paths/read_buckets/commit message builders는 malformed manifest, empty 또는 zero-budget read_paths, empty read_buckets, path-count mismatch, malformed 또는 duplicate read path label/root/hash, partial result ORAM bucket path, unsupported request signature algorithm, malformed signature key id, non-advancing commit epoch, empty commit을 canonical message construction 전에 거부한다.
- `qdrant-sec` crypto tests는 private HNSW manifest/read_paths/commit과 private result manifest/read_buckets/commit의 canonical message SHA-256 digest 및 deterministic Ed25519 known-answer signature를 고정하고, `docs/qdrant-sec-private-*-oram-signature-test-vector.json` fixture와의 SDK 호환성도 검증한다.
- REST/gRPC manifest upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC manifest read corrupt store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC private HNSW `read_paths`/`commit`과 private result ORAM `read_buckets`/`commit` client signature key id는 registry lookup 전에 shape validation을 통과해야 하며 invalid key id 오류는 submitted key id sentinel을 반사하지 않는다.
- REST/gRPC private HNSW `read_paths`와 `commit`은 active session manifest의 `owner_signing_key_id`를 확인한 뒤 verifier public key를 lookup하므로 non-owner key id 요청은 registry lookup 경계까지 가지 않는다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`도 active session manifest의 `owner_signing_key_id`를 확인한 뒤 verifier public key를 lookup하므로 non-owner key id 요청은 registry lookup 경계까지 가지 않는다.
- REST/gRPC private HNSW `read_paths`와 `commit`은 malformed/duplicate path label, malformed root, empty/oversized/duplicate updated bucket 같은 request-shape 오류를 signature verification 전에 fail closed 하고, shape-valid 요청만 client signature 검증 뒤 bucket path derivation 또는 Merkle/writeback 준비로 진행한다.
- REST/gRPC private result ORAM `read_buckets`는 session owner-key preflight 이후 canonical signed bucket-id sequence를 detailed path-shape 또는 bucket-range 검증보다 먼저 확인하므로, unauthenticated malformed read batch는 generic signature-failure path에서 멈춘다.
- REST/gRPC bucket upload epoch/root 오류 응답은 submitted root hash sentinel을 반사하지 않는다.
- REST/gRPC bucket upload Merkle root mismatch 오류 응답은 computed Merkle root를 반사하지 않는다.
- REST/gRPC bucket upload 오류 응답은 malformed bucket ciphertext sentinel을 반사하지 않는다.
- REST/gRPC bucket upload ordering/fixed-size 검증 오류는 bucket id, bucket epoch, bucket ciphertext 값을 반사하지 않는다.
- REST/gRPC bucket upload store layout 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC bucket upload/session open current epoch store 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- Common private HNSW/result ORAM store error mappers도 collection-originated path, bucket filename, bucket ciphertext sentinel을 generic 오류로 치환한다.
- collection-local private HNSW ORAM store의 bucket read/proof/commit 오류도 bucket id나 bucket epoch 값을 반사하지 않도록 일반화한다.
- collection-local private HNSW ORAM store의 current epoch, Merkle tree context, bucket shape 오류도 stored/requested epoch, bucket_count, bucket id, unsupported version 값을 반사하지 않도록 일반화한다.
- collection-local private HNSW ORAM store의 file/directory hardening 오류도 collection-local path, temp filename, symlink target, OS error 문자열을 반사하지 않도록 고정 메시지화한다.
- REST/gRPC session open client_id는 길이 제한과 safe ASCII resource-id 문자셋을 먼저 검증하고, oversized/malformed client id 오류 응답은 submitted client id sentinel을 반사하지 않는다.
- SDK helper는 commit plan의 old epoch/root가 해당 signed manifest와 맞을 때만 refreshed manifest/signature를 만들고, stale old root는 client-side에서 거부한다. Refresh 없이 post-commit epoch에서 계속 진행하는 클라이언트는 signed upload-anchor manifest가 아니라 live epoch/root와 leaf commitments를 `plan_private_hnsw_oram_commit_for_manifest_context`/`plan_private_result_oram_commit_for_manifest_context`에 넘겨 manifest lineage 검증과 current CAS context를 함께 유지한다.
- SDK upload bundle preflight는 manifest shape, manifest signature shape/owner key id, bucket ciphertext hash, bucket commitment, manifest root hash를 먼저 검증하고, bucket ciphertext hash와 context-bound commitment가 self-consistent하더라도 decoded ciphertext 길이가 manifest-derived fixed bucket ciphertext size와 다르면 client-side에서 거부한다. `validate_private_hnsw_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 같은 preflight에 runtime manifest validation context와 Ed25519 verification을 묶어 호출할 수 있게 한다. `PrivateHnswOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다.
- manifest-aware `sign_private_hnsw_oram_read_paths_for_manifest_context` helper는 live epoch/root와 manifest key lineage/owner signing key, `oram.path_batch_size`, tree-bounded unique leaf label을 읽기 서명 context로 사용해 fixed read batch 수, leaf range, duplicate path label이 맞지 않으면 SDK에서 서명 전에 fail closed 한다. `sign_private_hnsw_oram_read_paths_for_manifest`는 manifest epoch/root가 live read context인 first-read 또는 refreshed-manifest convenience wrapper로 남긴다.
- SDK/reference commit planning helper는 live old epoch/root와 current leaf commitments를 old commit context로 사용하고, updated bucket commitment가 ciphertext hash와 collection/vector/key lineage/bucket epoch context에 묶여 있지 않으면 commit 서명 전에 fail closed 한다. `plan_private_hnsw_oram_commit_for_manifest_context`는 manifest lineage와 live old epoch/root를 함께 받으며, first commit 또는 optional manifest refresh 직후처럼 manifest epoch/root가 live old context와 같을 때는 `plan_private_hnsw_oram_commit_for_manifest` convenience wrapper도 같은 검증을 수행한다. 두 manifest-aware helper는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget도 강제한다.
- SDK verified encrypted search/fetch helper도 writeback epoch가 read/session epoch보다 전진하지 않으면 첫 ORAM read 또는 local access remap 전에 fail closed 한다. HNSW verified search와 cached verified search는 `InvalidCommitEpoch`로 닫고, private result ORAM verified token fetch는 `new_epoch` manifest-field 오류로 닫아 서버 commit CAS와 같은 non-advancing epoch 불변식을 client boundary에서도 유지한다. Public HNSW plaintext/encrypted/verified search와 private result ORAM multi-batch verified fetch는 작업용 client state에만 remap/writeback을 누적하고 모든 proof/open/reseal 또는 plaintext validation이 성공한 뒤 원본 state를 갱신한다. HNSW search wrapper는 pending writeback overlay를 subsequent reads에 적용하되 caller writeback callback은 full search success 후 한 번만 호출하므로, 뒤 batch proof 실패나 post-access decode 실패가 앞 remap/writeback을 남기지 않는다.
- `PrivateHnswOramStore::commit_writeback_with_signature`와 `PrivateResultOramStore::commit_writeback_with_signature`는 runtime REST/gRPC commit 경로에 연결되어 canonical Ed25519 commit signature를 저장 manifest lineage로 검증한 뒤 durable pending-writeback journal을 fsync하고 fixed ciphertext size, context-bound bucket commitment, Merkle update, bucket writes, epoch/root CAS를 적용한다. 같은 signed commit 재시도는 prepare 직후, bucket/Merkle 반영 중, epoch CAS 직후에 남은 journal을 다시 검증하고 bucket/Merkle write와 CAS를 idempotent하게 완료한 뒤 journal을 삭제/fsync한다. 프로세스 재시작으로 기존 in-memory lease가 사라진 경우 새 session open은 pending journal을 발견해 index write reservation을 잡고 owner signature를 재검증한 뒤 복구를 완료하며, 같은 registry lock 안에서 reservation을 새 session writer lease로 전환한다. REST e2e는 HNSW와 result ORAM 모두 이 43→44 restart-style recovery를 고정한다. 변조 journal은 active state 변경 전에 fail closed 되고, pending journal이 남은 store는 temp-directory snapshot preflight를 통과하지 못한다. Commit CAS는 stored manifest epoch/root가 아니라 current epoch/root와 맞아야 하고, stored manifest는 lineage와 bucket_count 검증에 사용한다. invalid signature, malformed ciphertext, stale root, commitment-context mismatch, bucket ciphertext hash mismatch, short/oversized fixed ciphertext, wrong new Merkle root는 active bucket/Merkle/epoch 상태를 바꾸기 전에 fail closed 하며, runtime 오류 응답은 ciphertext 범주 같은 안전한 힌트만 보존하고 ciphertext body, bucket id, root hash는 반사하지 않는다. Consensus CAS, owner-union encrypted bucket replication, partial-finalize process fault recovery, fixed-layout manual/automatic bucket preinstall transfer, exact active marked transfer restart와 automatic missing-task resume, typed scale-up/down reshard orchestration, bounded existing-peer active-reshard Raft snapshot topology recovery, topology-only non-owner 및 exact scale-up target new-peer snapshot bootstrap, existing/new-owner custom shard-key mutation은 public/consensus 경로에 연결됐다. Pre-layout owner/transfer source/scale-down endpoint snapshot bootstrap은 계속 남아 있다.
- Paired HNSW/result scale-up/down, exact active reshard restart/repreinstall, source hard-crash automatic fresh-preinstall resume, scale-up stable-to-active 및 scale-down active-to-active Raft snapshot E2E, topology-only non-owner 및 wiped exact scale-up target new-peer snapshot E2E, custom shard-key bootstrap/existing-owner create/new-owner partial-preinstall failure와 retry/create/drop E2E가 추가되어 위의 result-ORAM reshard, reshard transfer restart, source-crash fail-closed recovery, automatic task resume, bounded existing-peer active-reshard snapshot recovery, 비소유 신규 피어 topology recovery, exact scale-up target의 full-store/migration recovery, custom shard-key mutation 잔여 항목은 닫혔다. Pre-layout owner/transfer source/scale-down endpoint snapshot bootstrap은 계속 남아 있다.
- 2026-07-29 완료: redundant pre-layout owner, redundant fixed-transfer source/owner, transfer-complete single/multi-shard scale-down endpoint snapshot bootstrap은 exact abort marker와 normal recovery E2E로 닫혔다. Fresh non-preowner active-transfer target의 full wipe는 exact resume marker와 fresh full-store preinstall E2E로 닫혔다. Partial target store loss와 비중복 owner/source는 명시적 fail-closed 경계로 유지한다.
- SDK encrypted client-state backup helper는 ORAM position map/stash snapshot shape를 seal 전에 검증하고, open 전에 ciphertext hash shape와 encoded ciphertext 길이를 제한해 malformed/oversized backup ciphertext를 거부하며, duplicate position/stash, duplicate stash point/payload fetch token, malformed node/token id, malformed leaf label, malformed stash node block/vector/neighbor/level mask, stash map-key/node-id mismatch를 snapshot export/import 경계에서 fail closed 한다. HNSW bucket/client-state AAD와 manifest-build/read-path-signature/commit-signature context의 collection/key ids도 safe ASCII shape로 제한하고, vector name은 slash/path-like 값과 client-state alias를 거부하며, encrypted backup DTO가 position entries, leaf labels, stash blocks, node ids, point/payload fetch tokens, vector bytes, neighbor ids를 plaintext로 직렬화하지 않는지도 검증한다.
- private result ORAM encrypted client-state backup open도 HNSW client-state backup과 같은 epoch/root context binding, malformed ciphertext, short ciphertext, malformed hash, tampered ciphertext fail-closed 회귀를 갖고, duplicate stash point token, malformed stash payload block version/payload length, stash map-key/token mismatch를 snapshot export/import 경계에서 fail closed 하며, client-state AAD 및 read/commit signature collection/key context ids도 safe ASCII shape로 제한한다. encrypted backup DTO가 position tokens, leaf labels, stash payload fetch tokens, point tokens, payload bytes를 plaintext로 직렬화하지 않는지 검증한다.
- manifest-aware `sign_private_result_oram_read_buckets_for_manifest_context` helper는 live epoch/root와 manifest key lineage/owner signing key, `oram.path_batch_size * (oram.tree_height + 1)` fixed bucket-id volume 및 canonical Path ORAM heap path shape를 읽기 서명 context로 사용해 fixed read batch 수나 path shape가 맞지 않으면 SDK에서 서명 전에 fail closed 한다. `sign_private_result_oram_read_buckets_for_manifest`는 manifest epoch/root가 live read context인 convenience wrapper로 남긴다.
- private result ORAM도 동일하게 `plan_private_result_oram_commit_for_manifest_context`는 live old epoch/root와 signed manifest lineage를 함께 사용하고, manifest-aware refresh helper는 first commit 또는 optional manifest refresh 직후처럼 commit plan의 old epoch/root와 signed manifest가 같은 경우에만 refreshed manifest/signature를 만든다. stale old root는 client-side에서 거부한다. manifest-aware SDK commit planner는 서버 commit guard와 같은 `oram.path_batch_size * (oram.tree_height + 1)` fixed writeback budget을 강제해 oversized aggregate writeback plan을 로컬에서 fail closed 한다.
- private result ORAM upload bundle preflight도 manifest signature shape와 owner key id를 먼저 검증한다. `validate_private_result_oram_upload_bundle_with_signature`와 bundle method `validate_initial_upload_contract_with_signature`는 upload API가 shape/bucket/root preflight와 owner Ed25519 verification을 하나의 helper로 호출할 수 있게 한다. `PrivateResultOramStore::write_initial_upload_bundle_with_signature`도 이 helper를 호출한 뒤에만 layout/bucket/current epoch 파일을 쓰므로 owner signature 실패는 저장 상태를 만들지 않는다. `PrivateResultOramStore::commit_writeback_with_signature`는 canonical Ed25519 commit signature를 store manifest lineage로 검증한 뒤에만 기존 bucket/Merkle/epoch writeback 경로로 들어가므로 invalid signature는 저장 상태를 바꾸지 않는다. REST/gRPC commit handler도 canonical commit signature validator가 duplicate bucket refs 같은 malformed writeback shape를 generic signature-failure path에서 먼저 닫은 뒤에만 Merkle/writeback 검증으로 진행한다. manifest-aware commit planning/signature helper도 empty commit, malformed updated bucket ciphertext hash, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않은 commit을 서명/검증 전에 fail closed 한다.
- private result ORAM store의 upload bundle, commit, stored Merkle tree root mismatch 오류는 computed Merkle root를 반사하지 않는다. Bucket read/proof/commit 오류도 bucket id나 bucket epoch 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 current epoch와 Merkle tree context 오류도 stored/requested epoch, bucket_count, unsupported version 값을 반사하지 않도록 일반화한다.
- private result ORAM store의 file/directory hardening 오류도 collection-local path, temp filename, symlink target, OS error 문자열을 반사하지 않도록 고정 메시지화한다.
- private HNSW/result ORAM manifest-only upload helper는 manifest/signature write가 성공한 뒤에만 initial current epoch를 publish하고, current manifest 재업로드는 저장 manifest/signature와 byte-identical일 때만 허용하며, writeback 이후 current epoch가 새 manifest epoch/root로 이미 전진한 post-commit refresh는 허용한다. Session open과 commit CAS는 refresh를 요구하지 않고 `epochs/current.json`의 live epoch/root를 따른다. Private HNSW/result ORAM current manifest reupload mismatch 오류도 제출/저장 signature와 root hash를 반사하지 않도록 테스트로 고정했다.
- private result ORAM store의 bucket shape 검증은 encoded ciphertext 길이를 decode 전에 제한한다. writeback commit도 empty update와 non-advancing epoch를 거부하고 current epoch/root CAS와 manifest bucket_count/lineage를 먼저 확인하며, updated bucket commitment가 ciphertext hash와 collection/key lineage/bucket epoch context에 묶여 있지 않으면 bucket/Merkle write 전에 fail closed 한다.
- private HNSW와 private result ORAM store의 bucket JSON read cap은 decoded ciphertext cap에 고정 여유분만 더하지 않고 base64url encoded 길이와 bounded JSON metadata overhead를 합산한다. 따라서 allowlist의 큰 bucket/block 조합도 정상 read되면서 oversized file은 계속 fail closed 된다.
- private HNSW와 private result ORAM의 client/server boundary arithmetic은 bucket plaintext codec length, canonical signature field length, Path ORAM path batch capacity, session lease expiry, registry refcount, Merkle bucket count, Merkle proof sibling count/level, request length, bucket id conversion을 checked conversion으로 처리해 overflow나 platform-width mismatch가 silent wrap 대신 fail closed 되도록 고정했다.
- private result ORAM initial epoch helper도 같은 epoch/root 재업로드만 idempotent하게 허용하고 mismatched manifest epoch/root 재업로드는 기존 `current.json`을 덮지 않는다. 같은 epoch/root의 initial upload bundle 재업로드도 저장된 manifest/signature, Merkle tree, bucket set과 byte-identical일 때만 no-op으로 허용하며, 각각의 mismatch를 별도 fail-closed 테스트로 고정했다.
- private HNSW ORAM initial upload bundle도 private result ORAM과 같은 parity를 갖는다. manifest Merkle root mismatch는 layout을 만들기 전에 거부하고, existing current epoch/root mismatch는 manifest/bucket/Merkle write 전에 fail closed 하며, 같은 epoch/root 재업로드는 저장된 manifest/signature, Merkle tree, bucket set이 byte-identical일 때만 no-op으로 허용한다. 두 store의 existing manifest/Merkle/bucket-set mismatch 오류도 제출되거나 저장된 root hash, signature, bucket commitment, ciphertext body를 반사하지 않도록 테스트로 고정했다.
- private result ORAM read-batch helper는 encrypted bucket read 전에 current epoch/root를 preflight하고, 반환 bucket과 Merkle proof leaf commitment가 서로 맞지 않으면 ciphertext, bucket id, root 값을 반사하지 않고 fail closed 한다.
- private ORAM bucket의 `index_epoch`는 해당 bucket이 마지막으로 쓰인 epoch를 뜻한다. writeback commit 후 변경되지 않은 bucket은 current index epoch보다 낮은 bucket epoch를 유지할 수 있으며, current Merkle root가 그 기존 bucket commitment를 포함할 때만 read proof로 반환된다. requested session epoch보다 미래인 bucket은 read/proof verifier에서 fail closed 한다.
- private result ORAM store는 directory chmod 전에 symlink/type을 검사하고, bucket symlink와 group/world-accessible bucket directory/file을 fail-closed로 거부한다. Snapshot source/restore preflight도 private HNSW/result ORAM root/nested symlink, unsupported file type, restore inspection error, client-state/position-map/stash alias를 fail closed로 거부하면서 symlink target path, bucket filename, collection-local path, OS error 문자열을 오류에 반사하지 않는다.
- collection-facing private HNSW ORAM runtime validation 오류는 내부 setup error detail을 붙이지 않고 고정 메시지로 반환해 unsupported option 이름, option 값, reason 문자열이 collection runtime BadInput에 반사되지 않는다.
- private HNSW와 private result ORAM Merkle proof store generator는 empty bucket batch를 거부하고, store-level Merkle commit prepare도 empty updated bucket set을 거부한다. SDK JSON verifier도 proof body를 파싱 전에 크기 제한하고, empty proof/bucket set을 거부하며, fixed-size path batch를 위해 반복 bucket/proof entry가 byte-identical인 경우만 허용하고 conflicting duplicate는 fail-closed로 거부한다. Store fixture는 HNSW와 result ORAM 모두 store-emitted duplicate proof JSON이 SDK verifier를 통과하는지 고정한다.
- private HNSW ORAM Merkle proof serialization failure도 serde error detail 없이 고정 service error로 반환한다.
- SDK verified encrypted search는 upper-layer client cache hit 경로에서도 Merkle proof를 bucket decrypt, state remap, ORAM writeback보다 먼저 검증한다.
- private HNSW ORAM commit fixed writeback budget 오류는 실제 max writeback bucket 수를 API 응답에 반사하지 않고 고정 문구로 반환한다. REST/gRPC oversized writeback fixtures가 `1..=N` 형태의 budget range 비노출을 고정한다.
- Common private HNSW/result ORAM session `Debug` fixtures는 bucket count, tree height, path batch size, derived ciphertext byte budget과 embedded manifest를 그대로 반사하지 않는지 고정한다.
- REST access log와 denied-auth audit path는 private ORAM close-session URL의 session id를 템플릿으로 치환하고 private ORAM read/commit query string과 비정상 private ORAM endpoint tail segment를 redacted 처리한다. malformed private result ORAM close-session path도 session id를 반사하지 않는다. Access log와 slow request log/request hash redaction은 private HNSW ORAM path/read/access/visited-node traversal aliases, query vector/embedding/plaintext aliases, score/distance aliases, candidate heap/score/distance aliases, node score/distance aliases, request/commit/read/manifest signature aliases, private result ORAM bucket ids, read bucket ids, bucket id sequences, bucket/leaf commitments, proof/proof_value aliases, updated bucket writebacks, leaf id/remap aliases, access-volume count aliases, session ids, client-state/ciphertext/hash/sha256 aliases, point/payload fetch tokens를 숨기며 snake_case/camelCase 단수·복수와 `payload.fetch.token` dotted alias fixture로 회귀를 고정한다.
- Snapshot/client-state, collection config validation, collection internal transfer/resharding/state/update guards, collection/common store and registry error mapping, slow-log/request-hash redaction, panic/error-reporting/audit redaction, metrics label, REST/gRPC route, receiving-shard, replica-priority recovery, collection cluster guards, and consensus transfer guards now treat `client_state_backup`, `client_state_snapshot`, `clientStateSnapshot(s)`, `encrypted_client_state`/`encryptedClientState`, encrypted client-state backup/snapshot, `*_ciphertext_sha256`, position-map/ORAM-position-map backup, token-position-map backup, and stash backup variants like other client-owned ORAM state aliases, so client state backup/snapshot material cannot be snapshotted as server-owned ORAM files or leak through config/search/update/cluster validation errors, slow/error/status logs, request hashes, metrics labels, route errors, or storage-level recovery/transfer errors.
- REST private HNSW/result ORAM DTO `Debug` fixtures도 manifest signature key/body와 encrypted bucket ciphertext, `ciphertext_sha256`, bucket commitment, upload/read bucket counts가 upload/read response wrapper에서 반사되지 않는지 직접 고정한다. REST/gRPC guard redaction fixtures는 plain/plural client-state, encrypted-client-state, position-map, ORAM-position-map, token-position-map, stash, state ciphertext/hash aliases와 `payload_fetch_token`/`payloadFetchToken(s)`/`payload.fetch.token` aliases까지 같은 금지 목록으로 유지한다.
- denied-auth audit error redaction도 private ORAM path/root/bucket/node/vector/token aliases와 query vector/embedding/plaintext, score/distance, candidate/node score/distance aliases를 숨기며 sentinel fixture로 회귀를 고정한다.
- private result ORAM nested request 객체 안의 `session_id`/`sessionId`, `bucket_ids`/`bucketIds`, `bucket_commitments`/`bucketCommitments`, `updated_buckets`/`updatedBuckets`, client-state ciphertext/hash aliases도 slow-request log와 request hash에서 redacted projection으로 동일화한다.
- panic telemetry와 gRPC status logging redaction도 private ORAM session/client id/path/raw read_paths/access path/read bucket id/bucket sequence/bucket or leaf commitment/leaf id/remap/proof_value/entry node/level mask/visited node/neighbor/query vector/score/distance/candidate score/distance/node score/distance/result/token/client-state/client-state ciphertext/hash/sha256/position-map/stash/update bucket/signature, owner/signing key id, signature-public-key registry, access-volume count/length snake_case·camelCase alias sentinel을 반사하지 않는지 검증한다.
- private result ORAM ordinary payload write/read guards는 configured protected payload path 파싱 실패 시 parser debug detail이나 submitted path token을 반사하지 않고 고정 오류로 fail closed 한다.
- Common/REST/gRPC update fixtures도 private HNSW ORAM `Upsert`/`Delete`/legacy `DeleteDeprecated`/`DeleteVectors`/internal `SyncPoints`와 private result ORAM `Upsert`/`SetPayload`/`OverwritePayload`/`DeletePayload`/`ClearPayload`/legacy `ClearPayloadDeprecated`/`Delete`/legacy `DeleteDeprecated`가 direct ordinary update guard와 같은 session API 안내로 fail closed 되는지 고정한다.
- Common/internal/gRPC create/delete-field-index fixtures도 `private-result-oram/v1` payload path의 payload index/schema creation/deletion이 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Public create/delete-field-index guard는 private result ORAM payload-path 검증 전에 `write().extras()` 권한을 먼저 확인해 unauthorized caller에게 provider/session/path detail을 드러내지 않는지도 고정한다.
- gRPC `GetPoints`/`ScrollPoints`/`SearchPoints`/batch search/`SearchPointGroups`/`RecommendPoints`/batch recommend/`RecommendPointGroups`/`DiscoverPoints`/batch discover/`QueryPoints`/batch query/`QueryPointGroups` ordinary payload read wrappers도 `private-result-oram/v1` payload path를 반환하려 하면 common read guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC `encrypted_payload=decrypted` read requests와 REST group lookup preflight도 `private-result-oram/v1` payload path에 대해 generic decrypt-runtime 오류로 빠지지 않고 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- Common/gRPC read fixtures는 private result ORAM collection에서도 payload를 요청하지 않는 허용 경로를 열어 두어, payload-omitted retrieve/scroll/search 요청이 private result ORAM session을 요구하지 않는지도 고정한다.
- collection-level private result ORAM read/write/selector helper도 retrieve/search/query/recommend/discover/group lookup/filter/order/facet/group-by/update payload operation label 전체가 고정 session API 안내에 반사되지 않는지 공통 assertion으로 고정한다.
- gRPC grouped `with_lookup` payload requests도 lookup collection이 `private-result-oram/v1` payload path를 반환하려 하면 main hit payload가 꺼져 있어도 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC facet, count filter, scroll filter/order-by, formula query, grouped search, grouped query selector wrappers도 `private-result-oram/v1` payload path를 inspect하려 하면 common selector guard와 같은 private result ORAM session API 안내로 fail closed 되는지 고정한다.
- gRPC `PointsSelector` filter variant도 private HNSW ORAM `delete`/`delete_vectors`와 private result ORAM `set_payload`/`overwrite_payload`/`delete_payload`/`clear_payload`/`delete`에서 point-id selector와 같은 private session API 안내로 fail closed 되는지 고정한다.
- REST/gRPC request metrics fixtures도 private result ORAM `read_buckets`와 close-session endpoint에서 fixed endpoint label만 방출하고 dynamic bucket id/session id sentinel을 방출하지 않는지 검증한다. Metrics/OpenAPI surface checks use exact private ORAM route-shape matching, strip query strings only for otherwise fixed routes, and include malformed/lookalike path negatives so partial, similar, or extra-tail path names do not become fixed labels. gRPC private HNSW/result ORAM services are wrapped with the collection telemetry adapter as well, but the wrapper attaches only `collection_name` and never vector names, session ids, path labels, bucket ids, roots, ciphertext, client-state fields, or `*_ciphertext_sha256` client-state aliases.
- REST/gRPC private HNSW와 private result ORAM bucket upload/commit request-shape preflight는 collection, manifest, session lookup 전에 empty upload/writeback, duplicate upload bucket id, malformed `ciphertext_sha256`/`bucket_commitment`를 거부하며 submitted root hash, bucket ciphertext, commit signature body, collection-local store path를 반사하지 않는다.
- REST/gRPC private result ORAM bucket upload preflight도 mismatched 또는 malformed root hash를 submitted root hash와 bucket ciphertext 반사 없이 fail closed 한다.
- REST/gRPC private result ORAM bucket upload ciphertext/hash mismatch 오류도 submitted bucket ciphertext body를 반사하지 않고 generic ciphertext validation failure로 멈춘다.
- REST/gRPC private result ORAM `read_buckets`와 `commit`은 mismatched 또는 malformed root hash를 fail closed 하면서 submitted root hash, commit signature body, updated bucket ciphertext를 오류에 반사하지 않는다.
- REST/gRPC private result ORAM commit fixed writeback budget 오류도 실제 max writeback bucket 수를 API 응답에 반사하지 않고 고정 문구로 반환한다.
- REST/gRPC `read_paths` 오류 응답은 mismatched root hash sentinel, malformed path label sentinel, stored bucket ciphertext를 반사하지 않는다. path-to-bucket derivation helper도 하위 leaf-label decode 오류를 그대로 반사하지 않는다.
- REST/gRPC `read_paths` missing encrypted bucket/proof 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths`는 store current epoch/root가 active session과 맞지 않으면 bucket을 읽기 전에 fail closed 하고 stale root, stored bucket ciphertext, collection-local `private_hnsw_oram` path를 반사하지 않는다.
- REST/gRPC `read_paths`는 collection store의 batch+proof helper로 bucket을 읽어 current epoch/root를 store layer에서도 재확인하고, 응답 직전에 각 bucket commitment가 같은 순서의 Merkle proof leaf와 일치하는지 검증하며, mismatch가 있으면 ciphertext나 store path를 반사하지 않고 fail closed 한다.
- REST/gRPC `read_paths`와 `commit` malformed client signature shape 오류 응답은 submitted signature sentinel을 반사하지 않는다. Crypto signature message builders/validators도 collection/vector/key lineage, root hash, read path label, duplicate path label, `requested_paths`/path count 일치성, non-advancing commit epoch, updated bucket ciphertext hash shape를 signature body parsing/message construction 전에 검증한다.
- REST/gRPC `read_paths` 성공 응답은 bucket id를 unique set으로 축약하지 않고 요청된 ORAM path별 bucket sequence를 보존해 `requested_paths * (tree_height + 1)` 크기를 유지하며, SDK verifier는 반복 bucket/proof가 byte-identical일 때만 허용한다. Collection store fixture도 duplicate Merkle proof JSON이 SDK verifier를 통과하는지 고정한다.
- REST/gRPC `commit` old epoch/root mismatch 오류 응답은 submitted old root hash sentinel을 반사하지 않는다.
- REST/gRPC `commit` fixture는 empty 또는 oversized `updated_buckets`를 fixed writeback request-size validation에서 거부하고, crypto commit signature message builders/validators도 empty bucket list를 signature body parsing 전에 fail closed 한다.
- REST/gRPC `commit` 오류 응답은 malformed updated bucket ciphertext/hash sentinel과 malformed `new_root_hash` sentinel을 반사하지 않으며, updated bucket `ciphertext_sha256` shape는 commit signature message construction 전에 검증한다.
- REST/gRPC `commit` missing Merkle metadata 오류 응답은 collection-local `private_hnsw_oram` filesystem path를 반사하지 않는다.
- REST/gRPC `read_paths` fixture는 path count, requested path count, dummy padding flag가 fixed path budget과 다르거나 exact duplicate/oversized/malformed path label을 포함하면 bucket read 전에 fail-closed로 거부하고 malformed label 본문을 반사하지 않는다. Common read budget helper unit test도 requested path 수, 실제 path 수, dummy padding flag mismatch가 session/detail 값을 반사하지 않는 고정 오류로 떨어지는지 고정한다.
- REST/gRPC `read_paths` 성공 경로는 collection/vector, key lineage, epoch/root, path labels, padding metadata에 대한 Ed25519 client signature를 검증한 뒤 encrypted buckets를 반환하고, invalid read signature는 fail-closed로 거부한다.
- REST/gRPC `read_paths`는 session lookup 전에 leaf label을 canonical fixed-length base64url form으로 제한하고 duplicate path label을 거부하며, fixed-budget/session epoch-root 검증 뒤 shape-valid 요청의 Ed25519 request signature를 ORAM bucket path 계산보다 먼저 검증한다.
- REST/gRPC `commit`은 bounded request-size/epoch checks 뒤 `old_root_hash`/`new_root_hash`를 canonical 32-byte base64url shape로 먼저 제한하고, Ed25519 request signature를 Merkle/writeback preparation보다 먼저 검증한다.
- OpenAPI `Beta` path surface도 private HNSW ORAM manifest/bucket/session/read/commit/close와 private result ORAM manifest/bucket/session/read/commit/close REST endpoints를 노출한다. 암호화 envelope DTO는 SDK-owned wire contract라 현재 OpenAPI에서는 opaque object request/response로 고정한다.
- REST/gRPC private HNSW `read_paths`/`commit`과 private result ORAM `read_buckets`/`commit` request signature key id는 session manifest의 `owner_signing_key_id`와 달라도 fail closed 한다.
- gRPC private HNSW/result ORAM proto conversion은 unspecified enum뿐 아니라 unknown nonzero enum 값도 fail closed 하고, unsupported enum 값을 status message에 반사하지 않는다.
- active session의 `read_paths`와 `commit`은 session open 이후 runtime instance policy가 바뀌어도 session manifest를 현재 runtime context와 다시 비교하고 drift를 fail closed 한다.
- REST와 gRPC route fixtures는 active session 이후 runtime `hnsw`, `fixed_budget`, `oram`, 또는 private-result `result_privacy` policy가 drift된 settings로 HNSW `read_paths`, result ORAM `read_buckets`, 또는 `commit`을 호출하면 fail closed 되는 경계를 모두 검증한다.
- private HNSW snapshot restore preflight는 `private_payload_oram_required` manifest를 collection에 `private-result-oram/v1` payload binding과 대응하는 result ORAM snapshot store가 있을 때만 허용하고, 없으면 fail closed 한다.
- CLI/startup snapshot mapping recovery도 crypto runtime validation 이후 private HNSW ORAM restore-layout preflight를 실행해 storage-level snapshot recovery와 같은 bucket/root consistency 검증을 적용하고, store-originated layout 오류는 collection-local `private_hnsw_oram` 경로나 bucket body를 반사하지 않도록 sanitize한다.
- CLI/startup private HNSW ORAM restore-layout 실패는 bucket id, bucket commitment mismatch detail, store file detail을 반사하지 않는 고정 메시지로 보고한다.
- private HNSW ORAM vector store 이름은 safe store path component가 아니거나 `client.state`, `position.map`, `stash`처럼 separator를 제거하면 client-owned state alias가 되는 값을 거부하고, snapshot source/archive/restore preflight도 같은 unsafe component와 확장자 없는 dotted alias/확장자 포함 alias를 fail closed 한다.
- CLI/REST snapshot recovery는 private HNSW ORAM restore-layout preflight 이후 runtime `signature_public_keys`로 stored manifest Ed25519 signature를 검증하고, tampered manifest signature를 bucket/root/path 반사 없이 fail closed 한다.
- storage-level `Collection::restore_snapshot` 자체도 shard restore 전에 private HNSW ORAM restore-layout preflight를 실행하고, layout 오류가 collection-local `private_hnsw_oram` 경로나 bucket body를 반사하지 않도록 sanitize한다.
- CLI/startup과 storage-level snapshot recovery도 private result ORAM restore-layout preflight를 실행하고, REST recovery validator는 result ORAM manifest Ed25519 signature를 runtime registry로 검증한다. orphan `private_result_oram/` store와 bucket/root layout mismatch 같은 오류는 collection-local path, reserved directory name, bucket ciphertext 반사 없이 fail closed 한다.
- collection-level private HNSW ORAM snapshot manifest/bucket-contract mismatch 오류도 manifest ids, vector name, dimension, bucket id, bucket ciphertext를 반사하지 않는다.
- REST/gRPC session open의 stale requested epoch 오류는 requested/current epoch 값을 반사하지 않고, private HNSW runtime `result_privacy` unsupported-value 오류도 submitted option value를 반사하지 않는다.
- collection/runtime vector dim/distance mismatch 오류는 실제 dim/distance 값을 반사하지 않는다.
- `qdrant-sec` private HNSW provider/client와 private result ORAM helper의 `Display` 오류 문자열은 structured enum fields를 보존하되 bucket id, epoch, version, ciphertext length, leaf, unsupported algorithm 같은 값은 반사하지 않도록 고정 메시지화한다.
- `qdrant-sec` private HNSW client와 private result ORAM error `Debug` 회귀도 Display와 같은 structured-value variant를 직접 렌더링해 bucket id, epoch, version, context sentinel, unsupported algorithm/detail이 반사되지 않는지 고정한다.
- Collection store initial upload의 unsupported/tampered manifest signature 오류도 submitted algorithm, signature key/body, manifest root, bucket ciphertext/hash/commitment를 반사하지 않고 layout 생성 전 fail closed 된다.
- Collection store writeback의 unsupported commit signature algorithm 오류도 submitted signature key/body, old/new root, updated bucket ciphertext, bucket commitment를 반사하지 않고 저장 epoch/bucket/Merkle 상태를 유지한다.
- `qdrant-sec` private result ORAM client helper의 encryption wrapper error는 inner AEAD algorithm/detail 문자열을 Display에 붙이지 않는다. Private HNSW helper는 resource-key validation 오류를 wrapper로 보존하지 않고 고정 `InvalidResourceKeyId`로 매핑해 submitted key detail을 반사하지 않는다.
- snapshot creation/restore preflight는 on-disk private HNSW ORAM vector store가 collection encryption rule에 매칭되지 않거나, configured vector store가 없거나, parent store가 symlink이거나, client-owned ORAM state 또는 non-empty temp write state가 섞여 있으면 fail-closed로 거부한다.
- manifest signature, manifest ORAM capacity, bucket hash, stale epoch, invalid commit signature, symlink/permission hardening, snapshot leakage, crash recovery는 현재 provider/store/API fixture에 추가되어 있다.

완료 조건:

- `vector/client-ckks@v1`는 server-blind opaque storage, `vector/openfhe-ckks@v1`는 trusted-bridge search, `vector/private-hnsw-oram@v1`는 client-led ORAM-HNSW search로 명확히 분리된다.
- Qdrant는 private provider에서 vector/query plaintext, distance/score, HNSW traversal decision, top-k result 결정을 수행하지 않는다.
- private provider의 snapshot/restore/shard transfer는 encrypted buckets, manifest, epoch/root metadata만 다루고 fail-closed 검증을 갖춘다.

## Phase 12: Private ORAM v2 Recovery and Append-Only Mutation

목표: Phase 11의 read-only bulk-built v1 provider를 운영 복구가 가능하고
fixed-capacity append insertion을 지원하는 v2 provider로 확장한다.

Versioning:

- `vector/private-hnsw-oram@v1`와 `payload/private-result-oram@v1`는 현재
  read-only bulk-built contract로 유지한다.
- Dynamic insertion은 signed manifest의 logical/dummy count와 HNSW/result
  상태를 함께 바꾸므로 in-place v1 확장으로 처리하지 않는다.
- 새 mutable contract는 `vector/private-hnsw-oram@v2`,
  `payload/private-result-oram@v2`, 대응하는 `/v2` binding으로 분리한다.
- v1에서 v2로의 전환은 client-side full rebuild와 새 signed initial upload를
  요구하며 server-side in-place migration은 지원하지 않는다.

v2 최소 범위:

- live source가 있는 wiped fixed-layout transfer target의 fresh-preinstall recovery
- RF=1 및 multi-shard non-redundant owner의 signed external backup restore
- fixed-capacity append-only insertion과 optional paired result payload insertion
- single logical writer, fixed padded mutation budget, client WAL
- update, delete, tree resize, online capacity expansion, true multi-writer는 비목표

현재 상태(2026-08-14):

- strict `private_payload_oram_required`, no-server point record, single logical writer 범위의
  V2 mutation data path는 public REST session/read/append/status/close, V3 owner reservation,
  recovery-capsule prestage/adoption, collection-wide consensus apply, seq1-7 terminal resume,
  cleanup witness, local cleanup marker, exact clear, terminal archive와 clear acknowledgement까지
  연결됐다.
- `ids_visible` mutation은 admission 및 durable-resume 양쪽에서 fail closed 한다. Visible point
  publish/abort authority는 V2 범위에서 활성화하지 않는다.
- 구현 완료와 production release는 구분한다. Coordinator takeover, acknowledged archive/capsule의
  물리 GC, Linux multi-process kill/failpoint matrix, latency/bandwidth benchmark와 운영 restore drill은
  V2-E release gate에 남아 있다.

보안 불변식:

- Qdrant는 client RK, vector/query plaintext, node/neighbor id, point token,
  position map, stash, distance, traversal state를 보유하지 않는다.
- 모든 mutable state는 monotonic `state_seq`, layout generation, HNSW/result
  epochs/roots, occupancy commitment, encrypted client recovery-state digest로
  하나의 owner-signed state record에 결합한다.
- Paired HNSW/result mode에서는 한 collection-wide mutation CAS가 두 상태를
  함께 전진시킨다. 한쪽만 새 epoch인 상태는 session과 recovery에서 거부한다.
- Mutation 전 client WAL을 fsync하고, server CAS acknowledgement 뒤 새 encrypted
  client checkpoint를 승격한다. 이전 checkpoint는 rollback recovery까지 보존한다.
- Insert는 고정 round/path/writeback budget과 dummy padding을 사용하고 예약
  capacity나 stash limit을 넘으면 server mutation 전에 거부한다.
- Backup/restore/transfer/mutation 중 일반 session과 ordinary point/vector/payload
  mutation API는 fail closed 한다.
- Client는 최신 backup generation, signed checkpoint, complete encrypted client
  recovery state를 pin한다. 이 pin 또는 외부 transparency log 없이 fully
  compromised server rollback은 막을 수 없다.

### V2-A: Signed External Recovery Checkpoint

Checkpoint domain:

`qdrant-sec/private-oram-external-recovery-checkpoint-signature/v1`

Signed fields:

- version, stable collection id, monotonic backup generation
- source peer id, canonical sorted local shard ids
- layout generation, canonical sorted owner-peer union
- shard-layout digest, private index-state digest
- exact closed collection snapshot byte size와 기존 Qdrant lowercase-hex SHA-256
- complete encrypted client recovery-state set의 base64url SHA-256 digest
- owner signing key id, creation time

작업:

- Crypto crate에 deny-unknown-fields DTO, redacted `Debug`, canonical
  length-prefixed big-endian message, package/sign/verify helper를 추가한다.
- Shape validator는 zero generation/size, empty/duplicate/unsorted owner 또는
  shard set, source-owner mismatch, malformed digest/signature를 서명 전에 거부한다.
- Restore validator는 collection/source/shards/layout/index/snapshot/client-state
  context를 exact match하고 owner-key registry로 Ed25519 signature를 검증한다.
- SDK complete recovery state는 기존 position map/stash 외 entry node와
  `ids_visible` point-token map을 encrypted body에 포함한다. Result ORAM state도
  동일 backup generation에 묶는다.
- Client-state ciphertext body는 recovery checkpoint, Qdrant API, Qdrant snapshot에
  넣지 않는다. Checkpoint에는 complete encrypted set의 digest만 넣는다.

현재 완료 범위:

- Recovery checkpoint DTO와 canonical package/sign/verify, exact context validator,
  deterministic known-answer 및 malformed/tamper/redaction unit test를 추가했다.
- Server restore admission, isolated read-only preflight, durable live
  install/commit은 V2-C에 연결됐다. Export와 complete client recovery-state DTO,
  RF=1 hard-crash/readback process gate는 아직 남아 있다.

완료 조건:

- Snapshot byte, client recovery state, consensus layout/index state 중 하나라도
  바뀌면 checkpoint 검증이 실패한다.
- SDK는 모든 private index의 epoch/root와 complete client state가 일치할 때만
  backup generation을 complete로 승격한다.

### V2-B: Fixed-Layout Active Target Fresh Preinstall

작업:

- Existing active marked `stream_records` transfer의 wiped target에 durable
  recovery intent를 남기고 target-triggered resume request를 허용한다.
- Source는 exact transfer id/method/source/target/layout transition을 재검증하고
  새 reservation 아래 every configured HNSW/result full store를 다시 설치한다.
- Target은 full-store acknowledgement를 durable하게 기록한 뒤 기존 exact
  `RestartTransfer(StreamRecords)` path로 point migration을 재개한다.
- Stale target-local buckets, source unavailable, transfer drift, target already
  active, competing transfer/reshard는 계속 fail closed 한다.

테스트:

- 기존 wiped-target rejection fixture를 bounded success fixture로 확장한다.
- source preinstall 전/중/후 crash, duplicate resume, stale root/signature,
  method/endpoint drift를 process E2E로 고정한다.

현재 완료 범위:

- Snapshot recovery marker v3는 `abort`와 `resume` action을 명시적으로
  분리하고, 기존 v1/v2 marker는 abort로만 해석한다.
- Fixed-layout snapshot preflight는 target이 pre-layout owner가 아니고 다른
  pre-layout shard도 소유하지 않으며, collection이 없거나 모든 configured
  ORAM store가 함께 없는 경우에만 exact resume intent를 기록한다. 일부 store만
  없거나 기존 store가 transition epoch/root와 다르면 mutation 전에 거부한다.
- Target restart hook과 source task monitor는 sole exact marked transfer,
  `Active` source, `Partial` target 조건에서만 transfer를 보존한다. Resume request는
  consensus apply를 막지 않는 background task로 보내며 overlapping request는
  collection의 exact transfer resume intent로 제한한다.
- Source internal API는 endpoint/method/sync와 pre/post layout generation/digest,
  index-state digest를 exact match하고, 새 reservation 아래 모든 HNSW/result store를
  설치하기 전에 기존 source task를 완전히 정지해 stale finish/abort callback을
  차단한 뒤 `RestartTransfer(StreamRecords)`를 호출한다. Task pool과 Raft restart
  operation은 full expected transfer identity를 묶어 same-key replacement race를
  거부한다. Auto layout은 configured shard count를, custom layout은 exact shard-key
  mapping coverage를 검증한다.
- Replacement task의 target initiate ACK 전에 exact active transfer와 모든 configured
  local store의 transition epoch/root를 재검증하되 marker는 유지한다. Target-local
  marker와 cluster-wide active transfer가 private session을 차단하고, transfer가
  사라진 뒤 target `Active`와 store 상태를 다시 검증한 consumer만 marker를 삭제한다.
- 3-peer process E2E는 target collection 전체 삭제와 HNSW/result store-only 전체
  삭제를 각각 compacted Raft snapshot으로 복원하고, fresh preinstall, same-key
  restart, marker 기반 HNSW/result session 차단, layout generation 2, session 재개방,
  marker cleanup, all-peer log redaction을 검증한다.
- Automatic fixed resume source는 기존 task를 정지하거나 reservation을 잡기 전에
  mode `0600`의 exact full-transfer와 domain-separated reservation lease-id hash를
  preinstall intent로 atomic save/fsync한다. Source restart는 이 intent가 sole active
  transfer, `Active` source, `Partial` target, consensus-bound transition과 모두
  일치할 때만 startup abort를 억제한다. 재기동 handler는 process-local session이
  없고 기록된 hash 및 full lease가 모두 일치하는 source reservation만 CAS
  release한다. Partial multi-index acquisition의 missing lease는 허용하되 더 새
  reservation은 삭제하지 않고, 재시도 전 fresh reservation hash로 intent를
  atomically 교체한다. Intent는 replacement transfer의 exact finish/terminal abort
  때까지 유지하며 startup은 이미 transfer가 없는 terminal leftover만 idempotently
  삭제한다. Malformed/insecure/active-transfer-mismatched intent는 fail closed 한다.
- Staging-only process matrix는 reservation 직후, 첫 HNSW store ACK 직후, 모든
  HNSW/result store ACK 직후, restart Raft apply 직후의 hard crash와 valid-shaped
  stale root, stale result signature를 검증한다. 각 단계의 target store durability,
  target/source marker 유지, session 차단, exact generation-`+1` recovery,
  marker cleanup, 원본 및 valid-shaped stale root/signature/ciphertext 로그 비노출을
  3-peer E2E로 고정했다. Exact method/endpoint/transition drift와 newer reservation
  identity 보존은 unit contract로 함께 유지한다. 별도 3-peer regression은 stale-root
  실패 뒤 남은 source intent가 exact terminal abort에서 제거되고 pre-layout
  generation/owner가 유지되는지 검증한다.

완료 조건:

- Wiped target은 live source의 freshly verified full-store bundle 없이는 transfer를
  재개하지 않는다.
- Session은 store install과 exact transfer completion 전까지 열리지 않는다.

### V2-C: Non-Redundant Owner External Restore

작업:

- Admin-only begin/upload/verify/commit/abort restore protocol과 expiring consensus
  recovery lease를 추가한다.
- 초기 범위는 consensus가 계속 가리키는 동일 peer identity 복구다. Replacement
  peer는 restore 완료 후 별도 topology transition으로 처리한다.
- Upload는 bounded chunks를 private temp directory에 저장하고 checkpoint의
  exact size/lowercase-hex SHA-256을 검증한다.
- Verify는 stable UUID/config, exact source shard set, point shard files,
  HNSW/result manifest signature, every bucket/hash/commitment/Merkle root,
  current epoch/root를 기존 restore preflight로 재검증한다.
- Commit은 durable recovery marker 아래 point shards와 collection-local ORAM
  stores를 install하고 exact layout/index-state/recovery-lease CAS를 제출한다.
- temp write, verify, local install, consensus commit, marker cleanup crash point마다
  old 전체 상태 또는 new 전체 상태만 복구한다.

현재 완료 범위:

- Collection-wide external recovery state와 `Begin/Renew/Abort` consensus CAS를
  추가했다. Recovery lease는 exact layout/index-state binding을 포함하고 private
  session, epoch/root, layout transition과 상호 fence하며 committed backup
  generation rollback을 거부한다.
- Distributed global-manage 전용 `begin/upload/status/verify/abort` REST API를
  추가했다. Raw operation token은 begin 응답에만 반환하고 consensus에는
  domain-separated hash만 저장한다. Status token은 전용 header만 허용하며 응답,
  access log, metrics label은 token/query 값을 보존하지 않는다.
- Upload는 private no-follow staging 아래 순서가 고정된 8 MiB chunk, chunk SHA-256,
  exact archive size/hash, collection-level file lock, atomic state/fsync, suffix
  truncation recovery를 강제한다.
- Verify는 archive를 operation-local pending directory에 복원하고 stable UUID와
  byte-exact config, source-local shard set, payload schema, 모든 HNSW/result
  manifest/signature/bucket/root를 재검증한다. 추가 read-only inspector는 current
  version, no recovery/initializing/dummy state, complete replica state, all-Active
  owner topology, local WAL/segment 구조를 쓰기 없이 검사하고 canonical layout
  digest를 checkpoint와 대조한 뒤에만 verified staging으로 승격한다.
- Lease가 만료돼도 동일 owner/token은 abort할 수 있고, 유효한 takeover는 이전
  local staging을 best-effort 정리한다.
- Durable install marker는 stopped old tree와 verified new tree digest, stable
  identity, semantic config digest, operation/checkpoint/layout/index-state
  binding, fresh 256-bit install-attempt nonce를 fsync한다. Nonce가 install-intent
  digest에 들어가므로 rollback 뒤 같은 tree를 다시 prepare해도 이전
  Prepare/Rollback CAS와 같아지지 않는다. `Staging` reconcile은 남은
  `Prepared` marker를 폐기해 다음 prepare가 nonce를 재사용하지 못하게 한다.
  Marker v4의 `RollbackInProgress`/`RollbackComplete`와 old config/private-state
  digest는 candidate 삭제 전, 삭제 후, backup restore 후 crash를 모두 old tree로
  reconcile하고 consensus rollback 관찰 전에는 marker를 보존한다.
  `PrepareInstall`은 exact `Staging -> Installing` CAS로 session과 일반 collection
  접근을 막고, local rename 전후 crash를 old 전체 또는 new 전체로 reconcile한다.
- Registry detach tombstone은 read/meta/create/delete/alias와 Raft snapshot apply를
  fence하고 collection snapshot에는 cached state를 합쳐 detached collection이
  삭제된 것으로 직렬화되지 않게 한다. 일반 collection/shard snapshot recovery,
  cross-collection lookup API, live Staging/restart-Installing snapshot apply, peer
  removal도 동일 fence를 적용하고 snapshot generation의 collection/alias lock
  order를 고정했다. Cross-collection lookup은 precheck 뒤 lifecycle lock을 결과
  callback까지 유지한다. Raft snapshot의 `Installing -> Staging`은 동일 lease의
  exact rollback image만 owner/non-owner 모두 적용하고, owner에서는 local durable
  marker reconciliation이 tree 복구를 독립적으로 증명해야 fence를 제거한다.
  Changed/dropped install snapshot은 계속 거부한다.
- Promoted tree는 `LoadInProgress` marker 아래 consensus가 아직 `Installing`인 동안
  실제 `Collection::load`를 거친다. Stable identity, byte-exact config,
  metadata-derived 및 실제 loaded local shard set, no transfer/resharding,
  all-Active replica state, shard key, owner union, semantic config/canonical
  layout/private-store digest가 모두 일치한 뒤에만 `Loaded`를 기록하고 Raft Commit을
  제출한다. Load/validation 실패는 durable rollback phase로 mutated candidate를
  폐기하고 exact old tree와 `Staging` consensus를 복원한다. `Loaded` marker부터는
  delayed Raft Commit과 충돌하지 않도록 point-of-no-return로 취급한다.
- Global-manage 전용 `commit` REST route는 exact committed generation을 다시
  관찰한 뒤에만 backup/marker를 finalize하고 이미 loaded collection을 publish한다.
  Startup은 pre-load phase를 `LoadInProgress`로 roll-forward하고 normal load 뒤
  post-load finalize를 수행한다. Active Staging/Installing state 또는 pending marker가
  있으면 forced snapshot restore와 tolerant load-error mode를 차단한다. Post-load
  finalize는 registry의 exact stable collection identity와 canonical layout digest를
  확인해야 backup을 지운다. Timeout 또는 불명확한 submit 결과는 파일을 되돌리지
  않고, exact marker/token retry가 tombstone 또는 live registry의
  Installing/Committed 상태를 이어서 정리한다.
- External verify는 archived replica peer identity를 rewrite하지 않고 source peer와
  다르면 그대로 거부한다. Persistent snapshot apply save failure는 in-memory
  recovery fence를 원상복구하고, exact rollback과 inexact transition을 분리한다.
- Unit test는 marker fsync ambiguity, stale-attempt rollback, private-store
  substitution, config substitution, destructive rollback crash points,
  committed-marker resume, load-before-cleanup, exact/inexact rollback snapshot과 기존
  signature/CAS matrix를 고정한다.

다음 작업:

- Consensus commit 전후, `LoadInProgress`/`Loaded` marker, marker cleanup,
  pre-commit load 실패의
  hard-crash process matrix를 추가한다.
- RF=1 single/multi-shard same-peer restore E2E에서 archive upload부터 commit,
  process restart, 첫 proof-verified read/writeback까지 검증한다.
- Commit submit ambiguity와 delayed Raft apply, detached/live-fenced snapshot
  generation/apply, lifecycle create/delete/alias/peer-removal race를 실제
  process/concurrency fault test로 고정한다.

완료 조건:

- RF=1 single/multi-shard owner를 snapshot, signed checkpoint, out-of-band complete
  client recovery state로 복구하고 첫 proof-verified read/writeback을 성공한다.
- Stale backup generation/layout/root, wrong archive/client-state digest, partial
  shard set, expired lease, crash injection은 상태를 보존하며 fail closed 한다.

### V2-D: Mutable State and Append-Only Insert

범위와 불변식:

- v1 manifest와 provider는 read-only bulk-built 계약으로 유지한다. v2 immutable
  manifest는 collection의 canonical private index set, provider-specific HNSW/ORAM
  설정, physical slot 수, logical capacity, reserved physical slack, client stash
  상한, exact append read/write budget을 서명한다.
- Mutable `PrivateOramSignedStateV2`는 immutable manifest digest, layout generation,
  monotonic state sequence, canonical HNSW/result index별 epoch/root,
  logical/dummy occupancy, 마지막 writeback digest, complete encrypted client-state
  set digest와 마지막 mutation id를 묶는다.
- 모든 index에서 `logical + dummy == immutable logical capacity`를 유지한다.
  한 append는 exact index set 전체에 대해 state sequence와 epoch를 각각 1 증가,
  logical을 1 증가, dummy를 1 감소시킨다. Root, last writeback digest와 encrypted
  client-state digest도 반드시 바뀐다.
- "Append-only"는 새 logical point만 추가한다는 의미다. HNSW insertion에 필요한
  bounded backlink/neighbor block rewrite는 signed fixed budget 안에서 허용하지만,
  기존 point의 vector/payload update, delete, standalone rewiring/compaction,
  capacity resize와 rebuild swap은 허용하지 않는다.
- v2는 하나의 logical writer만 지원한다. Stale client는 exact current signed-state
  digest/sequence CAS와 consensus-issued writer lease digest/monotonic operation
  fence로 거부한다. Writer identity handoff와 concurrent position map/stash merge는
  v3로 남긴다.
- 일반 upsert/update_vectors/payload write는 v2 private names에서도 계속 거부한다.
  전용 append route가 활성화되기 전까지 v2 contract 전체가 dormant 상태다.

#### V2-D0: Signed mutation contract

- `lib/crypto/src/private_oram_mutation.rs`에 immutable v2 manifest, collection-wide
  signed state, `private-oram-mutation/v1` append bundle과 canonical Ed25519
  encoding을 추가한다.
- Mutation은 mutation id/issued/expiry, writer lease digest/fence, exact old/new
  signed state, point operation kind/digest와 fixed-size ordered root-to-leaf
  HNSW/result bucket-occurrence frame을 묶는다. Result privacy가
  `private_payload_oram_required`이면 manifest가 `no_server_point_record`를
  강제하고 validation caller가 이를 visible point operation으로 완화할 수 없다.
  각 new index state의 writeback digest는 index kind/name, old/new epoch/root,
  exact read path count, server-observed ordered read transcript digest, bucket id,
  ciphertext SHA-256와 bucket commitment를 다시 묶는다. Read transcript는
  collection/manifest/mutation/old-state identity, writer lease+fence, manifest
  path-batch/tree geometry, index identity와 contiguous request window, duplicate를
  보존한 ordered in-range leaf-label sequence를 묶는다.
- `ids_visible` point operation은 arbitrary context digest를 허용하지 않는다.
  Collection/manifest/mutation, canonical point id와 exact durable staged InsertOnly
  frame SHA-256를 domain-separated digest로 묶는다. D3는 이 staged frame의
  canonical encoding을 route 활성화 전에 고정한다.
- Shape/context/transition validation은 unknown field, malformed digest/signature,
  unsorted/duplicate index, 잘못된 bucket occurrence 수·frame 경계·root-to-leaf
  순서·leaf transcript·bucket 범위, stale/skip sequence, mixed epoch/root,
  sequence/epoch overflow, immediate mutation-id reuse, future-signed new state,
  stale writer fence, unobserved 또는 manifest-geometry-mismatched read transcript,
  capacity exhaustion, wrong point digest, non-fixed batch 크기를 fail closed 한다.
  Bucket id 중복은 정상이며 signed frame 순서대로 적용하고, 같은 bucket의 마지막
  occurrence가 sparse Merkle patch와 durable write의 최종 commitment를 결정한다.
- D1 HNSW manifest는 `f32_le` vector encoding만 허용한다. Canonical KAT는 full
  manifest/old+new state/mutation DTO, read transcript, writeback, private/visible
  point operation의 canonical message bytes, digest와 Ed25519 signature를 함께
  고정한다.
- 이 단계에서는 provider registry, storage, consensus, route를 열지 않는다.

#### V2-D1: Client append planner

##### V2-D1-A: Encrypted checkpoint and duplicate ledger

- `PrivateOramAppendClientCheckpointV2`는 collection/manifest/layout/state sequence,
  canonical point ledger와 exact private index set을 묶는다. Point ledger는
  point token, optional visible point id, optional payload fetch token 관계를
  보존하고, HNSW index별 node/point/level/generation ledger 및 result
  payload/point/generation ledger와 position map/stash를 교차 검증한다.
- `ids_visible`은 visible point id를 필수로 하고 payload fetch token을 금지한다.
  `private_payload_oram_required`는 반대로 payload fetch token을 필수로 하고
  visible point id를 금지한다. 모든 HNSW/result index는 같은 logical point
  관계를 가져야 한다.
- Signed state와 encrypted checkpoint의 순환 commitment를 피하기 위해 checkpoint
  ciphertext와 public metadata digest를 먼저 `client_state_digest`로 확정하고
  state를 서명한다. Full signed-state digest는 그 뒤 outer checkpoint binding에
  붙이며 client-state digest에는 다시 넣지 않는다. Open은 두 digest와
  collection/manifest/layout/sequence/index epoch/root를 모두 재검증한다.
- 기존 overwrite 가능한 `insert_position`은 v1 호환용으로 유지한다. Append
  경로는 `insert_position_if_absent`와 validated position+stash insertion을
  사용하며, 전역 node/point/payload 중복은 encrypted checkpoint ledger에서
  첫 server read 전에 거부한다.
- Canonical checkpoint digest KAT는
  `docs/qdrant-sec-private-oram-append-checkpoint-test-vector.json`에 고정한다.

##### V2-D1-B: Ordered Path ORAM frame contract

- D0 writeback은 exact ordered path frame을 사용한다. 여러 Path ORAM access에서
  같은 bucket이 반복되어도 occurrence를 정렬하거나 합치지 않고 서명한다.
- 총 frame 수는 `fixed_append_read_path_count`, frame당 bucket occurrence는
  `tree_height + 1`로 고정한다. Root-to-leaf bucket id와 read transcript leaf
  sequence가 정확히 일치해야 하며 duplicate bucket id는 frame order대로
  보존한다.
- Full leaf commitment vector를 client에 요구하지 않는다. Verified read
  multiproof를 합치는 Merkle patch accumulator로 ordered final root를 계산하고,
  같은 bucket은 마지막 occurrence를 최종 값으로 사용한다. Non-power-of-two와
  single-bucket fixture에서 full recomputation과 일치시키며, unproven update,
  conflicting overlapping proof와 stale epoch/root를 거부한다.

##### V2-D1-C: Bounded HNSW append state machine

- 순수 graph-delta planner는 전체 checkpoint/state를 먼저 검증하고 첫 구현을
  level-0 append로 제한한다. Visited F32 candidates에서 distance와 node id로
  deterministic bounded neighbor를 고르고 reverse edge를 계획한다. 수정 node
  generation은 정확히 1 증가하며 node/point/payload identity, vector, level mask,
  deleted flag와 upper-layer edge는 rewrite에서 바뀌지 않는다.
- HNSW fixed path budget은 `candidate slots + max_neighbor_rewrites + insert slot`
  으로 분리한다. Manifest는 최소 한 candidate slot을 남기도록
  `fixed_append_read_path_count >= max_neighbor_rewrites + 2`를 강제하고, planner는
  사용하지 않은 candidate/rewrite slot을 padding으로 계산한다.
- Reciprocal rewrite가 모두 prune되면 새 node를 entry로 승격하고 이전 entry를
  level-0 neighbor로 강제해 기존 graph 도달 가능성을 유지한다.
- Append-safe path rewrite primitive는 target block을 stash에 올린 뒤 closure를
  적용하고 writeback하며, targetless HNSW/result eviction은 padding과 empty-index
  첫 삽입을 처리한다. 실패 시 cloned working state만 폐기되어 원본은 불변이다.
- `PrivateOramAppendHnswTransactionV2`는 HNSW 1개와 optional result 1개 topology,
  exact manifest path/window 수, candidate/rewrite/insert/padding 순서를 소유한다.
  Candidate block은 caller가 주입하지 않고 pinned old epoch/root multiproof를 검증한
  accepted window에서만 수집한다.
- 각 path는 server의 old-root bucket을 먼저 검증·복호화하고 이전 path의 최신
  plaintext overlay를 우선 적용한다. 새 epoch ciphertext를 path occurrence 순서대로
  보존하는 동시에 bucket별 last value를 sparse Merkle root와 최종 storage image에
  사용한다. Read response도 요청한 root-to-leaf path 순서를 그대로 따르며 공유
  root/ancestor 중복을 보존한다. 같은 leaf의 후속 window 재방문도 이 규칙을 따른다.
- Path 공개 전 `prepare_next_read_window`가 path 없는 recovery marker만 반환한다.
  SDK가 marker를 durable하게 저장하고 동일 값을
  `next_read_window(&persisted_marker)`에 제출해야만 path가 공개된다. 첫 read 뒤
  proof/window/stash/plan 오류는 transaction을 poisoned로 만들며 기존 checkpoint
  재사용을 금지한다. Marker의 `attempt_digest`는 exact checkpoint, point,
  candidate/remap/padding schedule을 바인딩하므로 같은 mutation metadata를 재사용한
  다른 plan이 기존 marker로 path를 공개할 수 없다.
- 기존 V2 recovery marker와 HNSW V2 attempt/prepared digest domain은 wire/storage
  호환성을 위해 그대로 유지한다. 활성 HNSW/result transaction은 index kind/name을
  포함하는 V3 marker와 V3 attempt digest domain을 사용한다. V3 prepared digest
  domain도 호환성 known-answer로 보존하지만, 활성 finalize 출력은 canonical source
  checkpoint digest까지 인증하는 provider별 V4 prepared-commit domain을 사용한다.
  Checkpoint, graph delta, HNSW/result client state는 JSON serialization이 아니라
  명시적 length-prefix, fixed-width big-endian scalar, option/enum tag로 canonical
  digest를 계산하며 client-state map/stash 순서는 keyed state로 정규화한다.
- Legacy V2 HNSW `window_issued` marker는 exact pending window에 한해
  `next_read_window_v2`로 1회 resume하며, 반환 request부터 V3 marker로 전환한다.
- Window 적용은 cloned working set에서 원자적으로 수행하고, finalizer는 exact
  frame 수, proof coverage, stash bound와 full-recompute-compatible root를 다시
  확인한다. 출력의 V4 `prepared_commit_digest`는 attempt, canonical source
  checkpoint, old/new epoch와 root, read transcript, ordered writeback, next client
  state와 graph delta를 바인딩한다. 이 marker는 server CAS와 새 encrypted
  checkpoint 영속화 전에는 제거하지 않는다.

##### V2-D1-D: Paired result append and D0 finalizer

###### V2-D1-D1: Verified fixed-window result append transaction

- 완료: `PrivateOramAppendResultTransactionV2`가 paired private-result topology에서
  insert 1회와 manifest-fixed padding path를 소유한다. 각 read response는 pinned
  old epoch/root와 exact ordered root-to-leaf sequence에 검증하며 shared ancestor
  occurrence를 합치지 않는다.
- 완료: 이전 path의 plaintext overlay를 우선 적용하고 매 occurrence를 새 epoch로
  reseal한다. Ordered ciphertext frame과 bucket별 last value를 함께 보존하고 sparse
  Merkle patch 결과를 full commitment-vector recomputation과 비교한다.
- 완료: payload/point duplicate와 oversized payload는 첫 read 전에 거부한다.
  Within-window duplicate path는 fail closed이고 later-window 동일 leaf는 허용한다.
  전체 fixed-window schedule은 `begin`에서 사전 검증해 malformed later window도
  첫 marker/path 공개 전에 거부한다.
  Correct-cardinality response는 manifest ciphertext encoded-size를 body decode 전에
  제한하고, verifier는 unchanged older-epoch bucket을 허용하면서 hash/commitment/
  proof와 current-epoch upper bound를 검증한다.
  두 번째 path operation 실패 fixture는 position map, stash, overlay와 ordered frame
  전체를 포함한 canonical working-artifact digest가 window 시작 값으로 원복된 뒤
  attempt가 poisoned 되는지 검증한다.
- 완료: result attempt digest는 checkpoint/point/fixed schedule을 바인딩하고,
  prepared digest는 result ledger record, old/new root와 epoch, transcript,
  ordered writeback과 next result state를 추가로 바인딩한다. HNSW prepared digest도
  V3에서 graph delta를 포함하며 legacy V2와 V3 digest는 변경하지 않았다. 활성
  HNSW/result finalize는 source checkpoint digest를 추가로 바인딩하는 V4 prepared
  domain을 사용한다. Legacy V2, 호환 V3, active V4 encoding은 known-answer test로
  고정했다.
- 완료: result prepared-output validator가 ordered raw ciphertext의 fixed size/hash/
  commitment/context, writeback ref, bucket별 last-occurrence final image, transcript,
  transcript-derived bucket frame, 포함된 old-tree Merkle patch proof/new root,
  next client state와 prepared digest를 재검증한다. `finalize`는 반환 전에 이
  validator를 반드시 통과하며 body/frame/proof/root/transcript 변조 회귀 테스트가
  이를 고정한다.

###### V2-D1-D2: Paired checkpoint ledger and encrypted reseal

- 완료: paired checkpoint planner가 HNSW graph point/record/new block과 result
  record의 point/payload token을 exact-match한다. 새 record generation은 1,
  reciprocal rewrite는 기존 ledger identity/vector/level을 보존하면서 generation만
  정확히 1 증가해야 한다.
- 완료: point/HNSW/result ledger는 raw 32-byte point/node/payload token 기준
  canonical 순서로 함께 전진한다. HNSW entry, 두 position-map/stash snapshot,
  epoch/root, logical/dummy count와 last-writeback digest를 하나의
  `state_sequence + 1` checkpoint에 적용한 뒤 전체 checkpoint validator를 다시
  통과한다.
- 완료: 두 prepared output은 공통 canonical `source_checkpoint_digest`를 내보내며
  각 provider별 V4 prepared-commit digest가 그 값을 인증한다. Paired planner는 같은
  source checkpoint, mutation, old state, writer lease/fence를 요구한다. 직전
  mutation id 재사용과 zero identity, partial index advancement는 fail closed다.
- 완료: reseal wrapper는 caller가 준 plaintext checkpoint를 신뢰하지 않고 old
  signed-state의 `client_state_digest/state_digest`에 결합된 encrypted checkpoint를
  인증·복호화한다. 그 exact plaintext를 검증·봉인하고 sealed ciphertext digest를
  새 signable `PrivateOramSignedStateV2.client_state_digest`에 넣은 다음 outer
  state binding을 생성하고 즉시 재개봉해 equality를 확인한다.
- 완료: checkpoint seal은 randomized이므로 반환된 ciphertext/state payload를
  하나의 durable pending artifact로 저장하고 CAS retry에서 그대로 재사용해야 한다.
  같은 logical delta를 다시 seal하면 다른 client-state/state digest가 만들어진다는
  회귀 테스트가 이 계약을 고정한다.
- 완료: Ed25519 state bundle과 mutation signature는 D1-D3 finalizer가 생성한다.

###### V2-D1-D3: Signed mutation finalizer and aggregate self-validation

- 완료: HNSW output이 old-tree Merkle patch proof를 보존하고, public self-validator가
  body decode 전 exact encoded size, AEAD framing, hash/commitment/ref, transcript
  derived frame, last-occurrence final image, sparse patch/new root를 result validator와
  같은 수준으로 검증한다.
- 완료: HNSW graph delta는 block version/nonzero identity/generation/F32 dimension과
  finite encoding, level-0 neighbor/rewrite identity, 기존 level-0 또는 새 node로
  제한된 edge transition, generation/upper-edge 보존, fixed
  candidate/rewrite/padding budget을 V4 digest와 별도로 검사한다. Next client
  state와 checkpoint ledger도 replacement edge target의 존재를 확인하고,
  manifest block shape, stash bound와 new/entry/selected/rewrite position을
  검사한다. Finalize는 이 validator 통과 전 output을 반환하지 않는다.
- 완료: paired finalizer가 trusted owner public key와 manifest/old-state signature,
  pinned collection/manifest/layout/sequence/state digest, writer lease/fence를 먼저
  확인한다. D1-D2 reseal을 정확히 한 번 수행한 뒤 새 state bundle,
  `no_server_point_record` digest, manifest-order writeback과 D0 mutation signature를
  만든다.
- 완료: finalizer는 `validate_private_oram_append_mutation_v1` 전체 검증과 signed
  new state 기준 checkpoint exact reopen을 모두 통과한 경우에만 prepared HNSW/result
  output, randomized encrypted checkpoint와 mutation bundle을 하나의 aggregate로
  반환한다. CAS retry는 이 aggregate를 durable하게 저장하고 그대로 재사용한다.
- 현재 self-check의 observed transcript는 prepared client output에서 온다.
  D3-B3-B1 owner-prepare admission은 raw transcript DTO를 받지 않고, server append
  session의 non-serializable capability recorder가 실제 accepted read window에서 발급한
  evidence만 받는다. D4는 그 recorder를 실제 read handler/session registry에 연결한다.
- Storage/consensus/public route는 D2-D4 전까지 dormant 상태를 유지한다.

#### V2-D2: Dormant collection-wide consensus primitive

- 완료: Persistent consensus state에 versioned collection record를 추가했다. Stable
  collection identity, manifest/layout, state sequence와 signed/client-state digest,
  canonical ordered HNSW/result epoch/root/writeback/occupancy set, tagged
  `Genesis | Mutation(exact receipt)`를 함께 저장한다.
- 완료: Receipt transition digest는 complete old record digest, receipt를 제외한 new
  state core digest, transition digest를 제외한 receipt core에서 재계산한다. Domain과
  field order는 known-answer regression으로 고정하고 nested V2 field는 required 및
  unknown-field reject로 유지한다.
- 완료: Optional lease map 대신 enrolled collection마다 삭제되지 않는 generation
  slot을 둔다. Acquire마다 generation과 max writer fence를 함께 증가시키며,
  `Preparing | ConsensusCommitted` active phase와 typed abort/finalize clear tombstone를
  보존한다. Expiry만으로 takeover하지 않고 stale vacant generation acquire를 거부해
  `None -> lease -> None` ABA를 막는다.
- 완료: `ApplyPrivateOramMutation` first-apply는 exact preparing lease와 old/new state를
  검증한 뒤 모든 HNSW/result epoch, collection state, layout index-state digest와
  committed lease phase를 한 번의 `Persistent::save()`로 전진시킨다. 각 index는 epoch
  +1, changed root/writeback, logical +1, dummy -1, fixed total capacity를 강제한다.
- 완료: Exact current new-state replay는 save나 lease mutation 없이 성공한다. Clear
  이후나 다음 mutation이 Preparing인 동안에도 latest-state replay가 유지되지만,
  후속 commit이 receipt를 교체하면 이전 retry는 stale이다. Perpetual historical
  receipt ledger는 v2 범위가 아니다.
- 완료: Enrollment는 standalone v1 epoch/layout mutation과 새 v1 search-session lease를
  막는다. Mutation acquire와 external recovery/session은 consensus apply 지점에서
  양방향으로 충돌하고 transfer/reshard는 enrolled layout CAS에서 fail closed 한다.
- 완료: Raft snapshot은 active preparing/committed slot을 차단하지 않고 그대로
  포함한다. Legacy snapshot은 두 top-level map 부재를 non-enrolled로 decode하며, V2
  state/slot/layout/epoch mismatch, rogue slot owner, active session/recovery overlap은
  reject한다. Startup command-line snapshot restore는 persisted active mutation을
  거부한다.
- 완료: State/slot/receipt/operation/Persistent/SnapshotData Debug와 consensus WAL log
  projection은 collection/index/root/mutation/client-state digest를 redaction한다.
- 유지 조건: D2 operation은 consensus state-machine/WAL decode에만 존재하며 Dispatcher
  proposal method와 public route를 제공하지 않는다.
- 완료(D3-A): `Persistent::save()`를 temp create/serialize/file-fsync의 definitive
  failure와 atomic publish/parent-fsync의 indeterminate failure로 분리했다. Publish 뒤
  오류는 target SHA-256이 candidate와 같을 때만 parent fsync를 세 번까지 재시도해
  success로 복구한다. 그 외에는 memory rollback 없이 process-local poison을 세우고
  fixed `ServiceError`로 consensus loop를 중단한다. Restart는 미적용 committed-entry
  queue에서 old/new durable image 모두 exact replay한다 (`DUR-003`).
- 완료(D3-B1): Collection-local parent mutation journal이 exact signed mutation,
  preparing lease, complete old consensus record와 canonical owner/index requirement를
  immutable descriptor로 고정한다. 아래 7단계 증거는 previous-record-linked current
  state로 저장하며 exact retry만 허용한다.
- 활성화 전 남음: D3-B3가 실제 child owner journal의
  signature/proof/durability evidence를 검증하고 point stage를 publish/abort/reconcile한
  뒤, D4 state-aware search writeback 및 consensus snapshot/lifecycle reservation이
  모든 race를 닫은 경우에만 proposal admission을 추가한다 (`ARCH-022`).

#### V2-D3: Durable prepare/finalize

- 완료(D3-A): Raft persistent image는 destination parent의 named temp file에 JSON을
  serialize하면서 digest를 계산하고 file fsync 뒤 atomic publish, parent-directory
  fsync 순으로 저장한다. Publish 오류는 보수적으로 indeterminate이며, exposed target이
  exact candidate일 때만 parent fsync retry로 확정한다. Exhausted/changed outcome은
  poisoned consensus save gate가 restart 전까지 모든 후속 save를 거부한다.
- 완료(D3-A): Transactional private ORAM state 변경은 definitive failure에서만 old
  in-memory maps를 복원한다. Indeterminate outcome은 new memory image를 유지하고 entry를
  applied 처리하지 않는다. Fault fixture는 old-disk/new-memory restart replay,
  rename-ahead recovery, parent-fsync retry/exhaustion을 고정한다.
- 완료(D3-B1): `private_oram_mutations/{active,temp,journal.lock}` parent journal을
  추가했다. Immutable descriptor는 exact signed mutation bundle, canonical mutation
  digest, preparing D2 lease, non-genesis receipt를 포함한 exact old consensus record,
  coordinator와 canonical owner/index cross-product를 묶는다. Descriptor/state
  digest encoding은 known-answer test로 고정한다.
- 완료(D3-B1/D3-B2-B): Parent state는 `LeaseAcquired -> OwnersPrepared -> PointStageDurable ->
  ConsensusCommitted -> RemotesFinalized -> LocalFinalized -> Complete`의 exact
  7단계만 허용한다. Point-operation digest와 committed receipt/record/transition은
  signed mutation 및 D2 state에서 재계산하며 remote-before-local 순서를 강제한다.
  State publish는 file fsync, atomic replace, parent fsync 순서이고 pre/post-publish
  오류와 exhausted parent-fsync를 definitive/indeterminate로 분류한다. Owner-only
  non-symlink layout, bounded files, same-file 검사와 redacted Debug/Error를 적용했다.
- 완료(D3-B2-A): `qdrant-sec` canonical InsertOnly frame은 collection/mutation/state,
  writer lease/fence, canonical shard route, point id, payload와 empty server-vector set을
  strict binary codec으로 묶는다. 64 MiB hard limit, exact decode/re-encode, frame digest,
  mutation point-operation digest와 known-answer vectors를 고정했다.
- 완료(D3-B2-B): Collection-local `private_oram_point_staging/active`에 descriptor,
  canonical frame과 Prepared-only state를 owner-only bounded files로 fsync한다. Child
  descriptor는 exact parent descriptor와 `OwnersPrepared` record digest를 묶고,
  parent는 child가 발급한 opaque durable token으로만 `PointStageDurable`에 CAS한다.
  Linux `renameat2(RENAME_NOREPLACE)`, pinned root-directory fsync, post-install reopen,
  no-follow/same-inode/link-count/mode 검증을 사용한다. Rename 전 crash가 남긴 private
  sibling candidate는 채택하거나 삭제하지 않고 무시하며 unknown/symlink entry는
  fail closed 한다 (`DUR-002`).
- 유지 조건(D3-B2): Frame file은 자체 AEAD store가 아니며 visible point id/payload
  bytes를 포함할 수 있다. D4 admission이 collection payload policy를 적용한 뒤에만
  호출해야 하고 host filesystem은 owner-only local Linux storage, durable file/directory
  fsync와 `RENAME_NOREPLACE`를 제공해야 한다. Private vector bytes는 항상 거부하며,
  D3-B3/D4 전까지 이 primitive는 dormant다.
- 완료(D3-B3-A1): Parent descriptor에서 exact new consensus record를 다시 만들고 현재
  collection record와 active lease slot을 함께 분류하는 validated reconciliation context를
  추가했다. Generation/max-fence, immutable lease identity, renewal monotonicity, parent phase,
  recorded committed renewal을 묶는다. Exact new + `ConsensusCommitted`만 finalize authority다.
  Unrelated state, old+committed, new+preparing, missing/cleared/ABA slot은 fail closed 한다.
- 유지 조건(D3-B3-A1): Exact old + `Preparing`은 현재 관찰값일 뿐 abort authority가
  아니다. Submit timeout 뒤 지연된 Raft entry가 적용될 수 있으므로 결과 이름도
  `ObservedOldNeedsAbortDecision`으로 고정했다.
- 완료(D3-B3-A2): Consensus lease에 unit `AbortDecided` phase를 추가하고 기존 Raft
  lease CAS 안에서 exact old state와 동일 active generation의
  `Preparing -> AbortDecided`만 선형화한다. Lease identity/generation/max-fence/last-clear와
  expiry/renewal revision은 decision 중 바꿀 수 없고, idempotent replay도 현재 state-slot
  관계를 다시 검증한다. `Preparing -> clear`와 terminal phase escape는 거부하며,
  `AbortDecided` 상태에서는 cleanup용 동일-phase renewal만 허용하고 mutation apply를
  거부한다. Parent classifier는 이 조합만 `ExactOldAbortDecided` abort authority로 낸다.
- 유지 조건(D3-B3-A2): `AbortDecided`는 Raft payload, persistent image와 snapshot에
  나타나는 새 serde variant다. 모든 peer가 이 phase와 강화된 clear 규칙을 지원한다는
  cluster capability gate 전에는 operation을 제안하지 않고, active/in-snapshot phase가
  남아 있는 동안 downgrade를 금지한다 (`ARCH-024`). Proposal timeout 뒤 local getter만
  보고 abort하지 않으며 같은 CAS의 Raft apply barrier와 한 read guard의 state-slot
  snapshot을 거친다.
- 완료(D3-B3-A3-ParentOwnerRecoveryAuthority): ConsensusManager가 collection state와 mutation
  lease slot을 하나의 persistent read guard 아래 opaque snapshot으로 캡처하고, parent journal은
  이 provenance 타입만 받아 per-owner restart authority를 만든다. Raw state/slot validator는
  module-private로 좁혔다. Authority는 parent descriptor, stable LeaseAcquired/OwnersPrepared
  record, exact old 또는 committed-new consensus record, immutable lease identity와 phase,
  authenticated owner peer, canonical owner requirement/Prepared digest, signed mutation bundle을
  domain-separated digest로 묶는다. Mutable parent tip, lease expiry와 renewal revision은 replay
  identity에서 제외하되 mint 시 monotonic validation은 유지하므로 same-phase renewal과 parent
  phase 진전 뒤에도 digest가 안정적이다. Unknown owner와 OwnersPrepared 이전 parent는
  fail closed 하고 KAT/debug-redaction test를 고정했다.
- 유지 조건(D3-B3-A3): `authenticated_owner_peer_id`는 request body가 아니라 local receiver
  identity 또는 인증된 transport destination에서 주입해야 한다. Parent의 raw
  `prepared_journal_digest`는 child durability proof가 아니므로 이 authority만으로 owner
  token이나 terminal record를 발급하지 않는다. Exact child 재결합도 public projection을
  authority로 취급하지 않으며 storage-private typed parent authority를 계속 보유한
  coordinator만 이후 recovery disposition을 선택해야 한다.
- 완료(D3-B3-B1): Client aggregate에서 server-safe owner-prepare wire package를 투영한다.
  Wire에는 signed mutation bundle, manifest-order ordered encrypted bucket bodies와 sparse
  Merkle patch proof만 들어가며 checkpoint, position map/stash, graph delta, result record,
  recovery marker, final client state와 read transcript claim은 들어가지 않는다. Validator는
  server append session의 non-serializable capability recorder와 같은 identity의 read
  evidence만 수락하고 foreign recorder evidence를 거부한다. Signed occurrence와 body를
  collapse 전에 순서대로 대조하고 HNSW/result fixed ciphertext size, hash, commitment와
  inner AEAD version, proof의 exact sorted unique leaf set, old-to-new sparse Merkle transition을
  검사한 뒤 bucket-id 순 last-occurrence final image를 opaque validated token으로 만든다.
- 유지 조건(D3-B3-B1): Recorder/evidence는 wire나 durable DTO가 아니며 server process의
  append session에서만 산다. Restart로 capability가 사라지면 owner prepare 전 read를 다시
  수행한다. D4가 recorder를 실제 accepted read-window log에 연결하기 전에는 public
  admission을 열지 않는다. Transport hard body limit도 deserialization 전에 별도로 필요하다.
- 완료(D3-B3-B2-Prepared): Primary HNSW store의 기존 `temp` gate 아래 paired V2 owner
  journal을 추가했다. Immutable descriptor는 exact parent descriptor/lease record와 owner,
  mutation/lease/fence, manifest-order signed occurrence 전체와 read transcript, bucket-ID-sorted
  last-occurrence final refs를 묶고 encrypted HNSW 및 optional result final bucket frame을 함께
  보존한다. Candidate file/temp/active/root fsync, Linux `RENAME_NOREPLACE`, root exclusive
  advisory lock, pinned candidate/installed inode와 post-fsync exact byte/entry-set 검증 뒤에만
  exact prepare/replay가 crate-private durable token을 발급한다. Structural inspection은
  self-consistent snapshot만 반환하며 evidence token을 만들지 않는다. Unknown entry,
  symlink/hardlink/bad mode, stale/tampered bytes는 fail closed 하고 canonical index 파일은
  prepare에서 수정하지 않는다 (`ARCH-023`).
- 유지 조건(D3-B3-B2-Prepared): 이 primitive는 owner-only local Linux filesystem,
  mounted procfs fd-relative access, durable file/directory fsync와 모든 journal writer의
  advisory-lock 준수를 요구한다. Token minting API는 D3-B3-B3의 typed parent state,
  authenticated peer identity와 연결될 때까지 crate-private/dormant다.
- 완료(D3-B3-B2-TerminalRecord): Prepared state를 덮어쓰지 않는 sequence-2
  `Finalized | AbortedOld` terminal record를 phase별 canonical domain으로 추가했다. Record는
  owner descriptor와 Prepared state digest, immutable parent descriptor, authenticated owner
  peer, stable consensus/reconciliation authority digest, descriptor 순서의 per-index canonical
  state digest를 함께 묶는다. Terminal candidate는 active temp 아래에서 file/directory fsync
  후 cross-directory `RENAME_NOREPLACE`로 설치하며 candidate/installed inode continuity,
  terminal/temp/active/root fsync, exact reread와 replay equality를 검증한다. Structural
  inspection은 shared root lock으로 writer와 직렬화되고 terminal token을 발급하지 않는다.
- 유지 조건(D3-B3-B2-TerminalRecord): Raw terminal context와 record method는 module-private라
  production caller가 임의 authority digest로 terminal token을 만들 수 없다. Stable
  consensus authority를 사용하며 전진하는 parent current-record digest는 replay identity로
  사용하지 않는다.
- 완료(D3-B3-B2-StoreInspector): HNSW/result canonical store에 module-private exact-old와
  exact-new verifier를 추가했다. Signed store manifest/runtime context, current epoch, 전체
  Merkle leaf vector/root/count, epoch directory와 target commit, mutation-affected bucket body의
  fixed size/hash/commitment/leaf를 root exclusive lock 아래 두 번 읽어 검증한다. Exact-old는
  new commit 부재와 digest-bound old commit 또는 signed initial-manifest anchor를 요구하고,
  exact-new는 digest-bound new commit과 expected final bucket full-body equality를 요구한다.
  Phase별 domain의 canonical-state digest는 owner journal descriptor, Prepared digest,
  immutable-manifest digest, index kind/name, signed store-manifest message, old/new state, commit
  kind, final refs와 observed affected bodies를 묶는다. Token 수명은 held lock보다 길 수 없고
  raw context, lock과 verifier entry point는 module-private다. Legacy pending, future/malformed
  commit entry, hardlink/symlink/inode drift와 bounded-read 초과는 fail closed 한다.
- 유지 조건(D3-B3-B2-StoreInspector): 이 token은 complete Merkle leaf state와
  mutation-affected bucket body의 canonical logical-state evidence이며 unrelated bucket body의
  availability proof는 아니다. Initial upload/restore가 전체 store를 검증하고 이후 모든 V2
  writer가 full bucket/Merkle invariant를 보존한다는 귀납 조건이 필요하다. Writer-wide 동일
  lock은 연결됐지만 child/store의 fd-relative pinned namespace가 완성될 때까지 production
  minting 경로를 열지 않는다.
- 완료(D3-B3-B2-StoreAdapter-LivePair): 진짜 durable Prepared token을 현재 journal의 exact
  Prepared snapshot에 다시 결합하고, immutable manifest, append mutation, old/new state의
  signature와 digest/identity/order를 재검증한 뒤 signed V2 immutable index를 physical V1
  HNSW/result manifest에 의미적으로 매핑하는 crate-private adapter를 추가했다. Adapter는
  HNSW -> result -> journal shared lock 순서 아래 두 StoreInspector를 소비하고 all-old 또는
  all-new일 때만 callback-scoped opaque pair token을 발급한다. Mixed old/new, foreign
  journal/collection path, signature substitution, signed/physical manifest mismatch는 callback
  전에 fail closed 한다. 7개 집중 test가 exact-old/new, mixed state, substitution과 debug
  redaction을 고정한다. Production call site와 terminal 호출은 아직 없다.
- 완료(D3-B3-B3-ChildPreparedRebind): Storage-private parent recovery authority가 정확히 같은
  authenticated owner의 canonical `Hnsw, Result` requirement/Prepared pair만 immutable public
  projection으로 투영한다. Collection은 이 projection을 untrusted input으로 취급하고 exact
  child journal을 shared root lock 아래 다시 열어 nonterminal Prepared state, parent/lease,
  mutation/lease/fence, index order/epoch/root/writeback과 모든 per-index Prepared digest를
  descriptor에서 재계산해 비교한다. Opaque binding은 실제 lock lifetime에 묶인 non-Clone
  crate-private callback value이고 capability accessor도 제공하지 않아 storage나 public
  caller가 잠금 밖으로 추출할 수 없다. HNSW-only,
  terminal child, owner/parent/mutation/index/digest substitution과 callback 중 terminal publish를
  fail closed 하는 집중 test를 추가했다. Store lock을 child lock 안에서 취득하도록 유도하던
  draft bridge는 lock inversion을 피하기 위해 제거했다.
- 완료(D3-B3-B3-ReadOnlyClassifier): Storage-private wrapper가
  `&PrivateOramValidatedOwnerRecoveryAuthorityV1`에서 projection을 만들고 public-hidden
  collection facade는 inert `AllOld | AllNew | PartialNew | ThirdState` observation만 반환한다.
  Static signed/path validation 뒤 HNSW -> result -> child journal shared 순서로 lock을 잡고,
  exact child의 untrusted structural view 안에서만 store authority를 파생한다. Store별 `Third`는
  validated current epoch/root가 old/new 어느 쪽도 아닐 때만 허용한다. Exact old/new pointer가
  manifest/commit/Merkle/bucket 검증에 실패하면 `Third`로 숨기지 않고 error로 fail closed 한다.
  `Old+Old=AllOld`, `New+New=AllNew`, canonical prefix `New+Old=PartialNew`, 나머지는
  `ThirdState`이며 3x3 matrix, 양쪽 store의 네 종류 corrupt evidence, HNSW/result/child-lock
  contention과 error 뒤 lock release, debug redaction test를 추가했다. Store/child token과 lock
  guard는 facade 밖으로 나오지 않는다.
- 완료(D3-B3-B3-WriterSerialization): HNSW/result canonical writer 전체를 각 owner-root
  exclusive lock에 편입하고 public writer는 잠금 없는 private implementation만 호출하도록
  정리했다. Common initial upload도 bucket별 재잠금 대신 전체 bucket set과 Merkle image를 한
  owner lock에서 preflight하고 설치한다. Exact-old/new callback 뒤 root identity를 다시
  검증하며, 동일 수준의 filesystem lock을 보장하지 못하는 non-Linux canonical writer는
  mutation 전에 fail closed한다. StoreInspector와 writer가 이제 같은 lock discipline을
  공유하지만 child/store 내부 파일 조작은 아직 pathname 기반이다.
- 완료(D3-B3-B3-LiveParentFoundation): Storage parent journal root와 lock file을 directory
  FD에 pin하고, consensus/lease snapshot과 parent descriptor/state를 callback 전후 exact
  재검증하는 non-Clone live authority를 추가했다. Callback 중 parent root 교체는 pinned read와
  pathname identity recheck로 거부한다. 이 callback은 아직 parent state를 변경하지 않으며,
  active child directory와 terminal publication은 후속 fd-relative mutating transaction 범위다.
- 남음(D3-B3-B3-AtomicRollForwardTerminal): 현재 classifier 원자성은 같은 owner store lock을
  사용하는 writer와 직렬화되지만 child/store directory의 pathname ABA를 막지 못한다.
  fd-relative pinned namespace와 child exclusive binding이 완성되기 전에는 production
  activation이 금지된다. Owned parent recovery authority는 read-only observation에는 충분하지만
  mutation authority가 아니므로, roll-forward/terminal은 parent live revalidation을 포함한
  `parent -> HNSW -> result -> child exclusive` transaction을 별도로 사용해야 한다. Shared child
  lock의 lock upgrade나 반환된 disposition 재사용은 금지한다.
  Partial-new는 fixed HNSW-prefix roll-forward 뒤 같은 transaction에서 `AllNew`를 재검증한
  경우에만 terminal evidence를 만들 수 있다. Authority -> projection -> real child -> real
  pair classifier cross-crate integration test도 activation 전에 추가한다.
  이 transaction에서 exact pair token을 module-private terminal recorder에 직접 소비시키는
  bridge도 필요하다. Legacy HNSW/result pending
  journal은 digest domain, duplicate-bucket model과 signature contract가 달라 V2 authority나
  evidence로 재사용하지 않는다.
- 남음(D3-B3-B3): HNSW/result owner record를 pair로 inspect하고 peer/parent requirement와
  exact terminal authority를 검증해 parent journal에 opaque evidence를 공급하는 internal
  RPC와 adapter가 필요하다.
- 완료(D3-C2-ParentStateWriter): V1과 wire-compatible하게 섞지 않는 fresh V2 parent writer를
  추가했다. `format.json`, sequence별 immutable record, current pointer를 분리하고 immutable
  record의 no-clobber publish와 directory fsync 뒤에만 pointer를 전진시킨다. Pointer 이전 crash로
  next record 하나가 남아도 structural load는 자동 채택하지 않으며 같은 phase-specific typed
  evidence를 다시 제출한 경우에만 roll-forward한다. V1-only active는 explicit legacy recovery로
  분리하고 mixed layout, history gap, pointer-ahead, 다른 pending evidence는 fail closed한다.
  Decision token은 한 consensus read guard에서 캡처한 state/lease와 실제 durable
  `PointStageDurable` predecessor digest에 묶인다. Test-only visible-point validator는 non-Clone
  durable token을 exact 비교하지만 token 자체는 live guard가 아니므로 production 연결 시 staged
  child store를 같은 lock window에서 다시 열어야 한다. Decision 기록은 그 phase record에
  묶인 별도 non-Clone token을, remote terminal 기록은 다시 `RemotesTerminal` record에 묶인 token을
  반환하며 다음 writer는 바로 이전 phase token만 받는다. Empty remote batch도 decoded disk state를
  authority로 사용하지 않는다. Pending/history 파일은 레코드별 structural validation, 7-entry
  iteration cap, 256 MiB aggregate cap, race-growth bounded read를 통과해야 한다. Exact pending
  retry도 immutable publisher를 다시 실행해 records/temp directory fsync를 재확립한 뒤 pointer를
  전진시킨다.
- 완료(D3-C2-PointResolutionWriter): Point-stage prepare/load/live reopen을 owner-only
  `stage.lock`으로 직렬화하고 Linux directory FD에 root를 고정했다. Callback-scoped live authority
  밖으로 frame/token을 이동할 수 없으며 unsupported platform은 authority 생성 전에 fail closed한다.
  `LocalTerminal` writer는 exact sequence-6 record에 묶인 non-Clone token을 반환하고,
  no-server-point path는 그 token만 소비해 sequence 7 `PointResolved`를 기록한다. Visible-point raw
  receipt sink와 child-consuming callback은 test-only로 닫았다. Exact sequence-7 retry는 disposable
  child가 이미 정리됐어도 durable parent evidence만으로 성공하고 다른 receipt는 거부한다. State
  pointer, immutable successor record, point-stage active publish 뒤 readback/root/fsync 실패는 모두
  `Indeterminate`로 분류한다. Empty payload는 dormant staged-frame V1에 production deployment 이력이
  없다는 전제 아래 `None` 하나만 canonical하게 허용하며 pre-activation fixture는 activation 전에
  폐기하거나 명시적으로 migration해야 한다.
- 완료(D3-C2-TerminalCoordinator): Original lease owner가 follower여도 exact slot 확인 Raft
  operation을 먼저 commit하고 한 persistent read에서 state, slot, parent watermark, recovery
  certificate, activation locator와 cleanup lifecycle을 캡처한다. Opaque resume facade는 seq3-7을
  한 단계씩만 진행하고, 각 local record가 다음 side effect 전에 consensus parent watermark에
  반영되도록 강제한다. Remote terminal은 configured signer pair와 authenticated peer transport를
  검증한 뒤 fresh authority로 다시 확인하며, local terminal은 paired HNSW/result recovery를 같은
  signed mutation context에서 수행한다.
- 완료(D3-C2-NoServerPointResolution): Strict V2는 no-server point record만 sequence 7로
  resolve한다. `ids_visible`은 admission과 restart resume 모두에서 side effect 전에 거부한다.
  Visible point publish/abort의 all-Active replica roster와 authenticated semantic readback은 이
  provider의 활성 범위가 아니며, 향후 별도 protocol 없이는 열지 않는다.
- 완료(D3-B3-C-StrictCleanup): Sequence 7 terminal watermark, exact decided lease, consensus
  state와 owner/point terminal evidence에서 domain-separated cleanup expectation을 만든다. Raft
  cleanup witness 뒤 process-local paired session을 해제하고 `cleanup_complete_v2.json`을 fsync한
  다음 clear-pending과 exact-generation clear만 허용한다. Cleared-pending tombstone에서만 opaque
  archive permit을 만들고 `active`를 no-replace terminal archive로 이동/검증/fsync한 뒤 clear
  acknowledgement를 제출한다. Acknowledgement 전에는 다음 generation admission이 계속 막히며,
  terminal archive와 recovery capsule 물리 GC는 보존 정책상 V2-E 이후로 미룬다.
- 완료(D3-B3-C-LocalApplyBarrier): Follower가 leader에 exact-slot confirmation을 전달한 경우에도
  confirmation entry의 local apply receipt/index를 받은 뒤에만 persistent snapshot을 읽는다.
  Snapshot의 `last_applied`가 receipt보다 뒤인지 같은 read guard에서 확인하므로 committed-but-local-
  stale authority로 filesystem 또는 remote side effect를 시작하지 않는다.
- 완료(D3-B3-C-ExecutionQuiescence): Terminal resume와 archive/ack coordinator는 collection key별
  process mutex로 직렬화된다. Cleanup은 exact generation을 claim해 새 session/job 획득과 phase
  mutation을 막고 worker liveness 종료를 기다린 뒤 paired session을 해제한다. 같은 process에서
  관찰했던 job이 tombstone 없이 사라지면 fail closed하고, restart 뒤 처음 보는 absence만 restart
  quiescence로 인정한다. Restart absence는 storage-root peer identity directory의 process-lifetime
  exclusive `flock`을 보유한 identity capability가 있어야만 인정한다. Quiescence permit과 tombstone은
  collection, mutation ID, immutable owner, generation, process incarnation과 exact cleanup evidence
  digest 전체에 묶이며 cross-key/same-generation 재사용을 거부한다. Session open reservation/install과
  cleanup claim/final tombstone은 같은 registry mutex에서 선형화된다. Reservation이나 active session이
  먼저 보이면 cleanup이 거부되고, cleanup claim이 먼저 보이면 install이 거부되며, final tombstone
  직전에도 reservation/session/job 부재를 다시 확인한다.
- 완료(D3-B3-C-AtomicPublication): Cleanup marker와 terminal archive receipt는 private temp file의
  bounded canonical write/file fsync, `RENAME_NOREPLACE`, destination/temp parent-directory fsync,
  exact installed-byte reread 순서로 publish한다. Archive는 rename 전에 exact source generation,
  descriptor, terminal record, cleanup marker와 tombstone binding을 재검증하고 root directory를
  fsync한다. Rename 뒤에는 destination directory를 다시 열어 pre-rename source FD와 `(dev, ino)`가
  같은지, active source 이름이 사라졌는지, canonical terminal bytes가 같은지 확인한 뒤에만 receipt를
  publish한다. Rename 뒤 directory fsync 전 failpoint와 exact retry가 marker/receipt 모두에서
  수렴하는 regression으로 고정됐다.
- 완료(D3-B3-C-ImmutableOwnerOperations): Original lease owner가 300초 동안 동일 foreign pending
  generation으로 관찰되면 durable protocol은 `Pending`을 유지하되 operational status는
  `Blocked: ImmutableCoordinatorUnavailable`로 전환한다. 이 상태는 takeover를 허용하지 않으며
  node-wide readiness를 실패시키지 않는다. Consensus/reconcile failure의 `Blocked`는 계속 readiness를
  실패시킨다.
- 완료(D3-B3-C-NextAdmissionGCTransfer): Clear acknowledgement 뒤 남은 exact recovery/terminal
  certificate pair는 다음 reservation 동안 보존되고 admission에서 acknowledged GC obligation으로
  원자적으로 이전된다. Partial certificate, pending tombstone, mismatched generation은 reservation
  전에 fail closed한다.

#### V2-D4: Dedicated API activation

- 완료: Public route는 collection-wide
  `/collections/{collection}/private-oram/v2/mutation/{open,append,status,close}`로
  분리됐고, mutation/session id와 encrypted bodies를 URL/log에 넣지 않는다. REST `u64`는
  canonical decimal string으로 encode/decode한다.
- 완료: Route별 finite JSON body, fixed read/write budget, ciphertext hash/commitment와 signed
  owner-prepare 검증을 admission 전에 수행한다. Detached append job은 bounded registry를 쓰고,
  terminal ownership을 supervisor에 넘긴 뒤 cleanup witness에서 underlying session을 해제한다.
- 완료: Internal gRPC는 owner reservation prepare/resolve, prestage/adopt와 authenticated terminal
  recovery를 paired mutation identity에 결합한다. Existing index별 generic writeback은 V2
  collection-wide consensus mutation을 대신할 수 없다.
- 완료: Active mutation/recovery/session은 private search, ordinary point mutation,
  snapshot, transfer/reshard와 lifecycle operation의 기존 fail-closed guard를 유지한다.

#### V2-D5: Recovery, leakage and process gates

테스트:

- Canonical manifest/state/mutation known-answer vector와 tamper matrix를 고정한다.
- HNSW-only와 paired HNSW/result append, duplicate token/mutation id, capacity/stash
  overflow, stale state sequence, partial prepare/finalize를 검증한다.
- CAS 전후 crash matrix에서 old 또는 new point/index/client checkpoint 전체만
  선택되는지 검증한다.
- Insert별 path/response/writeback 크기가 inserted node level과 neighbor count에
  무관하게 고정되는지 leakage fixture로 고정한다.
- Legacy consensus snapshot에는 v2 field가 없어도 load되고, v2 snapshot은 pending
  mutation 없이 complete state/receipt만 round-trip하는지 검증한다.

현재 검증:

- Exact authority confirmation과 rejected-entry apply cursor, seq3-7 one-step resume,
  cleanup marker replay, stale clear, duplicate active/archive namespace, symlink archive와
  idempotent archive/acknowledgement가 unit regression으로 고정됐다.
- Local-applied-index barrier, same-key supervisor serialization, cross-key 독립 진행, exact-generation
  cleanup quiescence, same-process job loss rejection/restart absence replay, marker/archive post-rename
  fault convergence, immutable-owner bounded blocked status와 acknowledged terminal material의 다음
  admission GC transfer가 regression으로 고정됐다.
- 별도 test-binary process가 peer identity lock을 잡은 상태에서 `SIGSTOP`해도 두 번째 process의
  restart-absence 진입이 거부되고, `SIGKILL` 뒤에만 새 process가 lock을 획득하는 회귀가 통과했다.
  Cleanup permit은 collection/mutation/owner/generation/process-incarnation/claim digest 각 불일치를
  독립적으로 거부한다.
- `cleanup_linearizes_against_open_reservation_and_session_install`은 outstanding open reservation이
  cleanup을 막고, cleanup claim 뒤 install이 실패하며, exact job 없는 active session도 restart absence를
  막는 두 경쟁 순서를 결정적으로 검증한다.
- `cargo test -p storage --lib` 전체 386개가 2026-08-14 기준 통과했다. 이 결과는 deterministic
  state-machine/filesystem fault coverage이며 실제 kernel/process power-loss 인증을 대체하지 않는다.
- `cargo test --bin qdrant` 전체 927개도 같은 최종 구현 기준 통과했다.
- `cargo check --workspace --all-targets`도 Python edge encrypted-payload unsupported projection과
  HNSW append-rewrite error projection을 포함한 최종 worktree에서 통과했다.
- Log projection은 private ORAM path/bucket/proof/position-map/stash/plaintext aliases를
  redaction하고, snapshot recovery error는 client recovery-state aliases를 노출하지 않는다.
- 남은 release gate는 terminal Qdrant process를 fsync/rename/Raft 경계마다 kill하는 multi-process
  matrix, 두 supervisor/leader-change concurrency E2E, disk-full/permission/fsync injection과
  end-to-end snapshot/WAL binary sentinel scan이다.

완료 조건:

- Append 후 recall 기준과 paired payload 조회가 통과하고, mixed HNSW/result
  epoch는 관찰·복구·검색할 수 없다.
- Snapshot, WAL, logs, metrics, panic/error report에 vector/token/client-state
  sentinel이 없다.

### V2-E: Release Gate and Deferred Multi-Writer

작업:

- Backup rotation, client-state escrow, restore drill, key-loss 절차를 runbook으로
  작성한다.
  - 2026-10-09: `docs/private-oram-operations-runbook.md`에 초안을 작성했다. Checkpoint
    서명과 client-state escrow를 자동화하는 tooling과 staging restore drill 결과 기록은
    아직 남아 있다.
- Active target recovery, RF=1 external restore, append mutation을 Linux
  multi-process cluster E2E와 latency/bandwidth/write-amplification benchmark로
  고정한다.
- v2는 single logical writer로 release한다.

Deferred v3:

- Writer identity handoff에는 complete encrypted client-state transfer,
  monotonic fencing token, stale-writer rejection이 먼저 필요하다.
- True concurrent writers는 ORAM position map/stash merge와 access-pattern
  privacy protocol이 필요하므로 v2에 포함하지 않는다.

완료 조건:

- v2 release checklist가 recovery, atomic mutation, rollback, leakage,
  performance gate를 모두 통과한다.
- 운영자가 matching server snapshot과 complete encrypted client recovery-state
  backup을 자동 점검하고 정기 restore drill로 검증할 수 있다.
