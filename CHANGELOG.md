# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/inferadb/common/compare/v0.1.0...v0.1.1) (2026-03-02)


### Features

* `is_transient()` on AuthError ([b7b34d6](https://github.com/inferadb/common/commit/b7b34d6ebc610c32a248823108ac7cda3fda6406))
* adapt to upstream ledger improvements ([13b8341](https://github.com/inferadb/common/commit/13b8341f95b073d3f3a53097ee72782b18c8c237))
* add `compare_and_set` to the `StorageBackend` trait ([4ddfac6](https://github.com/inferadb/common/commit/4ddfac652376852df6fc8f1f16982b658289a29d))
* add graceful shutdown to MemoryBackend ([0b04b18](https://github.com/inferadb/common/commit/0b04b18d1968c4b1b937713b0f81b83adc88917a))
* add inferadb-common-authn crate ([3621e36](https://github.com/inferadb/common/commit/3621e363824e2ac4e452525b91c4e598574d1db3))
* add ledger-back signing key support ([22a732b](https://github.com/inferadb/common/commit/22a732b5aabb990b9f1c5cc862e6f8230e6bbfac))
* add newtypes ([3f4ecf5](https://github.com/inferadb/common/commit/3f4ecf5b2f947a54c13daaa3af3c3b6a1f1d423b))
* add optimistic locking to LedgerSigningKeyStore write ops ([5bdb852](https://github.com/inferadb/common/commit/5bdb852ab61a97a2f2df4de8175e81bca67651f0))
* add retry policy with exponential backoff ([d673490](https://github.com/inferadb/common/commit/d673490c730a947449389feb862963b5fd8c7af7))
* add shared storage crates to common workspace ([e8e2190](https://github.com/inferadb/common/commit/e8e21907d7b1142dce1acb9a521869558a11aa13))
* add timeout config for storage ops ([069db88](https://github.com/inferadb/common/commit/069db88433a8b434044fdfcc7c0f98518a87fa92))
* add zeroize ([6b7b390](https://github.com/inferadb/common/commit/6b7b39079779aabd4144a73433b549d4963cd335))
* audit logging api ([4ac031d](https://github.com/inferadb/common/commit/4ac031d4ff6584b5eb0c5dce5237c25d7ecbf438))
* avoid lock contention in MemoryBackend clear_range ([554d04c](https://github.com/inferadb/common/commit/554d04caee46e6702d5a52fb41be0d2e9d1730f4))
* backend health check metadata ([49d0e57](https://github.com/inferadb/common/commit/49d0e5743aa325906ffc4db4ce143dbd1f0df5e5))
* batch writer flush ([69cc4ff](https://github.com/inferadb/common/commit/69cc4ff84e460bbf3b0d8f60e20b2a2f23108c71))
* cap fallback cache in `SigningKeyCache`; purge on revocation ([e9e89a3](https://github.com/inferadb/common/commit/e9e89a3bba07e38dc39e33d8a6d2dc0749145fbc))
* cas retry loop, config validations, percentile-based metrics ([4f05909](https://github.com/inferadb/common/commit/4f059094b82346ecbb25511ae82542521f9e86a2))
* clear_range latency metric ([3d01b23](https://github.com/inferadb/common/commit/3d01b2307f72cc77779b4cfe08df317c6c62d106))
* concurrency stress tests ([1aeed80](https://github.com/inferadb/common/commit/1aeed80a0932ba4beb48e350e5ee51aa194ff840))
* consolidate JWT claims extractors ([dfeda5c](https://github.com/inferadb/common/commit/dfeda5c1bfe6b69af99a56f4b645704a758d0129))
* control-scoped storage api improvements ([a2458f5](https://github.com/inferadb/common/commit/a2458f5c4295f6a3b1fc8615eadfd2a72647590a))
* criterion benchmarks ([64a8bb5](https://github.com/inferadb/common/commit/64a8bb5c6e0a4230078215c541035b7e9cbb8908))
* error message sanitization ([3f09cf7](https://github.com/inferadb/common/commit/3f09cf7938f589bce67355ff4226f1bd4ff20235))
* fallback cache staleness bound ([bddb87d](https://github.com/inferadb/common/commit/bddb87d42d390d45900c684258774369a138dba3))
* handle silent key deserialization failures in LedgerSigningKeyStore ([7832aa2](https://github.com/inferadb/common/commit/7832aa22cf3d7f5ec7663ad22039ef505aeb398b))
* harden kid input validation ([4ef6329](https://github.com/inferadb/common/commit/4ef632952552b7bfd0587b9fc509f25cb42013d9))
* health check readiness split, rstest parametric tests ([0e0c279](https://github.com/inferadb/common/commit/0e0c2794b67dc45ba1c36843643ad6c57dc82e15))
* jwt replay prevention ([520888c](https://github.com/inferadb/common/commit/520888c6c6cebea743e550919083294c3dba087f))
* KV size validation ([e2be732](https://github.com/inferadb/common/commit/e2be732bfd93d1ed4b25672a24f533f0d6a53a90))
* ledger circuit breaker ([b0060ae](https://github.com/inferadb/common/commit/b0060ae67db8b76d45cfb3564ba087bf9868720c))
* ledger get_range pagination support ([099b063](https://github.com/inferadb/common/commit/099b0637b8e288c0639e67167b3096395da10fd4))
* namespace-level metrics ([2f8e7ca](https://github.com/inferadb/common/commit/2f8e7cae06d40a4994269dbf51e1065e9909244c))
* preserve error source chain in AuthError:KeyStorageError ([2499ec0](https://github.com/inferadb/common/commit/2499ec0462a41bcf14f44d907180f3246442131a))
* proptest ([514795a](https://github.com/inferadb/common/commit/514795a066282e18583c000df9dbc5c4143f10e3))
* rate limit abstractions ([bd1ddf0](https://github.com/inferadb/common/commit/bd1ddf0c05405718f80b0de2d2db0a886de7e8ea))
* retry timeout during active backoff ([9709a7f](https://github.com/inferadb/common/commit/9709a7fa993ed4c7d62111eb14825fca26985136))
* **sdk:** endpoints → servers config ([976eef7](https://github.com/inferadb/common/commit/976eef7a205c2e7c9218394e01c4ce06fbdba2e2))
* specify non_exhaustive on error types ([1b4c105](https://github.com/inferadb/common/commit/1b4c10583ed4c6ec7398efa3c9388055249903fc))
* **storage:** batch write ops, metrics ([a502f9e](https://github.com/inferadb/common/commit/a502f9e0f201fbc3931f28df8e2be2ed8b43f0a6))
* store signing key revocation reason ([acef285](https://github.com/inferadb/common/commit/acef2855448f29ab3ea45781b6c0c556d32758d8))
* tracing instrumentation, partial failure tests ([e936949](https://github.com/inferadb/common/commit/e936949619a1b4f95d12d67e44754b49145f4a89))
* transaction isolation improvements ([22a422f](https://github.com/inferadb/common/commit/22a422f59c7b6f677dfe01463f33b93b8bbb3c9f))
* ttl support for atomic operations ([5607981](https://github.com/inferadb/common/commit/5607981ff67fe84848855a8164ada710bcdfcd68))
* use Ordering:Relaxed audit for atomic counters ([d0fcc17](https://github.com/inferadb/common/commit/d0fcc178ee3df6d329f64c6b27c524a78c2644d9))


### Bug Fixes

* SigningKeyCache race condition ([9a5afea](https://github.com/inferadb/common/commit/9a5afea8c2d7d95607672f0b475bc78e79dfb113))
* ttl timestamp calc ([aece225](https://github.com/inferadb/common/commit/aece225a97bbed01b176877e57a474fa01a4299b))
* write concurrency race condition ([0221049](https://github.com/inferadb/common/commit/0221049e526137b39416b6c5ce9499a29d1933f8))
* write concurrency race condition ([b314a1f](https://github.com/inferadb/common/commit/b314a1f38e32ecefe95df16d0509961624bcacf2))
* write concurrency race condition ([636f144](https://github.com/inferadb/common/commit/636f144b96b3c2bdeb85732b194847fb78528677))


### Improvements

* adapt ledger sdk changes ([aa7ca09](https://github.com/inferadb/common/commit/aa7ca099cda153c359298ada0de345b3650baf0f))
* dedupe `encode_key`/`decode_key` ([6df5678](https://github.com/inferadb/common/commit/6df567892c8910f7201a1e47ec1df7651be3e3a4))
* public api documentation ([10286d5](https://github.com/inferadb/common/commit/10286d521fe1628d1a9d21b001a99bf8a8b4d316))
* reduce allocations in get_range ([e2b947e](https://github.com/inferadb/common/commit/e2b947eabddaabc04e2cfe2095c58562b19560f0))
* streamling storage-ledger configuration ([987d89e](https://github.com/inferadb/common/commit/987d89e4aecde7f10ce180d0d5394da47f58aff6))
* use `Duration` instead of `u64` for `set_with_ttl` ([f875ad7](https://github.com/inferadb/common/commit/f875ad795f864fec09541ec613cbf388054a70be))

## [Unreleased]
