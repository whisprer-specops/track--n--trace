# Skeletrace Stage 10

This stage stays inside the source-agnostic, universally useful lane and adds three things:

1. **Batch ingest surfaces**
   - `EngineStore::ingest_raw_records_batch(...)`
   - `EngineStore::ingest_samples_batch(...)`
   - `EngineStore::ingest_batch(...)`
   - engine ingest path now uses the batch store helpers for lower overhead bookkeeping

2. **Replay benchmarking on fresh profiles**
   - `ReplayBenchmarkRequest`
   - `ReplayBenchmarkReport`
   - `SourceWorkloadSummary`
   - `OperatorRequest::BenchmarkReplayWorkload`
   - benchmarks instantiate a fresh engine from the saved profile each iteration so runs stay deterministic and do not accumulate prior state

3. **SQLite warm-store maintenance and tuning surfaces**
   - `WarmStoreMaintenanceReport`
   - `SqliteWarmStore::maintenance_report()`
   - `SqliteWarmStore::optimize(vacuum)`
   - operator-visible warm-store reporting and optimization requests

This deliberately avoids any source-specific rotation/evasion/identity-pool tactics.
The work here is still useful whether the final source mix is public/free/paid/private, or even if some categories are later rejected on ethical or legal grounds.
