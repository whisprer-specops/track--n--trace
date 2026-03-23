# Lookyloo topology stage

This stage adds a second-stage Lookyloo adapter that can emit sparse Skeletrace topology objects from capture summary payloads.

## New pieces
- `LookylooTopologyConfig`
- `LookylooTopologyAdapter`
- `AdapterProfile::LookylooTopology`
- topology-bearing `SourcePull` batches (`nodes`, `edges`, `boundaries`)
- engine ingestion of adapter-supplied topology entities
- tests for topology batch generation and end-to-end engine materialization

## Relationship model
For each Lookyloo capture summary, the adapter can materialize:
- a capture node
- one node per discovered domain in the root URL + redirect chain
- capture -> root-domain edge
- capture -> final-domain edge
- redirect-chain edges between sequential domains
- parent-capture -> capture edge when `parent` is present
- category boundaries
- a `Lookyloo No-Index` boundary
- a `Lookyloo Error` boundary

## Deliberate limits
- geography stays `None`; these are abstract topology entities
- category boundaries are emitted per category label and are not yet merged across repeated captures in one batch or across runs
- transport/auth behavior is unchanged; this stage only extends Lookyloo parsing/materialization
