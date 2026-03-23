Touched files in this pack:
- src/packet_workflow.rs       new
- src/operator.rs              updated
- src/event.rs                 updated (serde Serialize derives)
- tests/packet_workflow_contracts.rs  new

One additional change may be needed in your real current src/lib.rs if it differs from the uploaded hybrid tree:
- add: pub mod packet_workflow;
- re-export packet workflow types if you want external callers/tests to import them directly.

This pack formalizes packet analysis as:
- optional operator workflow: OperatorRequest::VerifyPackets / CliCommand::VerifyPackets
- optional verification/reporting path: PacketVerificationRequest/Report
- optional view/render surface: PacketRenderSurface::AsciiLandscape

It intentionally does NOT add packet analysis to core engine ViewKind.
