# Maxwell's Demon Detector (Rust, embeddable + live-capture build)

This crate is now split into two usable layers:

- an **embeddable library** for packet-stream scoring, anomaly verification, and ASCII landscape rendering
- a **terminal application** front-end with optional live libpcap/Npcap capture

It can now:
- list capture interfaces
- capture live packets via **libpcap** on Linux and **Npcap** on Windows
- replay CSV event streams
- ingest live JSONL events on stdin
- render a rolling ASCII traffic landscape in realtime
- compute per-lane packet-load / packet-size entropy / anomaly scores
- verify a packet-event stream offline without the terminal UI
- be linked into a larger app with the live-capture and terminal layers disabled

## What this build is

- a realtime terminal mapper
- a lawful packet-stream visualizer
- a reusable Rust library for normalized packet-event analysis
- a proper front-end for the original live-map concept

## What this build is not

- a Wireshark replacement
- a full application-layer reassembler
- a DPI / TLS decryption suite
- a GUI

## Feature layout

Default features keep the current standalone application behavior:

```toml
maxwells-demon-detector = "0.3"
```

For embedding into another Rust application without terminal UI or libpcap/Npcap linkage:

```toml
maxwells-demon-detector = { version = "0.3", default-features = false }
```

Available features:

- `tui` — terminal application front-end
- `live-pcap` — live capture source using libpcap/Npcap

## Embedding example

```rust
use maxwells_demon_detector::{verify_events, PacketEvent};
use maxwells_demon_detector::render::frame_string;

let report = verify_events(
    vec![
        PacketEvent {
            ts_ms: Some(0),
            len: 512,
            proto: "tls".into(),
            src: Some("10.0.0.2".into()),
            dst: Some("93.184.216.34".into()),
            sport: Some(51514),
            dport: Some(443),
            dir: Some("out".into()),
        }
    ],
    64,
    200,
    8,
);

let ascii = frame_string(&report.state, "embedded");
println!("{}", ascii);
```

## Build prerequisites

### Linux

Install the libpcap development package before building with `live-pcap`. On Debian-family systems that is typically:

```bash
sudo apt-get install libpcap-dev
```

### Windows

Install **Npcap** and the **Npcap SDK**, then add the SDK `Lib` directory to your `LIB` environment variable before building with `live-pcap`.

## Commands

### 1. List capture interfaces

```bash
cargo run --release -- --mode list-interfaces
```

### 2. Live packet capture

Use the default capture device:

```bash
cargo run --release -- --mode live-pcap
```

Use a named interface:

```bash
cargo run --release -- --mode live-pcap --interface eth0
```

Use a listed numeric interface index:

```bash
cargo run --release -- --mode live-pcap --interface 0
```

Use a BPF filter:

```bash
cargo run --release -- --mode live-pcap --interface eth0 --filter "tcp or udp"
```

Example narrow capture:

```bash
cargo run --release -- --mode live-pcap --interface eth0 --filter "port 53 or port 80 or port 443"
```

### 3. Demo mode

```bash
cargo run --release -- --mode demo
```

### 4. Replay mode

```bash
cargo run --release -- --mode replay --input examples/events.csv --replay-speed 40
```

### 5. STDIN JSONL mode

```bash
cat examples/events.jsonl | cargo run --release -- --mode stdin-jsonl
```

## Live capture notes

- The capture adapter uses `pcap::Device::lookup()` when no interface is specified.
- Interface listing uses `pcap::Device::list()`.
- A configurable BPF filter is applied with `pcap::Capture::filter()` after the interface is opened.
- The capture thread uses a non-zero timeout to avoid UI starvation and to allow a clean shutdown.
- The decoder currently supports the most common link and network combinations needed for practical traffic mapping:
  - Ethernet II
  - Linux cooked capture (SLL)
  - RAW IP
  - NULL / LOOP loopback headers
  - IPv4 / IPv6
  - TCP / UDP / ICMP / ICMPv6

## Traffic lanes

Rows are classified into:
- `WEB`
- `DNS`
- `MAIL`
- `MEDIA`
- `CTRL`
- `BULK`
- `OTHER`

Classification uses decoded transport ports, lightweight protocol guessing, and packet size.

## Glyph semantics

A cell is **not** a single packet.

A cell is one time bucket for one lane. Its glyph blends:
- packet load
- packet-size Shannon entropy
- rolling anomaly state

`!` marks an anomalous bucket.

## Controls

- `q` or `Esc` quits
- `Ctrl+C` also works

## Useful options

```text
--tick-ms <ms>            redraw interval
--width <cols>            map width override
--max-alerts <n>          alert history depth
--snaplen <bytes>         capture snap length
--buffer-size <bytes>     libpcap/Npcap kernel buffer target
--pcap-timeout-ms <ms>    capture timeout used by the capture thread
--promisc <true|false>    promiscuous capture on/off
```

## Example event schema for replay/stdin modes

```json
{"ts_ms":0,"len":512,"proto":"tls","src":"10.0.0.2","dst":"93.184.216.34","sport":51514,"dport":443,"dir":"out"}
```

## Packaging and licensing note

This project links against libpcap on Linux and Npcap on Windows when the `live-pcap` feature is enabled. If you distribute a Windows build, review the current Npcap licensing and redistribution terms carefully.
