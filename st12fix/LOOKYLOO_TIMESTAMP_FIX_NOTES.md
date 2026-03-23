# Lookyloo timestamp precision fix

- Fixed Python-style fractional timestamp parsing in `src/lookyloo.rs`.
- Normalizes fractional seconds before `%f%z` parsing so strings like `2025-03-23T12:34:56.123456+0000` are treated as microseconds (`123456000ns`), not raw nanoseconds (`123456ns`).
- This addresses the failing test `parse_lookyloo_summary_with_python_style_serialized_fields`.
