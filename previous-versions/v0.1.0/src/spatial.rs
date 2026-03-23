//! Spatial reference types — the minimal world scaffold.
//!
//! Skeletrace does not load a globe. It stores just enough math to
//! project sparse graph elements onto a geographic frame when needed.
//! This is Tier 0: world math only.

use serde::{Deserialize, Serialize};

// ── Geographic coordinate ──────────────────────────────────────────

/// WGS-84 geographic position. Altitude is optional because most
/// OSINT nodes only have a 2D fix (IP geolocation, city centroid, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoord {
    /// Latitude in decimal degrees, [-90.0, 90.0].
    pub lat: f64,
    /// Longitude in decimal degrees, [-180.0, 180.0].
    pub lon: f64,
    /// Altitude in metres above ellipsoid. `None` for 2D-only positions.
    pub alt: Option<f64>,
}

// ── Cartesian coordinate ───────────────────────────────────────────

/// Earth-centred, Earth-fixed (ECEF) Cartesian position in metres.
/// Used internally for geodesic math and through-globe shortcuts.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CartesianCoord {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

// ── Ellipsoid reference ────────────────────────────────────────────

/// WGS-84 ellipsoid constants. This is the entire "globe" that
/// skeletrace needs to know about — no tiles, no terrain, no meshes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ellipsoid {
    /// Semi-major axis (equatorial radius) in metres.
    pub semi_major: f64,
    /// Semi-minor axis (polar radius) in metres.
    pub semi_minor: f64,
    /// Flattening factor (1/298.257223563 for WGS-84).
    pub flattening: f64,
    /// First eccentricity squared.
    pub e_sq: f64,
}

/// Default WGS-84 constants. Populated in Stage 2.
pub const WGS84: Ellipsoid = Ellipsoid {
    semi_major: 6_378_137.0,
    semi_minor: 6_356_752.314_245_179,
    flattening: 1.0 / 298.257_223_563,
    e_sq: 0.006_694_379_990_141_316,
};

// ── Bounding box ───────────────────────────────────────────────────

/// Axis-aligned bounding box in geographic coords.
/// Used for viewport culling and spatial queries.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoBBox {
    pub min_lat: f64,
    pub min_lon: f64,
    pub max_lat: f64,
    pub max_lon: f64,
}
