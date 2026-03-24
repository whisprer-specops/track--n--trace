//! Spatial reference types — the minimal world scaffold.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoord {
    pub lat: f64,
    pub lon: f64,
    pub alt: Option<f64>,
}

impl GeoCoord {
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon, alt: None }
    }

    pub fn with_alt(lat: f64, lon: f64, alt: f64) -> Self {
        Self { lat, lon, alt: Some(alt) }
    }

    /// Haversine distance in metres.
    pub fn distance_to(&self, other: &GeoCoord) -> f64 {
        let r = 6_371_000.0_f64;
        let d_lat = (other.lat - self.lat).to_radians();
        let d_lon = (other.lon - self.lon).to_radians();
        let a = (d_lat / 2.0).sin().powi(2)
            + self.lat.to_radians().cos()
                * other.lat.to_radians().cos()
                * (d_lon / 2.0).sin().powi(2);
        r * 2.0 * a.sqrt().asin()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CartesianCoord {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ellipsoid {
    pub semi_major: f64,
    pub semi_minor: f64,
    pub flattening: f64,
    pub e_sq: f64,
}

pub const WGS84: Ellipsoid = Ellipsoid {
    semi_major: 6_378_137.0,
    semi_minor: 6_356_752.314_245_179,
    flattening: 1.0 / 298.257_223_563,
    e_sq: 0.006_694_379_990_141_316,
};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoBBox {
    pub min_lat: f64,
    pub min_lon: f64,
    pub max_lat: f64,
    pub max_lon: f64,
}

impl GeoBBox {
    pub fn contains(&self, coord: &GeoCoord) -> bool {
        coord.lat >= self.min_lat
            && coord.lat <= self.max_lat
            && coord.lon >= self.min_lon
            && coord.lon <= self.max_lon
    }
}
