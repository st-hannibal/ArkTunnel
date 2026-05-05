//! Traffic shaping primitives — Phase 12 WP4.
//!
//! Provides:
//!  - **Length quantization**: round payload sizes up to fixed buckets
//!    so on-wire packet length distribution is coarse and uninformative
//!    (`{256, 512, 1024, 1280, 1500}` bytes; larger payloads round up to
//!    multiples of the largest bucket).
//!  - **Cover traffic timing**: Poisson-distributed inter-arrival when
//!    the tunnel has been idle longer than `IDLE_THRESHOLD`, with mean
//!    `COVER_MEAN_LIGHT` (or `COVER_MEAN_HEAVY`).
//!
//! These are pure functions — no I/O. The wire-level use of cover
//! frames + payload padding is gated by ARK-frame v2 capability bits
//! negotiated in WP5; until then the client only emits shaping when
//! `Shape::Off` is in effect (i.e. it does not). The numbers and
//! buckets here are stable so the WP5 patch only has to wire them up.

use std::time::Duration;

/// Length-quantization buckets in bytes. Sized to match the most common
/// MTU regimes so a padded packet still fits in one IP datagram.
pub const BUCKETS: [usize; 5] = [256, 512, 1024, 1280, 1500];

/// Largest bucket — payloads above this round up to the next multiple
/// of `LARGEST_BUCKET` (e.g. 1501 → 3000).
pub const LARGEST_BUCKET: usize = 1500;

/// How long the tunnel must be idle (no real bytes either way) before
/// the cover-packet generator wakes up.
pub const IDLE_THRESHOLD: Duration = Duration::from_millis(500);

/// Mean cover-packet inter-arrival under `Shape::Light`.
pub const COVER_MEAN_LIGHT: Duration = Duration::from_millis(2000);

/// Mean cover-packet inter-arrival under `Shape::Heavy`.
pub const COVER_MEAN_HEAVY: Duration = Duration::from_millis(500);

/// Traffic-shaping policy selected by the operator (`--shape …`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Shape {
    /// No padding, no cover packets. Wire-compatible with v0.1.x
    /// servers. Default until WP5 negotiation lands.
    #[default]
    Off,
    /// Length quantization on every outbound payload + Poisson cover
    /// at ~2 s mean when idle.
    Light,
    /// Length quantization + Poisson cover at ~500 ms mean when idle.
    /// Significantly higher bandwidth overhead; intended for high-risk
    /// users on otherwise-quiet links.
    Heavy,
}

impl Shape {
    /// Mean cover inter-arrival for this shape, or `None` for `Off`.
    pub fn cover_mean(self) -> Option<Duration> {
        match self {
            Shape::Off => None,
            Shape::Light => Some(COVER_MEAN_LIGHT),
            Shape::Heavy => Some(COVER_MEAN_HEAVY),
        }
    }

    /// `true` when this shape should pad outgoing payloads to the next
    /// length bucket.
    pub fn pads_lengths(self) -> bool {
        !matches!(self, Shape::Off)
    }
}

impl std::str::FromStr for Shape {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" | "0" => Ok(Shape::Off),
            "light" | "default" => Ok(Shape::Light),
            "heavy" | "high" => Ok(Shape::Heavy),
            other => Err(format!("invalid --shape value: {other} (expected off|light|heavy)")),
        }
    }
}

impl std::fmt::Display for Shape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shape::Off => f.write_str("off"),
            Shape::Light => f.write_str("light"),
            Shape::Heavy => f.write_str("heavy"),
        }
    }
}

/// Round `n` up to the next length bucket. Payloads larger than the
/// largest bucket round up to the next multiple of `LARGEST_BUCKET`.
/// `n == 0` returns 0 (don't pad away the absence of data).
pub fn quantize_len(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    for &b in &BUCKETS {
        if n <= b {
            return b;
        }
    }
    // Larger than every bucket: round up to the next multiple of LARGEST_BUCKET.
    n.div_ceil(LARGEST_BUCKET) * LARGEST_BUCKET
}

/// Number of padding bytes to add to a payload of size `n` under `shape`.
pub fn padding_for(shape: Shape, n: usize) -> usize {
    if !shape.pads_lengths() {
        return 0;
    }
    quantize_len(n).saturating_sub(n)
}

/// Sample one Poisson inter-arrival delay with the given mean. Uses
/// inverse-CDF on a uniform `(0, 1]`, returning `-mean * ln(u)`.
///
/// Caller supplies the RNG so tests are deterministic.
pub fn next_cover_delay<R: rand::Rng + ?Sized>(mean: Duration, rng: &mut R) -> Duration {
    // Avoid u == 0 which would give +inf.
    let u: f64 = loop {
        let x: f64 = rng.r#gen();
        if x > 0.0 {
            break x;
        }
    };
    let secs = mean.as_secs_f64() * (-u.ln());
    // Clamp to a sane upper bound (10 * mean) to avoid pathological tail
    // delays freezing the cover stream.
    let cap = mean.as_secs_f64() * 10.0;
    Duration::from_secs_f64(secs.min(cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_buckets() {
        assert_eq!(quantize_len(0), 0);
        assert_eq!(quantize_len(1), 256);
        assert_eq!(quantize_len(256), 256);
        assert_eq!(quantize_len(257), 512);
        assert_eq!(quantize_len(900), 1024);
        assert_eq!(quantize_len(1280), 1280);
        assert_eq!(quantize_len(1281), 1500);
        assert_eq!(quantize_len(1500), 1500);
    }

    #[test]
    fn quantize_above_largest_bucket() {
        assert_eq!(quantize_len(1501), 3000);
        assert_eq!(quantize_len(3000), 3000);
        assert_eq!(quantize_len(3001), 4500);
        assert_eq!(quantize_len(64_000), 64_500);
    }

    #[test]
    fn padding_off_is_zero() {
        for n in [0, 1, 100, 1500, 9000] {
            assert_eq!(padding_for(Shape::Off, n), 0);
        }
    }

    #[test]
    fn padding_light_and_heavy_match_quantize() {
        for shape in [Shape::Light, Shape::Heavy] {
            assert_eq!(padding_for(shape, 0), 0);
            assert_eq!(padding_for(shape, 1), 255);
            assert_eq!(padding_for(shape, 256), 0);
            assert_eq!(padding_for(shape, 1024), 0);
            assert_eq!(padding_for(shape, 1100), 180);
            assert_eq!(padding_for(shape, 1501), 1499);
        }
    }

    #[test]
    fn shape_parse_roundtrip() {
        for s in ["off", "light", "heavy"] {
            let p: Shape = s.parse().unwrap();
            assert_eq!(p.to_string(), s);
        }
        assert!("hard".parse::<Shape>().is_err());
        assert_eq!("Light".parse::<Shape>().unwrap(), Shape::Light);
        assert_eq!("none".parse::<Shape>().unwrap(), Shape::Off);
    }

    #[test]
    fn shape_means_make_sense() {
        assert_eq!(Shape::Off.cover_mean(), None);
        assert_eq!(Shape::Light.cover_mean(), Some(COVER_MEAN_LIGHT));
        assert_eq!(Shape::Heavy.cover_mean(), Some(COVER_MEAN_HEAVY));
        assert!(Shape::Light.pads_lengths());
        assert!(!Shape::Off.pads_lengths());
    }

    #[test]
    fn cover_delay_distribution_has_correct_mean() {
        // Poisson with mean m → exponential inter-arrival with mean m.
        // Sample 10k draws, expect sample mean within 5% of m.
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA8E1_2F00_DEAD_BEEFu64);
        let mean = Duration::from_millis(2000);
        let n = 10_000;
        let total: f64 = (0..n)
            .map(|_| next_cover_delay(mean, &mut rng).as_secs_f64())
            .sum();
        let avg = total / n as f64;
        let want = mean.as_secs_f64();
        assert!(
            (avg - want).abs() / want < 0.05,
            "sample mean {avg:.3}s not within 5% of {want:.3}s"
        );
    }

    #[test]
    fn cover_delay_is_capped() {
        // Even for an absurdly small u, the cap kicks in at 10 * mean.
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mean = Duration::from_millis(2000);
        for _ in 0..10_000 {
            let d = next_cover_delay(mean, &mut rng);
            assert!(d <= mean * 10);
        }
    }
}
