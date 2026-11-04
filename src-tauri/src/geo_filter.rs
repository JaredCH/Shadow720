//! Movement gating, polling cadence, jitter, and backoff policy.
//!
//! The whole group shares **one** 5,000 req/hour PAT budget, so the client is
//! deliberately stingy: it refuses to publish a location it does not need to
//! publish, refuses to poll faster than the plan allows, and spreads every
//! interval with jitter so 50 phones never align into a thundering herd.
//!
//! Two independent mechanisms live here:
//!
//! * [`GeoGate`] — decides whether a new GPS fix is worth a `PATCH` at all
//!   (Haversine distance + cooldown + heartbeat).
//! * [`AdaptiveBackoff`] / [`RateLimitHalt`] — decides how long to wait before
//!   the next poll for a channel, and stops everything when GitHub says stop.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::error::{AppError, Result};

/// Minimum distance a member must move before a location `PATCH` is worthwhile.
pub const MIN_MOVE_METERS: f64 = 15.0;
/// Minimum seconds between location `PATCH`es, regardless of distance.
pub const MIN_INTERVAL_SECS: u64 = 30;
/// A stationary member still pings at least this often, so peers can see liveness.
pub const HEARTBEAT_SECS: u64 = 900;
/// Fraction of the interval that jitter may add or remove (25%).
pub const JITTER_FRACTION: f64 = 0.25;
/// Consecutive `304 Not Modified` polls before an interval is doubled.
pub const BACKOFF_THRESHOLD: u32 = 3;
/// Multiplier applied each time the threshold is crossed.
pub const BACKOFF_FACTOR: f64 = 2.0;
/// Longest a channel will ever back off to.
pub const BACKOFF_CAP_SECS: u64 = 300;
/// Extra slack added past `x-ratelimit-reset` before polling resumes.
pub const RATE_LIMIT_PADDING_SECS: i64 = 60;
/// Earth's mean radius, metres.
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Below this speed a member is treated as stationary, in metres per second.
///
/// GPS noise alone can report 0.5 m/s while standing still, so the threshold sits
/// above that rather than at zero.
pub const STILL_SPEED_MPS: f32 = 0.8;
/// Upper bound of walking, in metres per second (~5.4 km/h).
pub const WALK_SPEED_MPS: f32 = 1.5;
/// Upper bound of running, in metres per second (~14 km/h).
pub const RUN_SPEED_MPS: f32 = 4.0;
/// Upper bound of cycling, in metres per second (~29 km/h).
pub const CYCLE_SPEED_MPS: f32 = 8.0;

/// How a member appears to be moving.
///
/// Derived from reported speed rather than inferred from position deltas: the
/// platform already fuses GPS, Wi-Fi, and cell data, and a delta over a 30-second
/// publish interval is far noisier than the speed it reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Activity {
    /// Not moving, or moving too slowly to tell.
    Still,
    Walking,
    Running,
    Cycling,
    /// Motorised travel: driving, a bus, a train.
    Driving,
}

impl Activity {
    /// Classify a speed in metres per second.
    pub fn from_speed(speed_mps: f32) -> Self {
        if !speed_mps.is_finite() || speed_mps < STILL_SPEED_MPS {
            return Activity::Still;
        }
        if speed_mps < WALK_SPEED_MPS {
            Activity::Walking
        } else if speed_mps < RUN_SPEED_MPS {
            Activity::Running
        } else if speed_mps < CYCLE_SPEED_MPS {
            Activity::Cycling
        } else {
            Activity::Driving
        }
    }
}

// ---------------------------------------------------------------------------
// Haversine
// ---------------------------------------------------------------------------

/// Great-circle distance in metres between two WGS-84 coordinates.
///
/// Handles the antimeridian and poles correctly because the formula works on the
/// sphere rather than on a projected plane.
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let d_phi = (lat2 - lat1).to_radians();
    let d_lambda = (lon2 - lon1).to_radians();

    let a = (d_phi / 2.0).sin().powi(2)
        + phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2);
    // Clamp: floating point can push `a` a hair above 1 for antipodal points,
    // which would make asin() return NaN.
    let clamped = a.clamp(0.0, 1.0);
    2.0 * EARTH_RADIUS_M * clamped.sqrt().asin()
}

/// True when a coordinate pair is inside the valid WGS-84 range.
pub fn is_valid_coordinate(lat: f64, lon: f64) -> bool {
    lat.is_finite() && lon.is_finite() && (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

// ---------------------------------------------------------------------------
// GeoGate
// ---------------------------------------------------------------------------

/// A single GPS sample.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
    pub unix_ms: i64,
    /// Ground speed in metres per second, or `0.0` when the platform omits it.
    pub speed_mps: f32,
    /// Direction of travel in degrees clockwise from north, or `0.0` when unknown.
    pub heading_deg: f32,
    /// Horizontal accuracy radius in metres, or `0.0` when unknown.
    pub accuracy_m: f32,
}

impl Fix {
    /// A fix carrying only a position, for callers that have no motion data.
    pub fn at(lat: f64, lon: f64, unix_ms: i64) -> Self {
        Self { lat, lon, unix_ms, speed_mps: 0.0, heading_deg: 0.0, accuracy_m: 0.0 }
    }
}

impl Fix {
    /// Validate the sample before it can drive any decision.
    pub fn validate(&self) -> Result<()> {
        if !is_valid_coordinate(self.lat, self.lon) {
            return Err(AppError::invalid_argument(format!(
                "GPS fix ({}, {}) is outside valid WGS-84 bounds",
                self.lat, self.lon
            )));
        }
        if self.unix_ms <= 0 {
            return Err(AppError::invalid_argument(
                        "GPS fix has a non-positive timestamp",
            ));
        }
        Ok(())
    }
}

/// Why a fix was not published.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SkipReason {
    /// Not enough distance covered, and the heartbeat has not elapsed.
    MovedTooLittle {
        moved_m: f64,
        required_m: f64,
        waited_s: u64,
    },
    /// Cooldown still active after a recent publish, regardless of distance.
    CooldownActive {
        waited_s: u64,
        required_s: u64,
    },
}

/// Outcome of feeding a fix to [`GeoGate::evaluate`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Publish {
    /// Send a `PATCH` for this fix.
    Yes,
    /// Skip; the reason is informational and safe to log.
    No(SkipReason),
}

/// Decides whether a location update is worth spending a request on.
///
/// Publishes when **either**:
/// * at least [`MIN_INTERVAL_SECS`] have passed **and** the member moved at least
///   [`MIN_MOVE_METERS`], or
/// * at least [`HEARTBEAT_SECS`] have passed with no publish (liveness ping).
#[derive(Clone, Debug)]
pub struct GeoGate {
    last_published: Option<Fix>,
    min_move_m: f64,
    min_interval_s: u64,
    heartbeat_s: u64,
}

impl Default for GeoGate {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoGate {
    /// Gate with the plan's production thresholds.
    pub fn new() -> Self {
        Self {
            last_published: None,
            min_move_m: MIN_MOVE_METERS,
            min_interval_s: MIN_INTERVAL_SECS,
            heartbeat_s: HEARTBEAT_SECS,
        }
    }

    /// Gate with custom thresholds, for tests and future tuning.
    ///
    /// Returns [`AppError::InvalidArgument`] for nonsensical combinations
    /// (negative distance, zero interval, heartbeat shorter than the interval)
    /// rather than silently behaving oddly.
    pub fn with_thresholds(
        min_move_m: f64,
        min_interval_s: u64,
        heartbeat_s: u64,
    ) -> Result<Self> {
        if !min_move_m.is_finite() || min_move_m < 0.0 {
            return Err(AppError::invalid_argument(
                        "minimum movement distance must be a non-negative number",
            ));
        }
        if min_interval_s == 0 {
            return Err(AppError::invalid_argument(
                        "minimum publish interval must be greater than zero",
            ));
        }
        if heartbeat_s < min_interval_s {
            return Err(AppError::invalid_argument(
                        "heartbeat interval must be at least the minimum publish interval",
            ));
        }
        Ok(Self {
            last_published: None,
            min_move_m,
            min_interval_s,
            heartbeat_s,
        })
    }

    /// The last fix that was actually published, if any.
    pub fn last_published(&self) -> Option<Fix> {
        self.last_published
    }

    /// Decide whether `fix` should be published.
    ///
    /// Invalid fixes are rejected with an error; the caller should surface that
    /// rather than forward bad coordinates.
    pub fn evaluate(&self, fix: &Fix) -> Result<Publish> {
        fix.validate()?;

        let last = match self.last_published {
            None => return Ok(Publish::Yes),
            Some(previous) => previous,
        };

        let elapsed_ms = fix.unix_ms.saturating_sub(last.unix_ms);
        let elapsed_s = u64::try_from(elapsed_ms / 1_000).unwrap_or(0);
        let moved_m = haversine_m(last.lat, last.lon, fix.lat, fix.lon);

        // Out-of-order or duplicated timestamps carry no new information.
        if elapsed_ms <= 0 {
            return Ok(Publish::No(SkipReason::MovedTooLittle {
                moved_m,
                required_m: self.min_move_m,
                waited_s: 0,
            }));
        }

        if elapsed_s < self.min_interval_s {
            return Ok(Publish::No(SkipReason::CooldownActive {
                waited_s: elapsed_s,
                required_s: self.min_interval_s,
            }));
        }

        if moved_m >= self.min_move_m {
            return Ok(Publish::Yes);
        }

        if elapsed_s >= self.heartbeat_s {
            return Ok(Publish::Yes);
        }

        Ok(Publish::No(SkipReason::MovedTooLittle {
            moved_m,
            required_m: self.min_move_m,
            waited_s: elapsed_s,
        }))
    }

    /// Record that `fix` was published. Call this only after the `PATCH`
    /// succeeds, so a failed request does not suppress the next attempt.
    pub fn record_published(&mut self, fix: Fix) {
        self.last_published = Some(fix);
    }

    /// Forget history, e.g. after leaving and rejoining a group.
    pub fn reset(&mut self) {
        self.last_published = None;
    }
}

// ---------------------------------------------------------------------------
// Jitter
// ---------------------------------------------------------------------------

/// SplitMix64-based jitter source.
///
/// Seeded from the OS CSPRNG in production and from a fixed value in tests, so
/// interval spreading is reproducible when it needs to be.
pub struct Jitter {
    state: u64,
}

impl Jitter {
    /// Seed from the OS CSPRNG.
    pub fn from_entropy() -> Result<Self> {
        let seed = random_bytes::<8>()?;
        Ok(Self {
            state: u64::from_le_bytes(seed),
        })
    }

    /// Seed deterministically, for tests.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            // A zero state would be a fixed point; nudge it.
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    /// Next value in `[0, 1)`.
    pub fn next_unit(&mut self) -> f64 {
        // SplitMix64.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;

        // 53 bits of mantissa, mapped to [0, 1).
        let mantissa = (z >> 11) as f64;
        mantissa / (1u64 << 53) as f64
    }

    /// Apply ±[`JITTER_FRACTION`] to `base`, returning milliseconds.
    pub fn apply(&mut self, base: Duration) -> Duration {
        apply_jitter(base, self.next_unit())
    }
}

/// Apply ±[`JITTER_FRACTION`] to `base` using a caller-supplied `[0, 1)` sample.
///
/// Split out so the maths is unit-testable without the RNG.
pub fn apply_jitter(base: Duration, unit: f64) -> Duration {
    let unit = unit.clamp(0.0, 1.0);
    // Map [0,1) -> [-1,1).
    let signed = unit * 2.0 - 1.0;
    let scale = 1.0 + signed * JITTER_FRACTION;
    let base_ms = base.as_millis() as f64;
    let scaled = (base_ms * scale).round().max(0.0);
    // Guard against absurd inputs; u64 ms covers ~584 million years.
    Duration::from_millis(scaled.min(u64::MAX as f64) as u64)
}

// ---------------------------------------------------------------------------
// AdaptiveBackoff
// ---------------------------------------------------------------------------

/// Per-channel polling interval that lengthens when the channel goes quiet.
///
/// GitHub does not charge `304 Not Modified` against the rate limit, but the
/// *request* still costs a round trip and battery. When a channel has been
/// unchanged for [`BACKOFF_THRESHOLD`] polls in a row, doubling the interval
/// trades a little latency for a lot of headroom.
#[derive(Clone, Debug)]
pub struct AdaptiveBackoff {
    base: Duration,
    current: Duration,
    cap: Duration,
    consecutive_not_modified: u32,
}

impl AdaptiveBackoff {
    /// Backoff for a channel whose un-jittered interval is `base`.
    pub fn new(base: Duration) -> Self {
        let cap = Duration::from_secs(BACKOFF_CAP_SECS);
        Self {
            base,
            current: base,
            cap: if cap < base { base } else { cap },
            consecutive_not_modified: 0,
        }
    }

    /// The interval currently in force, before jitter.
    pub fn current(&self) -> Duration {
        self.current
    }

    /// The floor interval, i.e. the plan's cadence.
    pub fn base(&self) -> Duration {
        self.base
    }

    /// How many consecutive `304`s have been observed.
    pub fn consecutive_not_modified(&self) -> u32 {
        self.consecutive_not_modified
    }

    /// Feed a poll result. `true` means the response was `304 Not Modified`.
    pub fn observe(&mut self, not_modified: bool) {
        if not_modified {
            self.consecutive_not_modified = self.consecutive_not_modified.saturating_add(1);
            if self.consecutive_not_modified >= BACKOFF_THRESHOLD {
                let doubled_ms = (self.current.as_millis() as f64 * BACKOFF_FACTOR).round();
                let capped_ms = doubled_ms.min(self.cap.as_millis() as f64);
                self.current = Duration::from_millis(capped_ms.max(0.0) as u64);
                // Reset the counter so the next doubling needs another full run
                // of quiet polls rather than triggering on the very next one.
                self.consecutive_not_modified = 0;
            }
        } else {
            self.reset();
        }
    }

    /// Return to the base interval immediately.
    pub fn reset(&mut self) {
        self.current = self.base;
        self.consecutive_not_modified = 0;
    }

    /// Sleep duration for this channel, with jitter applied.
    pub fn next_delay(&self, jitter: &mut Jitter) -> Duration {
        jitter.apply(self.current)
    }
}

// ---------------------------------------------------------------------------
// RateLimitHalt
// ---------------------------------------------------------------------------

/// Global "stop polling" switch, driven by GitHub's rate-limit headers.
///
/// When tripped, **every** channel stops until `reset + padding`. This is the
/// difference between burning the shared PAT for an hour and recovering.
#[derive(Clone, Debug, Default)]
pub struct RateLimitHalt {
    halted_until_unix_s: Option<i64>,
    last_remaining: Option<u32>,
    last_limit: Option<u32>,
}

impl RateLimitHalt {
    /// Fresh, not halted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe `x-ratelimit-reset` (unix seconds) and `x-ratelimit-remaining`.
    ///
    /// Trips the halt when the request was a `429`, or a `403` that arrived with
    /// zero requests remaining.
    pub fn observe(&mut self, status: u16, reset_unix_s: Option<i64>, remaining: Option<u32>) {
        if let Some(remaining) = remaining {
            self.last_remaining = Some(remaining);
        }
        let exhausted = remaining == Some(0);
        if status == 429 || (status == 403 && exhausted) {
            if let Some(reset) = reset_unix_s {
                self.halted_until_unix_s = Some(reset.saturating_add(RATE_LIMIT_PADDING_SECS));
            }
        }
    }

    /// Record the total limit reported by GitHub, for diagnostics.
    pub fn observe_limit(&mut self, limit: Option<u32>) {
        self.last_limit = limit;
    }

    /// True when polling must not proceed at `now_unix_s`.
    pub fn is_halted(&self, now_unix_s: i64) -> bool {
        matches!(self.halted_until_unix_s, Some(until) if now_unix_s < until)
    }

    /// Unix second at which polling may resume, if currently halted.
    pub fn halted_until(&self) -> Option<i64> {
        self.halted_until_unix_s
    }

    /// Seconds remaining in the halt, or `None` when not halted.
    pub fn remaining_secs(&self, now_unix_s: i64) -> Option<i64> {
        match self.halted_until_unix_s {
            Some(until) if now_unix_s < until => Some(until - now_unix_s),
            _ => None,
        }
    }

    /// Requests remaining according to the last observed header.
    pub fn last_remaining(&self) -> Option<u32> {
        self.last_remaining
    }

    /// Total hourly limit according to the last observed header.
    pub fn last_limit(&self) -> Option<u32> {
        self.last_limit
    }

    /// Clear the halt. Use when the user taps "retry now".
    pub fn clear(&mut self) {
        self.halted_until_unix_s = None;
    }

    /// Fraction of the budget still available, in `[0, 1]`, if known.
    pub fn budget_fraction(&self) -> Option<f64> {
        match (self.last_remaining, self.last_limit) {
            (Some(remaining), Some(limit)) if limit > 0 => {
                Some(f64::from(remaining) / f64::from(limit))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Secret buffers
// ---------------------------------------------------------------------------

/// A zeroizing byte buffer used for decrypted file bodies passing through the
/// geo/polling pipeline. Kept here so the pruning path never leaves plaintext
/// bytes in a plain `Vec`.
pub type SecretBuffer = Zeroizing<Vec<u8>>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(lat: f64, lon: f64, unix_ms: i64) -> Fix {
        Fix::at(lat, lon, unix_ms)
    }

    // -- Activity ------------------------------------------------------------

    #[test]
    fn activity_classifies_by_speed() {
        assert_eq!(Activity::from_speed(0.0), Activity::Still);
        assert_eq!(Activity::from_speed(0.5), Activity::Still);
        assert_eq!(Activity::from_speed(1.2), Activity::Walking);
        assert_eq!(Activity::from_speed(3.0), Activity::Running);
        assert_eq!(Activity::from_speed(6.0), Activity::Cycling);
        assert_eq!(Activity::from_speed(25.0), Activity::Driving);
    }

    #[test]
    fn activity_treats_unknown_speed_as_still() {
        // A platform that omits speed must not be reported as driving.
        assert_eq!(Activity::from_speed(f32::NAN), Activity::Still);
        assert_eq!(Activity::from_speed(-1.0), Activity::Still);
    }

    #[test]
    fn activity_boundaries_are_inclusive_at_the_lower_edge() {
        assert_eq!(Activity::from_speed(WALK_SPEED_MPS), Activity::Running);
        assert_eq!(Activity::from_speed(RUN_SPEED_MPS), Activity::Cycling);
        assert_eq!(Activity::from_speed(CYCLE_SPEED_MPS), Activity::Driving);
    }

    // -- Haversine -----------------------------------------------------------

    #[test]
    fn haversine_zero_for_identical_points() {
        assert!(haversine_m(41.8781, -87.6298, 41.8781, -87.6298) < 1e-9);
    }

    #[test]
    fn haversine_matches_known_city_distance() {
        // Chicago -> New York, ~1145 km.
        let d = haversine_m(41.8781, -87.6298, 40.7128, -74.0060);
        assert!(
            (1_140_000.0..1_160_000.0).contains(&d),
            "expected ~1145 km, got {d} m"
        );
    }

    #[test]
    fn haversine_is_symmetric() {
        let a = haversine_m(10.0, 20.0, 30.0, 40.0);
        let b = haversine_m(30.0, 40.0, 10.0, 20.0);
        assert!((a - b).abs() < 1e-6);
    }

    #[test]
    fn haversine_handles_antimeridian() {
        // 179.9E -> 179.9W is ~22 km at the equator, not nearly the whole globe.
        let d = haversine_m(0.0, 179.9, 0.0, -179.9);
        assert!((20_000.0..25_000.0).contains(&d), "got {d} m");
    }

    #[test]
    fn haversine_handles_antipodes_without_nan() {
        let d = haversine_m(0.0, 0.0, 0.0, 180.0);
        assert!(d.is_finite(), "antipodal distance must be finite");
        assert!(d > 20_000_000.0, "half the globe, got {d} m");
    }

    #[test]
    fn haversine_rejects_nothing_but_is_finite_for_extremes() {
        for (lat, lon) in [(90.0, 0.0), (-90.0, 0.0), (0.0, -180.0)] {
            let d = haversine_m(0.0, 0.0, lat, lon);
            assert!(d.is_finite(), "distance to ({lat},{lon}) must be finite");
        }
    }

    #[test]
    fn coordinate_validation() {
        assert!(is_valid_coordinate(0.0, 0.0));
        assert!(is_valid_coordinate(90.0, 180.0));
        assert!(is_valid_coordinate(-90.0, -180.0));
        assert!(!is_valid_coordinate(90.1, 0.0));
        assert!(!is_valid_coordinate(0.0, 180.1));
        assert!(!is_valid_coordinate(f64::NAN, 0.0));
        assert!(!is_valid_coordinate(0.0, f64::INFINITY));
    }

    #[test]
    fn fix_validation_rejects_out_of_range_and_bad_time() {
        assert_eq!(fix(41.0, -87.0, 1).validate().expect("valid"), ());
        assert_eq!(
            fix(91.0, 0.0, 1).validate().expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
        assert_eq!(
            fix(0.0, 0.0, 0).validate().expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
    }

    // -- GeoGate -------------------------------------------------------------

    #[test]
    fn gate_publishes_first_fix() {
        let gate = GeoGate::new();
        assert_eq!(gate.evaluate(&fix(41.0, -87.0, 1_000)).expect("eval"), Publish::Yes);
    }

    #[test]
    fn gate_rejects_invalid_fix() {
        let gate = GeoGate::new();
        let err = gate.evaluate(&fix(999.0, 0.0, 1)).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvalidArgument);
    }

    #[test]
    fn gate_skips_when_cooldown_active() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 1_000_000));

        // Moved a long way, but only 5 s later: cooldown wins.
        let decision = gate
            .evaluate(&fix(41.0100, -87.0000, 1_005_000))
            .expect("eval");
        match decision {
            Publish::No(SkipReason::CooldownActive { waited_s, required_s }) => {
                assert_eq!(waited_s, 5);
                assert_eq!(required_s, MIN_INTERVAL_SECS);
            }
            other => panic!("expected cooldown skip, got {other:?}"),
        }
    }

    #[test]
    fn gate_skips_when_movement_is_below_threshold() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 1_000_000));

        // ~11 m north after 60 s: enough time, not enough distance.
        let decision = gate
            .evaluate(&fix(41.0001, -87.0000, 1_060_000))
            .expect("eval");
        match decision {
            Publish::No(SkipReason::MovedTooLittle {
                moved_m,
                required_m,
                waited_s,
            }) => {
                assert!(moved_m < MIN_MOVE_METERS, "moved {moved_m} m");
                assert_eq!(required_m, MIN_MOVE_METERS);
                assert_eq!(waited_s, 60);
            }
            other => panic!("expected movement skip, got {other:?}"),
        }
    }

    #[test]
    fn gate_publishes_when_moved_enough_after_cooldown() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 1_000_000));

        // ~22 m north after exactly 30 s.
        let decision = gate
            .evaluate(&fix(41.0002, -87.0000, 1_030_000))
            .expect("eval");
        assert_eq!(decision, Publish::Yes);
    }

    #[test]
    fn gate_publishes_heartbeat_when_stationary() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 1_000_000));

        let decision = gate
            .evaluate(&fix(41.0000, -87.0000, 1_900_000))
            .expect("eval");
        assert_eq!(decision, Publish::Yes, "900 s of stillness is a heartbeat");
    }

    #[test]
    fn gate_does_not_heartbeat_just_before_threshold() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 1_000_000));

        let decision = gate
            .evaluate(&fix(41.0000, -87.0000, 1_000_000 + 899_000))
            .expect("eval");
        assert!(matches!(decision, Publish::No(_)));
    }

    #[test]
    fn gate_skips_out_of_order_fixes() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 2_000_000));

        let decision = gate
            .evaluate(&fix(42.0000, -88.0000, 1_000_000))
            .expect("eval");
        assert!(matches!(decision, Publish::No(_)), "stale fix must not publish");
    }

    #[test]
    fn gate_skips_duplicate_timestamp() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0000, -87.0000, 2_000_000));
        let decision = gate
            .evaluate(&fix(42.0000, -88.0000, 2_000_000))
            .expect("eval");
        assert!(matches!(decision, Publish::No(_)));
    }

    #[test]
    fn gate_cooldown_boundary_is_inclusive() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0, -87.0, 1_000_000));
        // Exactly 30 s with no movement -> heartbeat not reached, so skip.
        let decision = gate.evaluate(&fix(41.0, -87.0, 1_030_000)).expect("eval");
        assert!(matches!(decision, Publish::No(_)));

        // 29 s with large movement -> still cooldown.
        let decision = gate.evaluate(&fix(41.01, -87.0, 1_029_000)).expect("eval");
        assert!(matches!(decision, Publish::No(SkipReason::CooldownActive { .. })));
    }

    #[test]
    fn gate_reset_clears_history() {
        let mut gate = GeoGate::new();
        gate.record_published(fix(41.0, -87.0, 1_000_000));
        assert!(gate.last_published().is_some());
        gate.reset();
        assert!(gate.last_published().is_none());
        assert_eq!(gate.evaluate(&fix(41.0, -87.0, 1_000_001)).expect("eval"), Publish::Yes);
    }

    #[test]
    fn gate_with_custom_thresholds_validates_arguments() {
        assert!(GeoGate::with_thresholds(5.0, 10, 60).is_ok());
        assert_eq!(
            GeoGate::with_thresholds(-1.0, 10, 60).expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
        assert_eq!(
            GeoGate::with_thresholds(5.0, 0, 60).expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
        assert_eq!(
            GeoGate::with_thresholds(5.0, 60, 30).expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
        assert_eq!(
            GeoGate::with_thresholds(f64::NAN, 10, 60).expect_err("must fail").kind(),
            crate::error::AppErrorKind::InvalidArgument
        );
    }

    #[test]
    fn gate_with_custom_thresholds_applies_them() {
        let mut gate = GeoGate::with_thresholds(100.0, 5, 20).expect("gate");
        gate.record_published(fix(41.0, -87.0, 1_000_000));
        // 50 m after 6 s: time is fine, distance is not.
        let decision = gate.evaluate(&fix(41.00045, -87.0, 1_006_000)).expect("eval");
        match decision {
            Publish::No(SkipReason::MovedTooLittle { required_m, .. }) => {
                assert_eq!(required_m, 100.0);
            }
            other => panic!("expected movement skip, got {other:?}"),
        }
    }

    // -- Jitter --------------------------------------------------------------

    #[test]
    fn jitter_is_deterministic_for_a_seed() {
        let mut a = Jitter::with_seed(42);
        let mut b = Jitter::with_seed(42);
        for _ in 0..10 {
            assert_eq!(a.next_unit(), b.next_unit());
        }
    }

    #[test]
    fn jitter_produces_values_in_unit_interval() {
        let mut jitter = Jitter::with_seed(12345);
        for _ in 0..1_000 {
            let v = jitter.next_unit();
            assert!((0.0..1.0).contains(&v), "out of range: {v}");
        }
    }

    #[test]
    fn jitter_is_reasonably_uniform() {
        let mut jitter = Jitter::with_seed(7);
        let buckets = 10;
        let mut counts = [0usize; 10];
        let samples = 10_000;
        for _ in 0..samples {
            let index = (jitter.next_unit() * buckets as f64) as usize;
            counts[index.min(buckets - 1)] += 1;
        }
        let expected = samples / buckets;
        for (i, count) in counts.iter().enumerate() {
            let deviation = ((*count as f64 - expected as f64) / expected as f64).abs();
            assert!(deviation < 0.25, "bucket {i} deviated {deviation:.2}");
        }
    }

    #[test]
    fn jitter_zero_state_is_not_a_fixed_point() {
        let mut jitter = Jitter::with_seed(0);
        let a = jitter.next_unit();
        let b = jitter.next_unit();
        assert_ne!(a, b, "zero seed must be nudged");
    }

    #[test]
    fn apply_jitter_stays_within_bounds() {
        let base = Duration::from_secs(60);
        // unit = 0 -> -25%, unit = 1 -> +25% (clamped endpoints).
        assert_eq!(apply_jitter(base, 0.0), Duration::from_millis(45_000));
        assert_eq!(apply_jitter(base, 1.0), Duration::from_millis(75_000));
        // unit = 0.5 -> no change.
        assert_eq!(apply_jitter(base, 0.5), Duration::from_millis(60_000));
        // Out-of-range input is clamped, not panicking.
        assert_eq!(apply_jitter(base, -100.0), Duration::from_millis(45_000));
        assert_eq!(apply_jitter(base, 100.0), Duration::from_millis(75_000));
    }

    #[test]
    fn jitter_apply_never_returns_zero_for_positive_base() {
        let mut jitter = Jitter::with_seed(999);
        for _ in 0..500 {
            let d = jitter.apply(Duration::from_secs(10));
            assert!(
                d >= Duration::from_millis(7_000) && d <= Duration::from_millis(13_000),
                "10 s ±25% produced {d:?}"
            );
        }
    }

    // -- AdaptiveBackoff -----------------------------------------------------

    #[test]
    fn backoff_starts_at_base() {
        let backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        assert_eq!(backoff.current(), Duration::from_secs(10));
        assert_eq!(backoff.base(), Duration::from_secs(10));
        assert_eq!(backoff.consecutive_not_modified(), 0);
    }

    #[test]
    fn backoff_halves_nothing_and_doubles_on_third_quiet_poll() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        backoff.observe(true);
        assert_eq!(backoff.current(), Duration::from_secs(10), "after 1");
        backoff.observe(true);
        assert_eq!(backoff.current(), Duration::from_secs(10), "after 2");
        backoff.observe(true);
        assert_eq!(backoff.current(), Duration::from_secs(20), "after 3");
        assert_eq!(backoff.consecutive_not_modified(), 0, "counter resets");
    }

    #[test]
    fn backoff_requires_a_full_run_each_time() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        for _ in 0..3 {
            backoff.observe(true);
        }
        assert_eq!(backoff.current(), Duration::from_secs(20));

        // A single extra 304 must not immediately double again.
        backoff.observe(true);
        assert_eq!(backoff.current(), Duration::from_secs(20));

        for _ in 0..2 {
            backoff.observe(true);
        }
        assert_eq!(backoff.current(), Duration::from_secs(40));
    }

    #[test]
    fn backoff_resets_on_changed_response() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        for _ in 0..6 {
            backoff.observe(true);
        }
        assert_eq!(backoff.current(), Duration::from_secs(40));

        backoff.observe(false);
        assert_eq!(backoff.current(), Duration::from_secs(10));
        assert_eq!(backoff.consecutive_not_modified(), 0);
    }

    #[test]
    fn backoff_respects_the_cap() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        for _ in 0..200 {
            backoff.observe(true);
        }
        assert_eq!(backoff.current(), Duration::from_secs(BACKOFF_CAP_SECS));
    }

    #[test]
    fn backoff_cap_is_at_least_the_base() {
        // A base longer than the global cap must not cause the interval to shrink.
        let base = Duration::from_secs(BACKOFF_CAP_SECS + 120);
        let backoff = AdaptiveBackoff::new(base);
        assert_eq!(backoff.current(), base);
    }

    #[test]
    fn backoff_next_delay_is_jittered_around_current() {
        let backoff = AdaptiveBackoff::new(Duration::from_secs(60));
        let mut jitter = Jitter::with_seed(2024);
        for _ in 0..200 {
            let d = backoff.next_delay(&mut jitter);
            assert!(
                d >= Duration::from_millis(45_000) && d <= Duration::from_millis(75_000),
                "60 s ±25% produced {d:?}"
            );
        }
    }

    #[test]
    fn backoff_reset_is_immediate() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        for _ in 0..50 {
            backoff.observe(true);
        }
        backoff.reset();
        assert_eq!(backoff.current(), Duration::from_secs(10));
        assert_eq!(backoff.consecutive_not_modified(), 0);
    }

    #[test]
    fn backoff_only_ever_lengthens_intervals() {
        let mut backoff = AdaptiveBackoff::new(Duration::from_secs(10));
        let mut previous = backoff.current();
        for _ in 0..100 {
            backoff.observe(true);
            assert!(
                backoff.current() >= previous,
                "interval shrank from {previous:?} to {:?}",
                backoff.current()
            );
            previous = backoff.current();
        }
    }

    // -- RateLimitHalt -------------------------------------------------------

    #[test]
    fn halt_starts_clear() {
        let halt = RateLimitHalt::new();
        assert!(!halt.is_halted(1_000));
        assert!(halt.halted_until().is_none());
        assert!(halt.remaining_secs(1_000).is_none());
        assert!(halt.last_remaining().is_none());
        assert!(halt.budget_fraction().is_none());
    }

    #[test]
    fn halt_trips_on_429() {
        let mut halt = RateLimitHalt::new();
        halt.observe(429, Some(1_700_000_000), Some(0));

        assert!(halt.is_halted(1_700_000_000));
        assert_eq!(
            halt.halted_until(),
            Some(1_700_000_000 + RATE_LIMIT_PADDING_SECS)
        );
        assert_eq!(halt.remaining_secs(1_700_000_000), Some(60));
        assert!(halt.is_halted(1_700_000_059));
        assert!(!halt.is_halted(1_700_000_060));
    }

    #[test]
    fn halt_trips_on_403_with_zero_remaining() {
        let mut halt = RateLimitHalt::new();
        halt.observe(403, Some(1_800_000_000), Some(0));
        assert!(halt.is_halted(1_800_000_000));
    }

    #[test]
    fn halt_ignores_403_with_budget_left() {
        let mut halt = RateLimitHalt::new();
        halt.observe(403, Some(1_800_000_000), Some(500));
        assert!(!halt.is_halted(1_800_000_000), "403 alone is not a rate limit");
    }

    #[test]
    fn halt_ignores_429_without_a_reset_header() {
        let mut halt = RateLimitHalt::new();
        halt.observe(429, None, Some(0));
        assert!(
            !halt.is_halted(1_800_000_000),
            "without a reset time we cannot know how long to wait"
        );
    }

    #[test]
    fn halt_does_not_trip_on_success() {
        let mut halt = RateLimitHalt::new();
        halt.observe(200, Some(1_800_000_000), Some(4_999));
        assert!(!halt.is_halted(1_800_000_000));
    }

    #[test]
    fn halt_tracks_remaining_and_limit_for_the_budget_bar() {
        let mut halt = RateLimitHalt::new();
        halt.observe(200, None, Some(1_250));
        halt.observe_limit(Some(5_000));

        assert_eq!(halt.last_remaining(), Some(1_250));
        assert_eq!(halt.last_limit(), Some(5_000));
        let fraction = halt.budget_fraction().expect("fraction");
        assert!((fraction - 0.25).abs() < 1e-9, "got {fraction}");
    }

    #[test]
    fn halt_budget_fraction_is_none_without_a_limit() {
        let mut halt = RateLimitHalt::new();
        halt.observe(200, None, Some(10));
        assert!(halt.budget_fraction().is_none());
    }

    #[test]
    fn halt_budget_fraction_handles_zero_limit() {
        let mut halt = RateLimitHalt::new();
        halt.observe(200, None, Some(0));
        halt.observe_limit(Some(0));
        assert!(halt.budget_fraction().is_none());
    }

    #[test]
    fn halt_clear_resumes_immediately() {
        let mut halt = RateLimitHalt::new();
        halt.observe(429, Some(1_700_000_000), Some(0));
        assert!(halt.is_halted(1_700_000_000));
        halt.clear();
        assert!(!halt.is_halted(1_700_000_000));
    }

    #[test]
    fn halt_keeps_the_latest_reset_window() {
        let mut halt = RateLimitHalt::new();
        halt.observe(429, Some(1_000), Some(0));
        halt.observe(429, Some(2_000), Some(0));
        assert_eq!(halt.halted_until(), Some(2_060));
    }

    #[test]
    fn halt_does_not_shrink_an_existing_window() {
        let mut halt = RateLimitHalt::new();
        halt.observe(429, Some(2_000), Some(0));
        // A later, stale header must not pull the resume time earlier.
        halt.observe(200, None, Some(1_000));
        assert_eq!(halt.halted_until(), Some(2_060));
    }

    // -- Combined budgets ----------------------------------------------------

    #[test]
    fn plan_cadences_fit_the_shared_budget() {
        // Sanity check that the plan's cadence is arithmetically survivable with
        // 50 members' comments spread over a 5,000 req/hr budget, assuming a
        // realistic ETag hit rate.
        let chat_interval_s = 10.0_f64;
        let roster_interval_s = 30.0_f64;
        let members = 50.0_f64;
        let budget = 5_000.0_f64;

        // Worst case: every poll is a 200, never a 304.
        let polls_per_hour = (3_600.0 / chat_interval_s) + (3_600.0 / roster_interval_s) * members;
        assert!(
            polls_per_hour > budget,
            "worst case should indeed exceed the budget: {polls_per_hour}"
        );

        // With the adaptive backoff cap in force on a quiet roster channel, the
        // roster cost drops by the backoff factor.
        let backed_off_roster = (3_600.0 / BACKOFF_CAP_SECS as f64) * members;
        let with_backoff = (3_600.0 / chat_interval_s) + backed_off_roster;
        assert!(
            with_backoff < budget,
            "backoff must bring the group back under budget: {with_backoff}"
        );
    }
}