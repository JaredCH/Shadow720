//! Long-term location history, kept on this device only.
//!
//! The fading trail in [`crate::group`] is a *visual aid*: sixty points, roughly
//! half an hour, thrown away when the app closes. This module is the opposite — a
//! month-long track log that survives restarts, so "where was everyone on
//! Tuesday" is answerable.
//!
//! # Why it is local-only
//!
//! History is never published. Relays and GitHub only ever hold a member's
//! *current* position, which is what keeps the group's shared footprint the same
//! size whether the app has been running for a minute or a month. Each device
//! records what it can see and nothing more, so a member who was offline for a
//! week simply has a gap rather than a fabricated line.
//!
//! # Resolution
//!
//! Storing every fix for a month would be tens of thousands of points per member.
//! Instead the log keeps full resolution for the last [`HISTORY_FULL_RES_MS`] and
//! thins older points to one per [`HISTORY_THIN_INTERVAL_MS`]. A month of driving
//! therefore costs a few thousand points, which is small enough to seal into one
//! file and load at startup.
//!
//! # Storage
//!
//! The log is sealed with the group key and written beside the vault, so it is
//! unreadable without the device key *and* the group key. Losing the vault loses
//! the history with it, which is the correct outcome: the history is as sensitive
//! as the live positions it was built from.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, GROUP_KEY_LEN};
use crate::error::{AppError, Result};
use crate::geo_filter::{haversine_m, Activity};

/// How long a point is kept, in days.
pub const HISTORY_RETENTION_DAYS: i64 = 31;
/// [`HISTORY_RETENTION_DAYS`] in milliseconds.
pub const HISTORY_RETENTION_MS: i64 = HISTORY_RETENTION_DAYS * 24 * 60 * 60 * 1_000;
/// Points newer than this keep their original resolution.
pub const HISTORY_FULL_RES_MS: i64 = 6 * 60 * 60 * 1_000;
/// Older points are thinned to at most one per this interval.
pub const HISTORY_THIN_INTERVAL_MS: i64 = 15 * 60 * 1_000;
/// Hard cap per member, so a pathological publisher cannot grow the file forever.
pub const HISTORY_MAX_POINTS: usize = 4_000;
/// A point closer than this to the previous one is collapsed, in metres.
pub const HISTORY_MIN_SPACING_M: f64 = 8.0;
/// File name inside the vault directory.
pub const HISTORY_FILENAME: &str = "history.bin";

/// One recorded position, with the context needed to explain it later.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackPoint {
    pub lat: f64,
    pub lon: f64,
    pub unix_ms: i64,
    /// Ground speed as reported at the time, metres per second.
    pub speed_mps: f32,
    /// Smoothed activity, so a day view can say "mostly driving".
    pub activity: Activity,
    /// Battery percentage, or `0` when the peer did not report one.
    pub battery_pct: u8,
    pub is_charging: bool,
}

impl TrackPoint {
    /// True when this point carries no usable battery reading.
    pub fn battery_unknown(&self) -> bool {
        self.battery_pct == 0
    }
}

/// Every member's track log, oldest point first.
#[derive(Default)]
pub struct TrackHistory {
    members: HashMap<String, Vec<TrackPoint>>,
    /// True when the in-memory log has changed since the last successful save.
    dirty: bool,
}

impl std::fmt::Debug for TrackHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackHistory")
            .field("members", &self.members.len())
            .field("points", &self.total_points())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl TrackHistory {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total points across every member, for diagnostics.
    pub fn total_points(&self) -> usize {
        self.members.values().map(Vec::len).sum()
    }

    /// True when the log has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the log as saved.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Append a point for `pubkey`, collapsing duplicates and pruning old data.
    ///
    /// Returns `true` when the point was actually stored, which lets the caller
    /// avoid marking the log dirty for a no-op.
    pub fn record(&mut self, pubkey: &str, point: TrackPoint, now_ms: i64) -> bool {
        if !point.lat.is_finite() || !point.lon.is_finite() || point.unix_ms <= 0 {
            return false;
        }

        let points = self.members.entry(pubkey.to_string()).or_default();

        if let Some(previous) = points.last() {
            // Out-of-order or repeated timestamps carry no new information.
            if point.unix_ms <= previous.unix_ms {
                return false;
            }
            // A member who has not moved and whose battery has not changed adds
            // nothing but file size.
            let moved = haversine_m(previous.lat, previous.lon, point.lat, point.lon);
            if moved < HISTORY_MIN_SPACING_M
                && previous.activity == point.activity
                && previous.battery_pct == point.battery_pct
                && previous.is_charging == point.is_charging
            {
                return false;
            }
        }

        points.push(point);
        prune(points, now_ms);
        self.dirty = true;
        true
    }

    /// Points for one member at or after `since_ms`, oldest first.
    pub fn points_since(&self, pubkey: &str, since_ms: i64) -> Vec<TrackPoint> {
        self.members
            .get(pubkey)
            .map(|points| {
                points
                    .iter()
                    .copied()
                    .filter(|point| point.unix_ms >= since_ms)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every member's points at or after `since_ms`.
    pub fn snapshot_since(&self, since_ms: i64) -> HashMap<String, Vec<TrackPoint>> {
        self.members
            .iter()
            .filter_map(|(pubkey, points)| {
                let filtered: Vec<TrackPoint> = points
                    .iter()
                    .copied()
                    .filter(|point| point.unix_ms >= since_ms)
                    .collect();
                if filtered.is_empty() {
                    None
                } else {
                    Some((pubkey.clone(), filtered))
                }
            })
            .collect()
    }

    /// Drop every point for one member.
    pub fn forget(&mut self, pubkey: &str) {
        if self.members.remove(pubkey).is_some() {
            self.dirty = true;
        }
    }

    /// Drop everything.
    pub fn clear(&mut self) {
        if !self.members.is_empty() {
            self.members.clear();
            self.dirty = true;
        }
    }

    /// Prune every member against `now_ms`.
    pub fn prune_all(&mut self, now_ms: i64) {
        for points in self.members.values_mut() {
            prune(points, now_ms);
        }
        self.members.retain(|_, points| !points.is_empty());
    }

    /// Seal the log into `dir`, replacing any previous file.
    ///
    /// Written to a temporary file and renamed, so an interrupted write cannot
    /// leave a half-sealed log that fails to open on the next launch.
    pub fn save(&mut self, dir: &Path, group_key: &[u8; GROUP_KEY_LEN]) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.members)
            .map_err(|e| AppError::io("serializing location history", e.to_string()))?;
        let sealed = crypto::seal_blob(group_key, &plaintext)?;

        std::fs::create_dir_all(dir)
            .map_err(|e| AppError::io("creating the vault directory", e.to_string()))?;

        let target = dir.join(HISTORY_FILENAME);
        let temporary = dir.join(format!("{HISTORY_FILENAME}.tmp"));
        std::fs::write(&temporary, &sealed)
            .map_err(|e| AppError::io("writing location history", e.to_string()))?;
        std::fs::rename(&temporary, &target)
            .map_err(|e| AppError::io("replacing location history", e.to_string()))?;

        self.dirty = false;
        Ok(())
    }

    /// Load the log from `dir`, or an empty log when none has been saved.
    ///
    /// A file that cannot be opened is reported rather than silently discarded:
    /// the caller decides whether to start fresh, and a corrupt log is worth
    /// knowing about.
    pub fn load(dir: &Path, group_key: &[u8; GROUP_KEY_LEN]) -> Result<Self> {
        let path = dir.join(HISTORY_FILENAME);
        if !path.exists() {
            return Ok(Self::new());
        }
        let sealed = std::fs::read(&path)
            .map_err(|e| AppError::io("reading location history", e.to_string()))?;
        let plaintext = crypto::open_blob(group_key, &sealed)?;
        let members: HashMap<String, Vec<TrackPoint>> = serde_json::from_slice(&plaintext)
            .map_err(|e| AppError::io("parsing location history", e.to_string()))?;

        let mut history = Self {
            members,
            dirty: false,
        };
        history.prune_all(crate::github_db::now_unix_ms());
        Ok(history)
    }

    /// Path the log is stored at, for diagnostics.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(HISTORY_FILENAME)
    }
}

/// Drop expired points, thin the older ones, and enforce the cap.
///
/// Thinning keeps the *newest* point of each interval, which is the one that best
/// describes where the member ended up.
///
/// Buckets are anchored to absolute time rather than to the previous kept point.
/// That matters because this runs on every recorded point: a relative bucket would
/// re-thin the already-thinned tail on each pass and quietly erase the older half
/// of the log. With absolute buckets the function is idempotent, so running it a
/// thousand times leaves the same points as running it once.
fn prune(points: &mut Vec<TrackPoint>, now_ms: i64) {
    let cutoff = now_ms.saturating_sub(HISTORY_RETENTION_MS);
    let full_res_from = now_ms.saturating_sub(HISTORY_FULL_RES_MS);

    let mut kept: Vec<TrackPoint> = Vec::with_capacity(points.len().min(HISTORY_MAX_POINTS));
    let mut last_bucket: Option<i64> = None;

    for point in points.iter().copied() {
        if point.unix_ms < cutoff {
            continue;
        }
        if point.unix_ms >= full_res_from {
            kept.push(point);
            continue;
        }
        let bucket = point.unix_ms.div_euclid(HISTORY_THIN_INTERVAL_MS);
        if last_bucket == Some(bucket) {
            // Same interval: keep the newest sample rather than the first.
            if let Some(slot) = kept.last_mut() {
                *slot = point;
            }
        } else {
            kept.push(point);
            last_bucket = Some(bucket);
        }
    }

    if kept.len() > HISTORY_MAX_POINTS {
        let excess = kept.len() - HISTORY_MAX_POINTS;
        kept.drain(0..excess);
    }

    *points = kept;
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 60 * 60 * 1_000;

    fn point(lat: f64, lon: f64, unix_ms: i64) -> TrackPoint {
        TrackPoint {
            lat,
            lon,
            unix_ms,
            speed_mps: 0.0,
            activity: Activity::Still,
            battery_pct: 80,
            is_charging: false,
        }
    }

    #[test]
    fn records_points_in_order() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        assert!(history.record("a", point(1.0, 1.0, now - 2_000), now));
        assert!(history.record("a", point(1.001, 1.0, now - 1_000), now));
        assert_eq!(history.points_since("a", 0).len(), 2);
    }

    #[test]
    fn collapses_a_stationary_member() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        assert!(history.record("a", point(1.0, 1.0, now - 2_000), now));
        // Same place, same battery: nothing new to say.
        assert!(!history.record("a", point(1.0, 1.0, now - 1_000), now));
        assert_eq!(history.points_since("a", 0).len(), 1);
    }

    #[test]
    fn records_a_battery_change_even_when_still() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        history.record("a", point(1.0, 1.0, now - 2_000), now);
        let mut drained = point(1.0, 1.0, now - 1_000);
        drained.battery_pct = 42;
        assert!(history.record("a", drained, now));
        assert_eq!(history.points_since("a", 0).len(), 2);
    }

    #[test]
    fn rejects_out_of_order_and_invalid_points() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        history.record("a", point(1.0, 1.0, now), now);
        assert!(!history.record("a", point(1.1, 1.0, now - 5_000), now));
        assert!(!history.record("a", point(f64::NAN, 1.0, now + 5_000), now));
        assert_eq!(history.points_since("a", 0).len(), 1);
    }

    #[test]
    fn drops_points_past_retention() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        let ancient = now - HISTORY_RETENTION_MS - HOUR_MS;
        history.record("a", point(1.0, 1.0, ancient), now);
        history.record("a", point(1.001, 1.0, now), now);
        let points = history.points_since("a", 0);
        assert_eq!(points.len(), 1, "the expired point must be dropped");
        assert_eq!(points.first().map(|p| p.unix_ms), Some(now));
    }

    #[test]
    fn thins_older_points_but_keeps_recent_ones() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        // One point a minute for 12 hours: 720 samples.
        for minute in 0..720 {
            let unix_ms = now - (720 - minute) * 60 * 1_000;
            let lat = 1.0 + minute as f64 * 0.001;
            history.record("a", point(lat, 1.0, unix_ms), now);
        }
        let points = history.points_since("a", 0);
        let recent = points
            .iter()
            .filter(|p| p.unix_ms >= now - HISTORY_FULL_RES_MS)
            .count();
        let older = points.len() - recent;
        // Six hours of full resolution, six hours thinned to one per 15 minutes.
        assert_eq!(recent, 360, "the recent window keeps every point");
        assert!(older <= 25, "older points are thinned, got {older}");
        assert!(older >= 20, "thinning must not discard the whole window");
    }

    #[test]
    fn pruning_is_idempotent() {
        // `record` prunes on every point, so a non-idempotent prune would erase
        // the older half of the log a little more on each fix.
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        for minute in 0..720 {
            let unix_ms = now - (720 - minute) * 60 * 1_000;
            history.record("a", point(1.0 + minute as f64 * 0.001, 1.0, unix_ms), now);
        }
        let once = history.points_since("a", 0);
        history.prune_all(now);
        history.prune_all(now);
        let thrice = history.points_since("a", 0);
        assert_eq!(once.len(), thrice.len(), "repeated pruning must be a no-op");
    }

    #[test]
    fn enforces_the_point_cap() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        for step in 0..(HISTORY_MAX_POINTS + 500) {
            let unix_ms = now - (HISTORY_MAX_POINTS as i64 + 500 - step as i64) * 1_000;
            let lat = 1.0 + step as f64 * 0.0001;
            history.record("a", point(lat, 1.0, unix_ms), now);
        }
        assert!(history.points_since("a", 0).len() <= HISTORY_MAX_POINTS);
    }

    #[test]
    fn snapshot_filters_by_time_and_skips_empty_members() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        history.record("a", point(1.0, 1.0, now - 10 * HOUR_MS), now);
        history.record("a", point(1.001, 1.0, now), now);
        history.record("b", point(2.0, 2.0, now - 10 * HOUR_MS), now);

        let snapshot = history.snapshot_since(now - HOUR_MS);
        assert_eq!(snapshot.get("a").map(Vec::len), Some(1));
        assert!(
            !snapshot.contains_key("b"),
            "a member with nothing in range is omitted rather than sent empty"
        );
    }

    #[test]
    fn forget_and_clear_mark_the_log_dirty() {
        let mut history = TrackHistory::new();
        let now = 1_700_000_000_000;
        history.record("a", point(1.0, 1.0, now), now);
        history.mark_clean();
        history.forget("a");
        assert!(history.is_dirty());
        history.mark_clean();
        history.record("b", point(2.0, 2.0, now), now);
        history.clear();
        assert!(history.is_dirty());
        assert_eq!(history.total_points(), 0);
    }

    #[test]
    fn save_and_load_round_trip_through_the_group_key() {
        let dir = std::env::temp_dir().join(format!("shadow720-history-{}", uuid::Uuid::new_v4()));
        let key = [9u8; GROUP_KEY_LEN];
        let now = crate::github_db::now_unix_ms();

        let mut history = TrackHistory::new();
        history.record("a", point(1.0, 1.0, now - 1_000), now);
        history.record("a", point(1.002, 1.0, now), now);
        history.save(&dir, &key).expect("save");
        assert!(!history.is_dirty());

        let loaded = TrackHistory::load(&dir, &key).expect("load");
        assert_eq!(loaded.points_since("a", 0).len(), 2);

        // A different key must not open it.
        assert!(TrackHistory::load(&dir, &[1u8; GROUP_KEY_LEN]).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_returns_empty_when_nothing_was_saved() {
        let dir = std::env::temp_dir().join(format!("shadow720-empty-{}", uuid::Uuid::new_v4()));
        let history = TrackHistory::load(&dir, &[3u8; GROUP_KEY_LEN]).expect("load");
        assert_eq!(history.total_points(), 0);
    }
}
