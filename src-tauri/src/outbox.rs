//! Offline location outbox.
//!
//! A fix that the movement gate decided was worth publishing can still fail to
//! reach a relay: a tunnel, a plane, a dead Wi-Fi network. Throwing that fix away
//! means the group's last sight of this member is wherever they were when the
//! connection dropped, which is exactly the moment the position matters most.
//!
//! So a failed publish is *deferred* rather than dropped. The fix is appended
//! here, sealed with the group key, and written beside the vault so it survives
//! the process being killed — which on Android is the normal outcome of a long
//! offline stretch.
//!
//! # Why the queue is coalesced on replay
//!
//! A member's roster slot is an addressable Nostr event keyed by their pubkey, so
//! publishing replaces the previous value. Replaying forty cached fixes would cost
//! forty relay round-trips and leave peers holding only the last one. The flush
//! therefore publishes the **newest** cached fix — the only one a peer can see —
//! and folds the rest into the local track log, where intermediate points are
//! genuinely useful and cost nothing to keep.
//!
//! # Bounds
//!
//! The queue is capped by both age and count. A device that is offline for a week
//! must not accumulate a week of positions: the oldest are dropped, because a
//! position from six days ago is not what "where are they now" is asking.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::{self, GROUP_KEY_LEN};
use crate::error::{AppError, Result};

/// File name inside the vault directory.
pub const OUTBOX_FILENAME: &str = "outbox.bin";
/// Most fixes kept while offline.
///
/// At the 30-second publish floor this is a little over four hours of movement,
/// which covers a flight or a long drive without letting a forgotten device grow
/// the file without bound.
pub const OUTBOX_MAX_POINTS: usize = 512;
/// Fixes older than this are dropped rather than replayed.
pub const OUTBOX_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1_000;

/// One fix that could not be published yet.
///
/// Carries the battery reading from the moment it was captured, not the current
/// one: replaying a fix with today's battery level would misreport the past.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingFix {
    pub lat: f64,
    pub lon: f64,
    pub unix_ms: i64,
    pub speed_mps: f32,
    pub heading_deg: f32,
    pub accuracy_m: f32,
    pub battery_pct: u8,
    pub is_charging: bool,
}

/// Fixes waiting for a connection, oldest first.
#[derive(Default)]
pub struct Outbox {
    pending: VecDeque<PendingFix>,
    /// True when the in-memory queue has changed since the last successful save.
    dirty: bool,
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field("pending", &self.pending.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl Outbox {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many fixes are waiting.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True when nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// True when the queue has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the queue as saved.
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Append a fix, returning the new queue length.
    ///
    /// A sample at or before the newest queued timestamp carries no new position,
    /// so it replaces the tail rather than extending it. That keeps a device that
    /// retries the same fix from filling the queue with duplicates.
    pub fn push(&mut self, fix: PendingFix, now_ms: i64) -> usize {
        if !fix.lat.is_finite() || !fix.lon.is_finite() || fix.unix_ms <= 0 {
            return self.pending.len();
        }

        if let Some(last) = self.pending.back_mut() {
            if fix.unix_ms < last.unix_ms {
                return self.pending.len();
            }
            if fix.unix_ms == last.unix_ms {
                *last = fix;
                self.dirty = true;
                return self.pending.len();
            }
        }

        self.pending.push_back(fix);
        self.dirty = true;
        self.prune(now_ms);
        self.pending.len()
    }

    /// The newest queued fix, which is the one worth publishing.
    pub fn newest(&self) -> Option<PendingFix> {
        self.pending.back().copied()
    }

    /// Remove every fix, oldest first.
    ///
    /// The caller owns the returned points until it either publishes them or
    /// hands them back with [`Outbox::restore`]. Nothing is written to disk here,
    /// so a crash mid-flush leaves the on-disk queue intact and the fixes are
    /// retried on the next launch.
    pub fn take(&mut self) -> Vec<PendingFix> {
        let taken: Vec<PendingFix> = self.pending.drain(..).collect();
        if !taken.is_empty() {
            self.dirty = true;
        }
        taken
    }

    /// Put fixes back at the front, e.g. after a flush failed.
    pub fn restore(&mut self, fixes: Vec<PendingFix>) {
        for fix in fixes.into_iter().rev() {
            self.pending.push_front(fix);
        }
        self.dirty = true;
        self.prune(crate::wire::now_unix_ms());
    }

    /// Drop everything.
    pub fn clear(&mut self) {
        if !self.pending.is_empty() {
            self.pending.clear();
            self.dirty = true;
        }
    }

    /// Drop expired fixes and enforce the count cap.
    fn prune(&mut self, now_ms: i64) {
        let cutoff = now_ms.saturating_sub(OUTBOX_MAX_AGE_MS);
        while let Some(front) = self.pending.front() {
            if front.unix_ms >= cutoff {
                break;
            }
            self.pending.pop_front();
            self.dirty = true;
        }
        while self.pending.len() > OUTBOX_MAX_POINTS {
            self.pending.pop_front();
            self.dirty = true;
        }
    }

    /// Seal the queue into `dir`, replacing any previous file.
    ///
    /// Written to a temporary file and renamed, so an interrupted write cannot
    /// leave a half-sealed queue that fails to open on the next launch.
    pub fn save(&mut self, dir: &Path, group_key: &[u8; GROUP_KEY_LEN]) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.pending)
            .map_err(|e| AppError::io("serializing the offline location cache", e.to_string()))?;
        let sealed = crypto::seal_blob(group_key, &plaintext)?;

        std::fs::create_dir_all(dir)
            .map_err(|e| AppError::io("creating the vault directory", e.to_string()))?;

        let target = dir.join(OUTBOX_FILENAME);
        let temporary = dir.join(format!("{OUTBOX_FILENAME}.tmp"));
        std::fs::write(&temporary, &sealed)
            .map_err(|e| AppError::io("writing the offline location cache", e.to_string()))?;
        std::fs::rename(&temporary, &target)
            .map_err(|e| AppError::io("replacing the offline location cache", e.to_string()))?;

        self.dirty = false;
        Ok(())
    }

    /// Load the queue from `dir`, or an empty queue when none has been saved.
    pub fn load(dir: &Path, group_key: &[u8; GROUP_KEY_LEN]) -> Result<Self> {
        let path = dir.join(OUTBOX_FILENAME);
        if !path.exists() {
            return Ok(Self::new());
        }
        let sealed = std::fs::read(&path)
            .map_err(|e| AppError::io("reading the offline location cache", e.to_string()))?;
        let plaintext = crypto::open_blob(group_key, &sealed)?;
        let pending: VecDeque<PendingFix> = serde_json::from_slice(&plaintext)
            .map_err(|e| AppError::io("parsing the offline location cache", e.to_string()))?;

        let mut outbox = Self {
            pending,
            dirty: false,
        };
        outbox.prune(crate::wire::now_unix_ms());
        Ok(outbox)
    }

    /// Path the queue is stored at, for diagnostics.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(OUTBOX_FILENAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A timestamp inside the retention window, relative to the real clock.
    ///
    /// The queue prunes against wall-clock time, so a hardcoded 2023 instant would
    /// be dropped as expired and every test would pass vacuously.
    fn recent(offset_ms: i64) -> i64 {
        crate::wire::now_unix_ms() - offset_ms
    }

    fn fix(lat: f64, lon: f64, unix_ms: i64) -> PendingFix {
        PendingFix {
            lat,
            lon,
            unix_ms,
            speed_mps: 0.0,
            heading_deg: 0.0,
            accuracy_m: 5.0,
            battery_pct: 80,
            is_charging: false,
        }
    }

    #[test]
    fn pushes_in_order_and_reports_the_newest() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        assert_eq!(outbox.push(fix(1.0, 1.0, now - 2_000), now), 1);
        assert_eq!(outbox.push(fix(1.1, 1.0, now - 1_000), now), 2);
        assert_eq!(outbox.newest().map(|f| f.lat), Some(1.1));
    }

    #[test]
    fn a_repeated_timestamp_replaces_rather_than_appends() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        outbox.push(fix(1.0, 1.0, now), now);
        outbox.push(fix(2.0, 2.0, now), now);
        assert_eq!(outbox.len(), 1, "the same instant is one position");
        assert_eq!(outbox.newest().map(|f| f.lat), Some(2.0));
    }

    #[test]
    fn an_out_of_order_sample_is_ignored() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        outbox.push(fix(1.0, 1.0, now), now);
        outbox.push(fix(9.0, 9.0, now - 5_000), now);
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox.newest().map(|f| f.lat), Some(1.0));
    }

    #[test]
    fn invalid_coordinates_are_rejected() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        assert_eq!(outbox.push(fix(f64::NAN, 1.0, now), now), 0);
        assert_eq!(outbox.push(fix(1.0, 1.0, 0), now), 0);
        assert!(outbox.is_empty());
    }

    #[test]
    fn expired_fixes_are_dropped() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        outbox.push(fix(1.0, 1.0, now - OUTBOX_MAX_AGE_MS - 1_000), now);
        assert!(outbox.is_empty(), "a fix older than the window is not replayed");
    }

    #[test]
    fn the_count_cap_keeps_the_newest() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        let base = now - 1_000_000;
        for index in 0..(OUTBOX_MAX_POINTS + 10) {
            let stamp = base + i64::try_from(index).expect("index") * 1_000;
            outbox.push(fix(1.0, 1.0, stamp), now);
        }
        assert_eq!(outbox.len(), OUTBOX_MAX_POINTS);
        assert_eq!(
            outbox.newest().map(|f| f.unix_ms),
            Some(base + i64::try_from(OUTBOX_MAX_POINTS + 9).expect("index") * 1_000),
            "the newest sample must survive the cap"
        );
    }

    #[test]
    fn take_empties_and_restore_puts_them_back() {
        let mut outbox = Outbox::new();
        let now = recent(0);
        outbox.push(fix(1.0, 1.0, now - 2_000), now);
        outbox.push(fix(1.1, 1.0, now - 1_000), now);

        let taken = outbox.take();
        assert_eq!(taken.len(), 2);
        assert!(outbox.is_empty());

        outbox.restore(taken);
        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox.newest().map(|f| f.lat), Some(1.1));
    }

    #[test]
    fn a_round_trip_through_disk_preserves_the_queue() {
        let dir = std::env::temp_dir().join(format!(
            "shadow720-outbox-{}",
            crate::wire::now_unix_ms()
        ));
        let key = [7u8; GROUP_KEY_LEN];

        let mut outbox = Outbox::new();
        let now = recent(0);
        outbox.push(fix(41.8781, -87.6298, now - 1_000), now);
        outbox.save(&dir, &key).expect("save");
        assert!(!outbox.is_dirty());

        let loaded = Outbox::load(&dir, &key).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.newest().map(|f| f.lon), Some(-87.6298));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_loads_as_empty() {
        let dir = std::env::temp_dir().join("shadow720-outbox-absent");
        let loaded = Outbox::load(&dir, &[1u8; GROUP_KEY_LEN]).expect("load");
        assert!(loaded.is_empty());
    }
}
