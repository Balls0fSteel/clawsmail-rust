//! Cache policy: how much of a mailbox is kept on local disk.
//!
//! A policy can be set globally, per account and per folder. The most
//! specific setting wins, field by field: a folder may override only the
//! mode and still inherit the body-cache budget from its account.

use serde::{Deserialize, Serialize};

/// How message content is stored locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Envelopes, structure and bodies are downloaded for offline reading.
    Full,
    /// Only envelopes, flags and MIME structure are stored. Bodies and
    /// attachments are fetched from the server when opened.
    Remote,
}

/// A partial cache setting at one level (global, account or folder).
/// `None` fields inherit from the next less specific level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<CacheMode>,
    /// Size budget of the on-demand body cache in Remote mode, in MiB.
    /// 0 keeps fetched bodies in memory only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_cache_mib: Option<u32>,
    /// Only sync headers (and in Full mode, bodies) of messages newer than
    /// this many days. 0 means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_days: Option<u32>,
}

/// A fully resolved cache policy for one folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    pub mode: CacheMode,
    pub body_cache_mib: u32,
    pub window_days: u32,
}

impl CachePolicy {
    /// Defaults used when no level sets a field.
    pub const DEFAULT: CachePolicy = CachePolicy {
        mode: CacheMode::Remote,
        body_cache_mib: 200,
        window_days: 0,
    };

    /// Resolve a policy from the most specific level to the least specific.
    pub fn resolve(
        folder: &CacheSettings,
        account: &CacheSettings,
        global: &CacheSettings,
    ) -> Self {
        let levels = [folder, account, global];
        let pick = |f: fn(&CacheSettings) -> Option<u32>, default: u32| {
            levels.iter().find_map(|s| f(s)).unwrap_or(default)
        };
        CachePolicy {
            mode: levels
                .iter()
                .find_map(|s| s.mode)
                .unwrap_or(Self::DEFAULT.mode),
            body_cache_mib: pick(|s| s.body_cache_mib, Self::DEFAULT.body_cache_mib),
            window_days: pick(|s| s.window_days, Self::DEFAULT.window_days),
        }
    }

    /// True when message bodies may be written to disk.
    pub fn stores_bodies_on_disk(&self) -> bool {
        match self.mode {
            CacheMode::Full => true,
            CacheMode::Remote => self.body_cache_mib > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_levels_give_defaults() {
        let none = CacheSettings::default();
        assert_eq!(
            CachePolicy::resolve(&none, &none, &none),
            CachePolicy::DEFAULT
        );
    }

    #[test]
    fn most_specific_level_wins_per_field() {
        let global = CacheSettings {
            mode: Some(CacheMode::Full),
            body_cache_mib: Some(500),
            window_days: Some(365),
        };
        let account = CacheSettings {
            mode: Some(CacheMode::Remote),
            ..Default::default()
        };
        let folder = CacheSettings {
            body_cache_mib: Some(0),
            ..Default::default()
        };
        let p = CachePolicy::resolve(&folder, &account, &global);
        assert_eq!(p.mode, CacheMode::Remote);
        assert_eq!(p.body_cache_mib, 0);
        assert_eq!(p.window_days, 365);
        assert!(!p.stores_bodies_on_disk());
    }

    #[test]
    fn full_mode_always_stores_bodies() {
        let folder = CacheSettings {
            mode: Some(CacheMode::Full),
            body_cache_mib: Some(0),
            window_days: None,
        };
        let none = CacheSettings::default();
        assert!(CachePolicy::resolve(&folder, &none, &none).stores_bodies_on_disk());
    }

    #[test]
    fn settings_round_trip_through_toml() {
        let s = CacheSettings {
            mode: Some(CacheMode::Remote),
            body_cache_mib: Some(0),
            window_days: None,
        };
        let text = toml::to_string(&s).unwrap();
        assert_eq!(text.trim(), "mode = \"remote\"\nbody_cache_mib = 0");
        assert_eq!(toml::from_str::<CacheSettings>(&text).unwrap(), s);
    }
}
