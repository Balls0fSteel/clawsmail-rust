//! Fake message-list rows, generated on demand so 100,000 rows cost no memory.

const SUBJECTS: &[&str] = &[
    "Re: Quarterly report draft",
    "Build failed on main",
    "Lunch on Friday?",
    "[rust-users] Async traits in 2026",
    "Your invoice is ready",
    "Fwd: Conference travel",
    "[claws-mail-users] Filtering by header",
    "Meeting notes",
    "Re: Re: Patch review",
    "Weekly digest",
];

const SENDERS: &[&str] = &[
    "Alice Example <alice@example.com>",
    "Bob Builder <bob@example.org>",
    "CI Robot <ci@example.net>",
    "Dóra Kovács <dora@example.hu>",
    "rust-users list <rust-users@example.com>",
    "Eve Tracker <news@example.com>",
    "Frank <frank@example.org>",
];

pub const COLUMNS: &[(&str, i32)] = &[("Subject", 420), ("From", 260), ("Date", 140)];

/// Text of one cell. Row 0 is the newest message.
pub fn cell(row: usize, column: i32) -> String {
    match column {
        0 => format!("{} #{}", SUBJECTS[row % SUBJECTS.len()], row + 1),
        1 => SENDERS[(row * 7 + row / 3) % SENDERS.len()].to_string(),
        _ => date(row),
    }
}

/// 2026-11-17 21:00 minus 17 minutes per row, as `YYYY-MM-DD HH:MM`.
fn date(row: usize) -> String {
    const START: i64 = 1_794_949_200; // 2026-11-17 21:00:00 local, treated as UTC here
    let t = START - row as i64 * 17 * 60;
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs % 3600 / 60)
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::date(0), "2026-11-17 21:00");
        assert_eq!(super::civil_from_days(0), (1970, 1, 1));
    }
}
