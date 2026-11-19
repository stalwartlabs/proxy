/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;
use std::time::SystemTime;

use serde::{Serialize, Serializer};

const SECS_PER_DAY: u64 = 86_400;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct UtcTime(pub SystemTime);

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u64,
    minute: u64,
    second: u64,
}

impl UtcTime {
    fn civil(self) -> Civil {
        let secs = self
            .0
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let rem = secs % SECS_PER_DAY;
        let (year, month, day) = civil_from_days(i64::try_from(secs / SECS_PER_DAY).unwrap_or(0));
        Civil {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem % 3600 / 60,
            second: rem % 60,
        }
    }

    pub fn compact(self) -> Compact {
        Compact(self)
    }
}

impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.civil();
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    }
}

impl Serialize for UtcTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

pub struct Compact(UtcTime);

impl fmt::Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = self.0.civil();
        write!(
            f,
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    }
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/time/tests.rs"]
mod tests;
