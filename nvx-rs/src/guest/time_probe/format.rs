//! The C formats of the diagnostics' numbers and times.
//!
//! Rust formats a float with a precision exactly, rounding a tie to even, as musl's `printf`
//! does in its default rounding mode, so the fixed-point fields equal C's `%.Nf`. Only the
//! spellings of the values that are not finite differ, which [`fixed`] maps to C's.

/// Seconds in a day, which split a time into its day and the seconds within it.
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
/// Days from 0000-03-01 to 1970-01-01 in the proleptic Gregorian calendar, which
/// [`civil_date`] counts from.
const DAYS_TO_UNIX_EPOCH: i64 = 719_468;
/// Days in a 400-year cycle of the Gregorian calendar.
const DAYS_PER_ERA: i64 = 146_097;
/// Years in a 400-year cycle of the Gregorian calendar.
const YEARS_PER_ERA: i64 = 400;

/// Formats `value` with C's `%.{precision}f`.
fn fixed(value: f64, precision: usize) -> String {
    if value.is_nan() {
        if value.is_sign_negative() {
            "-nan"
        } else {
            "nan"
        }
        .to_owned()
    } else {
        format!("{value:.precision$}")
    }
}

/// Formats a whole-number field with C `%.0f`.
pub(super) fn f0(value: f64) -> String {
    fixed(value, 0)
}

/// Formats a one-decimal field with C `%.1f`.
pub(super) fn f1(value: f64) -> String {
    fixed(value, 1)
}

/// Formats a nine-decimal seconds field with C `%.9f`.
pub(super) fn f9(value: f64) -> String {
    fixed(value, 9)
}

/// Returns the proleptic Gregorian year, month, and day of `days` since 1970-01-01, by Howard
/// Hinnant's `civil_from_days`, which counts from 0000-03-01 so that a leap day ends its year.
fn civil_date(days: i64) -> (i64, i64, i64) {
    let days = days + DAYS_TO_UNIX_EPOCH;
    let era = days.div_euclid(DAYS_PER_ERA);
    let day_of_era = days.rem_euclid(DAYS_PER_ERA);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * YEARS_PER_ERA + i64::from(month <= 2);
    (year, month, day)
}

/// Formats Unix `seconds` as C's `strftime` with `%Y-%m-%dT%H:%M:%S` formats `gmtime_r`'s
/// UTC broken-down time.
pub(super) fn utc_seconds(seconds: i64) -> String {
    let (year, month, day) = civil_date(seconds.div_euclid(SECONDS_PER_DAY));
    let time = seconds.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_with_c_rounding_and_spelling() {
        assert_eq!(f0(12.5), "12");
        assert_eq!(f0(13.5), "14");
        assert_eq!(f1(12.25), "12.2");
        assert_eq!(f9(1.5), "1.500000000");
        assert_eq!(f1(-0.0), "-0.0");
        assert_eq!(f0(f64::INFINITY), "inf");
        assert_eq!(f1(f64::NEG_INFINITY), "-inf");
        assert_eq!(f9(f64::NAN), "nan");
        assert_eq!(f0(-f64::NAN), "-nan");
    }

    #[test]
    fn formats_the_complete_finite_double_range_without_truncation() {
        let integer = f0(f64::MAX);
        assert_eq!(integer.len(), 309);
        assert!(integer.starts_with("179769313486231570814527423731704356798070567525"));
        assert!(integer.ends_with("50404026184124858368"));

        let one_decimal = f1(f64::MAX);
        assert_eq!(one_decimal.len(), 311);
        assert!(one_decimal.ends_with(".0"));

        let nine_decimals = f9(f64::MAX);
        assert_eq!(nine_decimals.len(), 319);
        assert!(nine_decimals.ends_with(".000000000"));
    }

    #[test]
    fn utc_times_follow_the_gregorian_calendar() {
        assert_eq!(utc_seconds(0), "1970-01-01T00:00:00");
        assert_eq!(utc_seconds(-1), "1969-12-31T23:59:59");
        assert_eq!(utc_seconds(951_782_400), "2000-02-29T00:00:00");
        assert_eq!(utc_seconds(1_790_841_600), "2026-10-01T08:00:00");
        assert_eq!(utc_seconds(4_107_542_399), "2100-02-28T23:59:59");
        assert_eq!(utc_seconds(4_107_542_400), "2100-03-01T00:00:00");
        assert_eq!(utc_seconds(253_402_300_799), "9999-12-31T23:59:59");
    }
}
