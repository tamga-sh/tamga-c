#include "util/rfc3339.h"

#include <string.h>
#include <time.h>

/* Reads exactly `digits` ASCII digits from `s` into `*out`. Returns false on
 * a non-digit -- deliberately strict, so "2026-8-1" is rejected rather than
 * silently parsed as something else. */
static bool tamga_read_uint(const char *s, size_t digits, unsigned int *out) {
    unsigned int value = 0u;
    size_t i;

    for (i = 0u; i < digits; i++) {
        char c = s[i];
        if (c < '0' || c > '9') {
            return false;
        }
        value = (value * 10u) + (unsigned int)(c - '0');
    }
    *out = value;
    return true;
}

static bool tamga_is_leap_year(int64_t year) {
    return ((year % 4) == 0 && (year % 100) != 0) || ((year % 400) == 0);
}

static unsigned int tamga_days_in_month(int64_t year, unsigned int month) {
    static const unsigned int lengths[12] = {31u, 28u, 31u, 30u, 31u, 30u,
                                             31u, 31u, 30u, 31u, 30u, 31u};
    if (month < 1u || month > 12u) {
        return 0u;
    }
    if (month == 2u && tamga_is_leap_year(year)) {
        return 29u;
    }
    return lengths[month - 1u];
}

/*
 * Days since 1970-01-01 for a proleptic Gregorian date. This is Howard
 * Hinnant's days_from_civil, chosen because it is branch-free over the
 * leap-year rules and correct for negative years -- unlike the usual
 * accumulate-365-and-add-leap-days loop, which is easy to get subtly wrong
 * around century boundaries.
 */
static int64_t tamga_days_from_civil(int64_t year, unsigned int month, unsigned int day) {
    int64_t y = year;
    int64_t era;
    int64_t yoe;
    int64_t doy;
    int64_t doe;

    y -= (month <= 2u) ? 1 : 0;
    era = ((y >= 0) ? y : (y - 399)) / 400;
    yoe = y - (era * 400); /* [0, 399] */
    doy = (int64_t)((153u * ((month > 2u) ? (month - 3u) : (month + 9u)) + 2u) / 5u) +
          (int64_t)day - 1;                            /* [0, 365] */
    doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy; /* [0, 146096] */
    return (era * 146097) + doe - 719468;
}

bool tamga_rfc3339_parse(const char *str, int64_t *out_epoch_seconds) {
    unsigned int year_u, month, day, hour, minute, second;
    size_t pos;
    int64_t days;
    int64_t seconds;
    int64_t offset_seconds = 0;
    size_t len;

    if (str == NULL || out_epoch_seconds == NULL) {
        return false;
    }
    len = strlen(str);
    /* Shortest legal form is "1970-01-01T00:00:00Z" -- 20 characters. */
    if (len < 20u) {
        return false;
    }

    if (!tamga_read_uint(&str[0], 4u, &year_u) || str[4] != '-') {
        return false;
    }
    if (!tamga_read_uint(&str[5], 2u, &month) || str[7] != '-') {
        return false;
    }
    if (!tamga_read_uint(&str[8], 2u, &day)) {
        return false;
    }
    if (str[10] != 'T' && str[10] != 't') {
        return false;
    }
    if (!tamga_read_uint(&str[11], 2u, &hour) || str[13] != ':') {
        return false;
    }
    if (!tamga_read_uint(&str[14], 2u, &minute) || str[16] != ':') {
        return false;
    }
    if (!tamga_read_uint(&str[17], 2u, &second)) {
        return false;
    }
    pos = 19u;

    /* Fractional seconds: accepted, then discarded. */
    if (str[pos] == '.') {
        size_t start = pos + 1u;
        pos = start;
        while (pos < len && str[pos] >= '0' && str[pos] <= '9') {
            pos++;
        }
        if (pos == start) {
            return false; /* a '.' with no digits after it */
        }
    }

    if (pos >= len) {
        return false; /* RFC 3339 requires an explicit offset */
    }
    if (str[pos] == 'Z' || str[pos] == 'z') {
        if ((pos + 1u) != len) {
            return false;
        }
    } else if (str[pos] == '+' || str[pos] == '-') {
        unsigned int off_hour, off_minute;
        int sign = (str[pos] == '-') ? -1 : 1;
        if ((pos + 6u) != len) {
            return false;
        }
        if (!tamga_read_uint(&str[pos + 1u], 2u, &off_hour) || str[pos + 3u] != ':') {
            return false;
        }
        if (!tamga_read_uint(&str[pos + 4u], 2u, &off_minute)) {
            return false;
        }
        if (off_hour > 23u || off_minute > 59u) {
            return false;
        }
        offset_seconds = (int64_t)sign * (((int64_t)off_hour * 3600) + ((int64_t)off_minute * 60));
    } else {
        return false;
    }

    if (month < 1u || month > 12u) {
        return false;
    }
    if (day < 1u || day > tamga_days_in_month((int64_t)year_u, month)) {
        return false;
    }
    if (hour > 23u || minute > 59u) {
        return false;
    }
    if (second > 60u) {
        return false;
    }
    if (second == 60u) {
        second = 59u; /* leap second */
    }

    days = tamga_days_from_civil((int64_t)year_u, month, day);
    seconds = (days * 86400) + ((int64_t)hour * 3600) + ((int64_t)minute * 60) + (int64_t)second;
    /* A local-time offset is how far ahead of UTC the stamp is, so UTC is the
     * stamp minus the offset. */
    *out_epoch_seconds = seconds - offset_seconds;
    return true;
}

int64_t tamga_time_now_unix(void) {
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        return 0;
    }
    if ((int64_t)now < 0) {
        return 0;
    }
    return (int64_t)now;
}
