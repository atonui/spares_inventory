/* Shared temporal foundation. Loaded by consumers in the coordinated release.
 * Instants require explicit RFC 3339 offsets. Calendar dates remain plain dates.
 * Browser numeric instants have millisecond precision; API values are not changed.
 */
var InventoryTime = (() => {
    const instantPattern = /^(\d{4}-\d{2}-\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

    function validDate(value) {
        if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
        const [year, month, day] = value.split('-').map(Number);
        if (year < 1 || month < 1 || month > 12 || day < 1) return false;
        const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
        return day <= [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
    }

    function isValidZone(zone) {
        if (typeof zone !== 'string' || !zone || (zone !== 'UTC' && !zone.includes('/')) || /^(posix|right)\//.test(zone)) return false;
        try { new Intl.DateTimeFormat('en-GB', {timeZone: zone}); return true; }
        catch { return false; }
    }

    function parseInstant(value) {
        if (typeof value !== 'string') return NaN;
        const match = instantPattern.exec(value);
        if (!match || !validDate(match[1])) return NaN;
        const milliseconds = Date.parse(value);
        if (!Number.isFinite(milliseconds)) return NaN;
        const year = new Date(milliseconds).getUTCFullYear();
        return year >= 1 && year <= 9999 ? milliseconds : NaN;
    }

    function partsFor(milliseconds, zone, clock = false) {
        const options = {timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit', era: 'short'};
        if (clock) Object.assign(options, {hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'longOffset'});
        return Object.fromEntries(new Intl.DateTimeFormat('en-GB-u-ca-gregory-nu-latn', options)
            .formatToParts(new Date(milliseconds)).map(part => [part.type, part.value]));
    }

    function dateFromParts(parts) {
        if (parts.era !== 'AD' || Number(parts.year) < 1 || Number(parts.year) > 9999) throw new RangeError('Local date out of range');
        return `${parts.year.padStart(4, '0')}-${parts.month}-${parts.day}`;
    }

    function formatInstant(value, zone) {
        const milliseconds = parseInstant(value);
        if (!Number.isFinite(milliseconds) || !isValidZone(zone)) return 'Unknown';
        try {
            const parts = partsFor(milliseconds, zone, true);
            const offset = parts.timeZoneName.replace(/^GMT/, 'UTC').replace(/^UTC[+-]00:00$/, 'UTC');
            return `${dateFromParts(parts)} ${parts.hour}:${parts.minute}:${parts.second} ${offset}`;
        } catch { return 'Unknown'; }
    }

    function formatDate(value) { return validDate(value) ? value : 'Unknown'; }

    function today(zone, instant = new Date().toISOString()) {
        const milliseconds = parseInstant(instant);
        if (!Number.isFinite(milliseconds) || !isValidZone(zone)) return 'Unknown';
        try { return dateFromParts(partsFor(milliseconds, zone)); }
        catch { return 'Unknown'; }
    }

    // Synthetic UTC is used only for calendar arithmetic, never for display or
    // interpretation of a date-only value as a real-world event timestamp.
    function calendarClock(value) {
        return validDate(value) ? new Date(value + 'T00:00:00Z') : null;
    }

    function addDays(value, days) {
        const clock = calendarClock(value);
        if (!clock || !Number.isSafeInteger(days)) return 'Unknown';
        clock.setUTCDate(clock.getUTCDate() + days);
        if (!Number.isFinite(clock.getTime()) || clock.getUTCFullYear() < 1 || clock.getUTCFullYear() > 9999) return 'Unknown';
        return clock.toISOString().slice(0, 10);
    }

    function daysBetween(first, last) {
        const start = calendarClock(first), end = calendarClock(last);
        return start && end ? (end.getTime() - start.getTime()) / 86400000 : NaN;
    }

    return Object.freeze({parseInstant, formatInstant, formatDate, isValidZone, today, addDays, daysBetween});
})();
