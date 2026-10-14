const InventoryAnnouncementTime = (() => {
    function localInput(instant, zone) {
        if (!instant) return '';
        const milliseconds = InventoryTime.parseInstant(instant);
        if (!Number.isFinite(milliseconds) || !InventoryTime.isValidZone(zone)) throw Error('Announcement schedule timezone is unavailable');
        const values = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
            timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',
        }).formatToParts(new Date(milliseconds)).map(p=>[p.type,p.value]));
        return `${values.year}-${values.month}-${values.day}T${values.hour}:${values.minute}:${values.second}`;
    }
    return {localInput};
})();
