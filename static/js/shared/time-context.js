function validTimezoneContext(data) {
    return Boolean(data && InventoryTime.isValidZone(data.business_timezone) && InventoryTime.isValidZone(data.display_timezone) && Number.isSafeInteger(data.revision) && data.revision>0);
}
