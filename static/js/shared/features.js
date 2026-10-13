// Preserve getters and method receivers while enforcing one owner per property.
function composeInventoryFeatures(...parts) {
    const result = {};
    for (const part of parts) {
        for (const key of Reflect.ownKeys(part)) {
            if (Object.prototype.hasOwnProperty.call(result, key)) {
                throw new Error('Duplicate inventory feature property: ' + String(key));
            }
            Object.defineProperty(result, key, Object.getOwnPropertyDescriptor(part, key));
        }
    }
    return result;
}
