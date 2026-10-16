function inventoryDialogFocusFeature() {
    return {
        initDialogFocus(dialog, stateKey) {
            this.$watch(stateKey, open => {
                if (open) {
                    dialog._returnFocus = dialog.ownerDocument.activeElement;
                    this.$nextTick(() => {
                        const selector = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
                        const first = [...dialog.querySelectorAll(selector)].find(element => element.getClientRects().length > 0);
                        (first || dialog).focus();
                    });
                } else {
                    this.$nextTick(() => dialog._returnFocus?.focus());
                }
            });
        },

        trapDialogFocus(event) {
            if (event.key !== 'Tab') return;
            const dialog = event.currentTarget;
            const selector = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
            const focusable = [...dialog.querySelectorAll(selector)].filter(element => element.getClientRects().length > 0);
            const active = dialog.ownerDocument.activeElement;
            if (!focusable.length) {
                event.preventDefault();
                dialog.focus();
                return;
            }

            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && (active === first || active === dialog || !dialog.contains(active))) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
                event.preventDefault();
                first.focus();
            }
        },

        closeDialog(stateKey) {
            if (typeof this[stateKey] === 'boolean') this[stateKey] = false;
        }
    };
}
