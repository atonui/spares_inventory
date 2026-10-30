function notificationLinksFeature() {
    return {
        notificationNavigationApplied: false,

        async applyNotificationLink() {
            if (this.notificationNavigationApplied || typeof window === 'undefined') return;
            this.notificationNavigationApplied = true;
            const params = new URLSearchParams(window.location.search || '');
            const transferId = Number(params.get('transfer_id'));
            const storeId = Number(params.get('store_id'));
            const inventoryId = Number(params.get('inventory_id'));
            const nextFrame = () => new Promise(resolve => {
                if (typeof requestAnimationFrame === 'function') requestAnimationFrame(resolve);
                else setTimeout(resolve, 0);
            });

            if (Number.isSafeInteger(transferId) && transferId > 0) {
                await nextFrame();
                const transfer = this.pendingTransfers.find(item => Number(item.id) === transferId);
                if (!transfer) {
                    this.error = 'This transfer is no longer awaiting receipt.';
                    return;
                }
                document.getElementById(`transfer-row-${transferId}`)
                    ?.scrollIntoView({behavior: 'smooth', block: 'center'});
                return;
            }

            if (!Number.isSafeInteger(storeId) || storeId <= 0) return;
            const store = this.storeOptions.find(item => Number(item.id) === storeId);
            if (!store) {
                this.error = 'This store is unavailable to your account.';
                return;
            }
            await this.viewStoreInventory(store);
            if (Number.isSafeInteger(inventoryId) && inventoryId > 0) {
                await nextFrame();
                document.getElementById(`store-inventory-row-${inventoryId}`)
                    ?.scrollIntoView({behavior: 'smooth', block: 'center'});
            }
        },
    };
}
