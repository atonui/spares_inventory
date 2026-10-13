function transferReceiptsFeature() {
    return {
        pendingTransfers: [],

        async loadPendingTransfers() {
            this.pendingTransfers = await this.apiCall('/inventory/transfers');
        },

        async refreshTransfers() {
            this.error = '';
            try {
                await this.loadPendingTransfers();
                await this.loadStats();
            } catch (error) { this.error = 'Failed to refresh transfers: ' + error.message; }
        },

        async confirmTransfer(transfer, action) {
            if (this.loading || (action === 'receive' ? !transfer.can_receive : !transfer.can_return)) return;
            const message = action === 'receive'
                ? `Confirm physical receipt of all ${transfer.quantity} x ${transfer.part_number} at ${transfer.to_store_name}?`
                : `Confirm all ${transfer.quantity} x ${transfer.part_number} have physically returned to ${transfer.from_store_name}? Source stock will be restored.`;
            if (!confirm(message)) return;
            this.loading = true;
            this.error = '';
            try {
                const result = await this.apiCall(`/inventory/transfers/${transfer.id}/${action}`, {
                    method:'POST', body:JSON.stringify({confirmed:true})
                });
                this.successMessage = result.message;
                await this.loadPendingTransfers();
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory = this.inventory.filter(i=>i.store_id===this.selectedStore.id);
                await this.loadMovements();
                await this.loadStats();
            } catch (error) { this.error = 'Confirmation failed: ' + error.message; }
            finally { this.loading = false; }
        },
    };
}
