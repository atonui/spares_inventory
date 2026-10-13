function stockDispatchFeature() {
    return {
        transferForm: {
            inventory_id: '',
            to_store_id: '',
            quantity: ''
        },

        showTransferModal: false,

        async transferItem(item) {
            this.transferForm.replenishment = false;
            this.transferForm.max_quantity = null;
            this.transferForm.inventory_id = item.id;
            this.transferForm.quantity = 1;
            this.transferForm.to_store_id = '';
            this.showTransferModal = true;
        },

        async transferStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall('/inventory/transfer', {
                    method: 'POST',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.transferForm.inventory_id),
                        to_store_id: parseInt(this.transferForm.to_store_id),
                        quantity: parseInt(this.transferForm.quantity),
                        ...(this.transferForm.replenishment ? {replenishment:true} : {})
                    })
                });

                this.successMessage = result.message;
                this.showTransferModal = false;
                this.transferForm = { inventory_id: '', to_store_id: '', quantity: '' };

                await this.loadInventory();
                await this.loadStats();
                await this.loadPendingTransfers();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to transfer stock: ' + error.message;
            } finally {
                this.loading = false;
            }
        },
    };
}
