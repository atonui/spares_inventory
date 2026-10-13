function stockConsumptionFeature() {
    return {
        showConsumeModal: false,

        consumeForm: {
            inventory_id: '',
            part_number: '',
            description: '',
            store_name: '',
            available_quantity: 0,
            quantity: '',
            work_order_number: '',
            notes: ''
        },

        consumeItem(item) {
            this.consumeForm = {
                inventory_id: item.id,
                part_number: item.part_number,
                description: item.description,
                store_name: item.store_name,
                available_quantity: item.quantity,
                quantity: 1,
                work_order_number: '',
                notes: ''
            };
            this.showConsumeModal = true;
        },

        async consumeStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall('/inventory/consume', {
                    method: 'POST',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.consumeForm.inventory_id),
                        quantity: parseInt(this.consumeForm.quantity),
                        work_order_number: this.consumeForm.work_order_number.trim(),
                        notes: this.consumeForm.notes || null
                    })
                });

                this.successMessage = result.message;
                this.showConsumeModal = false;
                this.consumeForm = {};

                await this.loadInventory();
                await this.loadMovements();
                await this.refreshDashboard();

                if (this.selectedStore) {
                    this.storeInventory = this.inventory.filter(item => item.store_id === this.selectedStore.id);
                }

                setTimeout(() => this.successMessage = '', 5000);

            } catch (error) {
                this.error = 'Failed to consume stock: ' + error.message;
            } finally {
                this.loading = false;
            }
        },
    };
}
