function stockEntryFeature() {
    return {
        addingStock: false,
        addForm: {
            part_id: '',
            store_id: '',
            quantity: '',
            work_order_number: ''
        },

        editForm: {
            inventory_id: '',
            new_quantity: ''
        },

        showAddModal: false,
        showEditModal: false,
        partSearchTerm: '',
        filteredPartsForSelection: [],

        async addStockToStore(store) {
            this.addForm.store_id = store.id;
            this.addForm.part_id = '';
            this.addForm.quantity = '';
            this.addForm.work_order_number = '';
            this.partSearchTerm = '';  // Reset search
            this.filteredPartsForSelection = this.parts;  // Show all parts initially
            this.showAddModal = true;
        },

        filterPartsForSelection() {
            if (!this.partSearchTerm) {
                this.filteredPartsForSelection = this.parts;
                return;
            }

            const term = this.partSearchTerm.toLowerCase();
            this.filteredPartsForSelection = this.parts.filter(part =>
                part.part_number.toLowerCase().includes(term) ||
                part.description.toLowerCase().includes(term) ||
                part.category.toLowerCase().includes(term)
            );
        },

        selectPart(part) {
            this.addForm.part_id = part.id;
            this.partSearchTerm = `${part.part_number} - ${part.description}`;
        },

        async addStock() {
            this.addingStock = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/inventory/add', {
                    method: 'POST',
                    body: JSON.stringify({
                        part_id: this.addForm.part_id,
                        store_id: this.addForm.store_id,
                        quantity: Number(this.addForm.quantity),
                        work_order_number: this.addForm.work_order_number || null
                    })
                });

                this.successMessage = 'Stock added successfully';
                this.showAddModal = false;
                this.addForm = { part_id: '', store_id: '', quantity: '', work_order_number: '' };
                this.partSearchTerm = '';

                await this.loadInventory();
                await this.loadStats();
                await this.loadEquipmentStats();

                if (this.selectedStore) {
                    await this.viewStoreInventory(this.selectedStore);
                }

                setTimeout(() => this.successMessage = '', 3000);
            } catch (error) {
                this.error = 'Failed to add stock: ' + error.message;
            } finally {
                this.addingStock = false;
            }
        },

        async editItem(item) {
            this.editForm.inventory_id = item.id;
            this.editForm.new_quantity = item.quantity;
            this.showEditModal = true;
        },

        async updateStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/inventory/update', {
                    method: 'PUT',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.editForm.inventory_id),
                        new_quantity: parseInt(this.editForm.new_quantity)
                    })
                });

                this.successMessage = 'Stock updated successfully!';
                this.showEditModal = false;
                this.editForm = { inventory_id: '', new_quantity: '' };

                await this.loadInventory();
                await this.loadStats();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update stock: ' + error.message;
            } finally {
                this.loading = false;
            }
        },
    };
}
