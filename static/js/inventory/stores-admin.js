function storesAdminFeature() {
    return {
        storeForm: {
            name: '',
            type: 'customer_site',
            location: '',
            assigned_user_id: ''
        },

        showStoreModal: false,
        editingStore: null,

        async createStore() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/stores', {
                    method: 'POST',
                    body: JSON.stringify({
                        name: this.storeForm.name,
                        type: this.storeForm.type,
                        location: this.storeForm.location || null,
                        assigned_user_id: this.storeForm.assigned_user_id ? parseInt(this.storeForm.assigned_user_id) : null
                    })
                });

                this.successMessage = 'Store created successfully!';
                this.showStoreModal = false;
                this.storeForm = { name: '', type: 'customer_site', location: '', assigned_user_id: '' };

                await this.loadStores();
                await this.loadStats();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to create store: ' + error.message;
            } finally {
                this.loading = false;
            }
        },
        editStore(store) {
            this.editingStore = store.id;
            this.storeForm = {
                name: store.name,
                type: store.type,
                location: store.location || '',
                assigned_user_id: store.assigned_user_id || ''
            };
            this.showStoreModal = true;
        },

        async updateStore() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/stores/${this.editingStore}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        name: this.storeForm.name,
                        type: this.storeForm.type,
                        location: this.storeForm.location || null,
                        assigned_user_id: this.storeForm.assigned_user_id ? parseInt(this.storeForm.assigned_user_id) : null
                    })
                });

                this.successMessage = 'Store updated successfully!';
                this.showStoreModal = false;
                this.editingStore = null;
                this.storeForm = { name: '', type: 'customer_site', location: '', assigned_user_id: '' };

                await this.loadStores();
                await this.loadInventory();
                await this.loadStats();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update store: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deleteStore(storeId, storeName) {
            if (!confirm(`Archive store ${storeName}? History will be preserved.`)) {
                return;
            }

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall(`/stores/${storeId}`, {
                    method: 'DELETE'
                });

                this.successMessage = result.message;
                if (this.selectedStore?.id === storeId) { this.selectedStore=null; this.storeInventory=[]; this.showStoreInventoryPanel=false; }
                await this.loadStores();
                await this.loadStats();

                await this.loadInventory();
                if (this.showArchivedPanel) await this.loadArchivedRecords();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to archive store: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async importStores(event) {
            const file = event.target.files[0];
            if (!file) return;

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const formData = new FormData();
                formData.append('file', file);

                const result = await this.apiCall('/stores/bulk-import', {
                    method: 'POST', body: formData
                });
                this.successMessage = result.message;
                if (result.errors && result.errors.length > 0) {
                    this.error = 'Some errors occurred:\n' + result.errors.join('\n');
                }

                await this.loadStores();
                event.target.value = ''; // Reset file input
                setTimeout(() => {
                    this.successMessage = '';
                    this.error = '';
                }, 5000);

            } catch (error) {
                this.error = 'Failed to import stores: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        downloadStoreTemplate() {
            const csv = 'name,type,location,assigned_user_email\nSample Store,customer_site,Sample Location,user@example.com';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'stores_import_template.csv';
            a.click();
        },

    };
}
