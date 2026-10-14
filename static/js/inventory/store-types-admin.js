function storeTypesAdminFeature() {
    return {
        storeTypeForm: {
            type_code: '',
            type_name: '',
            description: '',
            display_order: 0,
            is_active: true
        },

        showStoreTypeModal: false,
        editingStoreType: null,

        async createStoreType() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/store-types', {
                    method: 'POST',
                    body: JSON.stringify({
                        type_code: this.storeTypeForm.type_code,
                        type_name: this.storeTypeForm.type_name,
                        description: this.storeTypeForm.description,
                        display_order: parseInt(this.storeTypeForm.display_order) || 0
                    })
                });

                this.successMessage = 'Store type created successfully!';
                this.showStoreTypeModal = false;
                this.storeTypeForm = { type_code: '', type_name: '', description: '', display_order: 0 };

                await this.loadStoreTypes();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to create store type: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        editStoreType(storeType) {
            this.editingStoreType = storeType.id;
            this.storeTypeForm = {
                type_code: storeType.type_code,
                type_name: storeType.type_name,
                description: storeType.description || '',
                display_order: storeType.display_order,
                is_active: storeType.is_active
            };
            this.showStoreTypeModal = true;
        },

        async updateStoreType() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/store-types/${this.editingStoreType}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        type_name: this.storeTypeForm.type_name,
                        description: this.storeTypeForm.description,
                        display_order: parseInt(this.storeTypeForm.display_order) || 0,
                        is_active: this.storeTypeForm.is_active
                    })
                });

                this.successMessage = 'Store type updated successfully!';
                this.showStoreTypeModal = false;
                this.editingStoreType = null;
                this.storeTypeForm = { type_code: '', type_name: '', description: '', display_order: 0 };

                await this.loadStoreTypes();
                await this.loadStores(); // Refresh stores in case type changed
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update store type: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deleteStoreType(typeId, typeName) {
            if (!confirm(`Are you sure you want to delete/deactivate store type '${typeName}'?`)) {
                return;
            }

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall(`/store-types/${typeId}`, {
                    method: 'DELETE'
                });

                this.successMessage = result.message;
                await this.loadStoreTypes();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to delete store type: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

    };
}
