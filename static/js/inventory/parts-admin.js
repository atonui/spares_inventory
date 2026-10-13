function partsAdminFeature() {
    return {
        partForm: {
            part_number: '',
            description: '',
            category: '',
            unit_cost: ''
        },

        showPartModal: false,
        editingPart: null,

        async createPart() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/parts', {
                    method: 'POST',
                    body: JSON.stringify({
                        part_number: this.partForm.part_number,
                        description: this.partForm.description,
                        category: this.partForm.category,
                        unit_cost: parseFloat(this.partForm.unit_cost)
                    })
                });

                this.successMessage = 'Part created successfully!';
                this.showPartModal = false;
                this.partForm = { part_number: '', description: '', category: '', unit_cost: '' };

                await this.loadParts();
                await this.loadStats();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to create part: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        editPart(part) {
            this.editingPart = part.id;
            this.partForm = {
                part_number: part.part_number,
                description: part.description,
                category: part.category,
                unit_cost: part.unit_cost
            };
            this.showPartModal = true;
        },

        async updatePart() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/parts/${this.editingPart}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        part_number: this.partForm.part_number,
                        description: this.partForm.description,
                        category: this.partForm.category,
                        unit_cost: parseFloat(this.partForm.unit_cost)
                    })
                });

                this.successMessage = 'Part updated successfully!';
                this.showPartModal = false;
                this.editingPart = null;
                this.partForm = { part_number: '', description: '', category: '', unit_cost: '' };

                await this.loadParts();
                await this.loadInventory();
                await this.loadStats();

                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update part: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deletePart(partId, partNumber) {
            if (!confirm(`Archive part ${partNumber}? History will be preserved.`)) {
                return;
            }

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall(`/parts/${partId}`, {
                    method: 'DELETE'
                });

                this.successMessage = result.message;
                await this.loadParts();
                await this.loadStats();

                await this.loadInventory();
                if (this.showArchivedPanel) await this.loadArchivedRecords();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to archive part: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async importParts(event) {
            const file = event.target.files[0];
            if (!file) return;

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                if (!this.csrfToken) {
                    await this.getCsrfToken();
                }

                const formData = new FormData();
                formData.append('file', file);

                const result = await this.apiCall('/parts/bulk-import', {
                    method: 'POST',
                    body: formData
                });

                this.successMessage = `Import complete! Added: ${result.added}, Skipped: ${result.skipped}`;

                if (result.skipped > 0) {
                    console.log(`${result.skipped} parts were skipped - check if they already exist`);
                }

                await this.loadParts();
                await this.loadStats();

                event.target.value = '';

                setTimeout(() => this.successMessage = '', 5000);

            } catch (error) {
                this.error = 'Failed to import parts: ' + error.message;
                console.error('Import error:', error);
            } finally {
                this.loading = false;
            }
        },

        downloadPartTemplate() {
            const csv = 'part_number,description,category,unit_cost\nSAMPLE-001,Sample Part Description,Sample Category,99.99';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'parts_import_template.csv';
            a.click();
        },
    };
}
