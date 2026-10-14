function equipmentFeature() {
    return {
        equipment: [],
        equipmentStats: {},
        equipmentForm: {
            equipment_name: '',
            make: '',
            model: '',
            serial_number: '',
            assigned_user_id: '',
            calibration_cert_number: '',
            calibration_authority: '',
            calibration_date: '',
            next_calibration_date: '',
            notes: ''
        },

        calibrationForm: {
            calibration_cert_number: '',
            calibration_authority: '',
            calibration_date: '',
            next_calibration_date: '',
            notes: ''
        },

        transferEquipmentForm: {
            to_user_id: '',
            notes: ''
        },

        editingEquipment: null,
        selectedEquipment: null,
        equipmentHistory: [],
        calibrationReminderDays: 30,

        // Equipment-related modals/panels
        showEquipmentModal: false,
        showCalibrationModal: false,
        showTransferEquipmentModal: false,
        showEquipmentPanel: false,
        showEquipmentHistoryModal: false,
        showCalibrationSettingsModal: false,

        async loadEquipment() {
            try {
                this.equipment = await this.apiCall('/equipment?show_all=true');
            } catch (error) {
                this.error = 'Failed to load equipment: ' + error.message;
            }
        },

        async loadEquipmentStats() {
            try {
                this.equipmentStats = await this.apiCall('/equipment/statistics');
            } catch (error) {
                this.error = 'Failed to load equipment stats: ' + error.message;
            }
        },

        async loadCalibrationSettings() {
            try {
                const response = await this.apiCall('/settings/calibration-reminder-days');
                this.calibrationReminderDays = response.days;
            } catch (error) {
                this.error = 'Failed to load calibration settings: ' + error.message;
            }
        },

        async createEquipment() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall('/equipment', {
                    method: 'POST',
                    body: JSON.stringify({
                        equipment_name: this.equipmentForm.equipment_name,
                        make: this.equipmentForm.make,
                        model: this.equipmentForm.model,
                        serial_number: this.equipmentForm.serial_number,
                        assigned_user_id: this.equipmentForm.assigned_user_id ? parseInt(this.equipmentForm.assigned_user_id) : null,
                        calibration_cert_number: this.equipmentForm.calibration_cert_number || null,
                        calibration_authority: this.equipmentForm.calibration_authority || null,
                        calibration_date: this.equipmentForm.calibration_date || null,
                        next_calibration_date: this.equipmentForm.next_calibration_date || null,
                        notes: this.equipmentForm.notes || null
                    })
                });

                this.successMessage = 'Equipment created successfully!';
                this.showEquipmentModal = false;
                this.equipmentForm = {
                    equipment_name: '', make: '', model: '', serial_number: '',
                    assigned_user_id: '', calibration_cert_number: '',
                    calibration_authority: '', calibration_date: '',
                    next_calibration_date: '', notes: ''
                };

                await this.loadEquipment();
                await this.loadEquipmentStats();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to create equipment: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        editEquipment(equipment) {
            this.editingEquipment = equipment.id;
            this.equipmentForm = {
                equipment_name: equipment.equipment_name,
                make: equipment.make,
                model: equipment.model,
                serial_number: equipment.serial_number,
                assigned_user_id: equipment.assigned_user_id || '',
                calibration_cert_number: equipment.calibration_cert_number || '',
                calibration_authority: equipment.calibration_authority || '',
                calibration_date: equipment.calibration_date || '',
                next_calibration_date: equipment.next_calibration_date || '',
                notes: equipment.notes || ''
            };
            this.showEquipmentModal = true;
        },

        async updateEquipment() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/equipment/${this.editingEquipment}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        equipment_name: this.equipmentForm.equipment_name,
                        make: this.equipmentForm.make,
                        model: this.equipmentForm.model,
                        serial_number: this.equipmentForm.serial_number,
                        assigned_user_id: this.equipmentForm.assigned_user_id ? parseInt(this.equipmentForm.assigned_user_id) : null,
                        calibration_cert_number: this.equipmentForm.calibration_cert_number || null,
                        calibration_authority: this.equipmentForm.calibration_authority || null,
                        calibration_date: this.equipmentForm.calibration_date || null,
                        next_calibration_date: this.equipmentForm.next_calibration_date || null,
                        notes: this.equipmentForm.notes || null
                    })
                });

                this.successMessage = 'Equipment updated successfully!';
                this.showEquipmentModal = false;
                this.editingEquipment = null;
                this.equipmentForm = {
                    equipment_name: '', make: '', model: '', serial_number: '',
                    assigned_user_id: '', calibration_cert_number: '',
                    calibration_authority: '', calibration_date: '',
                    next_calibration_date: '', notes: ''
                };

                await this.loadEquipment();
                await this.loadEquipmentStats();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update equipment: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deleteEquipment(equipmentId, equipmentName) {
            if (!confirm(`Are you sure you want to delete equipment ${equipmentName}?`)) {
                return;
            }

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/equipment/${equipmentId}`, {
                    method: 'DELETE'
                });

                this.successMessage = 'Equipment deleted successfully!';
                await this.loadEquipment();
                await this.loadEquipmentStats();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to delete equipment: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        openCalibrationModal(equipment) {
            this.selectedEquipment = equipment;
            this.calibrationForm = {
                calibration_cert_number: equipment.calibration_cert_number || '',
                calibration_authority: equipment.calibration_authority || '',
                calibration_date: this.businessToday() === 'Unknown' ? '' : this.businessToday(),
                next_calibration_date: equipment.next_calibration_date || '',
                notes: ''
            };
            this.showCalibrationModal = true;
        },

        async updateCalibration() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/equipment/${this.selectedEquipment.id}/calibrate`, {
                    method: 'POST',
                    body: JSON.stringify(this.calibrationForm)
                });

                this.successMessage = 'Calibration updated successfully!';
                this.showCalibrationModal = false;
                this.selectedEquipment = null;
                this.calibrationForm = {
                    calibration_cert_number: '',
                    calibration_authority: '',
                    calibration_date: '',
                    next_calibration_date: '',
                    notes: ''
                };

                await this.loadEquipment();
                await this.loadEquipmentStats();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update calibration: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        openTransferEquipmentModal(equipment) {
            this.selectedEquipment = equipment;
            this.transferEquipmentForm = {
                to_user_id: '',
                notes: ''
            };
            this.showTransferEquipmentModal = true;
        },

        async transferEquipmentToUser() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/equipment/${this.selectedEquipment.id}/transfer`, {
                    method: 'POST',
                    body: JSON.stringify({
                        to_user_id: this.transferEquipmentForm.to_user_id ? parseInt(this.transferEquipmentForm.to_user_id) : null,
                        notes: this.transferEquipmentForm.notes || null
                    })
                });

                this.successMessage = 'Equipment transferred successfully!';
                this.showTransferEquipmentModal = false;
                this.selectedEquipment = null;
                this.transferEquipmentForm = { to_user_id: '', notes: '' };

                await this.loadEquipment();
                await this.loadEquipmentStats();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to transfer equipment: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async viewEquipmentHistory(equipment) {
            this.selectedEquipment = equipment;
            this.loading = true;

            try {
                this.equipmentHistory = await this.apiCall(`/equipment/${equipment.id}/history`);
                this.showEquipmentHistoryModal = true;
            } catch (error) {
                this.error = 'Failed to load equipment history: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async updateCalibrationReminderDays() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                await this.apiCall(`/settings/calibration-reminder-days?days=${this.calibrationReminderDays}`, {
                    method: 'PUT'
                });

                this.successMessage = `Calibration reminder set to ${this.calibrationReminderDays} days!`;
                this.showCalibrationSettingsModal = false;
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to update setting: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        getCalibrationStatus(equipment) {
            if (!equipment.next_calibration_date) return { status: 'none', class: '', text: 'Not set' };

            const daysUntil = InventoryTime.daysBetween(this.businessToday(), equipment.next_calibration_date);
            if (!Number.isFinite(daysUntil)) return {status:'none',class:'',text:'Unknown'};

            if (daysUntil < 0) {
                return { status: 'overdue', class: 'overdue-cal', text: `Overdue by ${Math.abs(daysUntil)} days` };
            } else if (daysUntil <= 7) {
                return { status: 'urgent', class: 'urgent-cal', text: `Due in ${daysUntil} days` };
            } else if (daysUntil <= 30) {
                return { status: 'soon', class: 'soon-cal', text: `Due in ${daysUntil} days` };
            } else {
                return { status: 'ok', class: 'ok-cal', text: `Due in ${daysUntil} days` };
            }
        },

        get myEquipment() {
            return this.equipment.filter(eq => eq.assigned_user_id === this.currentUser?.id);
        },

        get dueSoonEquipment() {
            const today=this.businessToday();
            return this.equipment.filter(eq => {
                if (!eq.next_calibration_date) return false;
                const daysUntil = InventoryTime.daysBetween(today,eq.next_calibration_date);
                return daysUntil >= 0 && daysUntil <= this.calibrationReminderDays;
            });
        },

        get overdueEquipment() {
            const today=this.businessToday();
            return this.equipment.filter(eq => {
                if (!eq.next_calibration_date) return false;
                return InventoryTime.daysBetween(today,eq.next_calibration_date)<0;
            });
        },

        exportEquipmentCSV() {
            const headers = [
                'Equipment Name', 'Make', 'Model', 'Serial Number', 'Assigned To',
                'Calibration Cert', 'Calibration Authority', 'Calibration Date',
                'Next Calibration', 'Days Until Due', 'Status'
            ];

            const rows = this.equipment.map(eq => {
                const calStatus = this.getCalibrationStatus(eq);
                return [
                    eq.equipment_name,
                    eq.make,
                    eq.model,
                    eq.serial_number,
                    eq.assigned_user_name || 'Unassigned',
                    eq.calibration_cert_number || '-',
                    eq.calibration_authority || '-',
                    eq.calibration_date || '-',
                    eq.next_calibration_date || '-',
                    eq.days_until_calibration || '-',
                    calStatus.text
                ];
            });

            this.downloadCSV(headers, rows, `equipment_${new Date().toISOString().split('T')[0]}.csv`);
        },

        downloadEquipmentTemplate() {
            const csv = 'equipment_name,make,model,serial_number,assigned_user_email,calibration_cert_number,calibration_authority,calibration_date,next_calibration_date,notes\n' +
                        'Sample Equipment,Sample Make,Sample Model,SN-12345,user@example.com,CERT-001,Lab Name,2024-01-01,2025-01-01,Sample notes';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'equipment_import_template.csv';
            a.click();
        },

    };
}
