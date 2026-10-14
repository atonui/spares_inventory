function movementHistoryFeature() {
    return {
        movementTimeContext: null,
        showMovementsPanel: false,
        movements: [],
        movementFilters: {
            startDate: '',
            endDate: '',
            movementType: '',
            partId: '',
            storeId: ''
        },

        async loadMovements() {
            const params = new URLSearchParams();

            if (this.movementFilters.startDate) {
                params.append('start_date', this.movementFilters.startDate);
            }
            if (this.movementFilters.endDate) {
                params.append('end_date', this.movementFilters.endDate);
            }
            if (this.movementFilters.movementType) {
                params.append('movement_type', this.movementFilters.movementType);
            }
            if (this.movementFilters.partId) {
                params.append('part_id', this.movementFilters.partId);
            }
            if (this.movementFilters.storeId) {
                params.append('store_id', this.movementFilters.storeId);
            }

            const queryString = params.toString();
            const endpoint = queryString ? `/movements?${queryString}` : '/movements';
            this.movements = await this.apiCall(endpoint,{},context=>this.movementTimeContext=context);
        },

        clearMovementFilters() {
            this.movementFilters = {
                startDate: '',
                endDate: '',
                movementType: '',
                partId: '',
                storeId: ''
            };
            this.loadMovements();
        },

        get recentActivity() {
            // Get last 20 movements
            return this.movements.slice(0, 20);
        },

exportMovementsCSV() {
    const headers = [`Date/Time (${this.movementTimeContext?.timezone || 'Unknown'})`, 'Type', 'Part Number', 'Quantity', 'From Store', 'To Store', 'Work Order', 'Created By', 'Transfer Status', 'Confirmed By', `Confirmed At (${this.movementTimeContext?.timezone || 'Unknown'})`];
    const rows = this.movements.map(m => [
        this.formatBusinessInstant(m.created_at,this.movementTimeContext),
        m.movement_type,
        m.part_number,
        m.quantity,
        m.from_store_name || '-',
        m.to_store_name || '-',
        m.work_order || '-',
        m.created_by_name, m.transfer_status || '', m.completed_by_name || '', m.completed_at ? this.formatBusinessInstant(m.completed_at,this.movementTimeContext) : ''
    ]);

    this.downloadCSV(headers, rows, `movement_history_${new Date().toISOString().split('T')[0]}.csv`);
},

        async toggleMovements() {
            this.showMovementsPanel = !this.showMovementsPanel;
            if (this.showMovementsPanel) {
                await this.loadMovements();
            }
        },

    };
}
