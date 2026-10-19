function inventoryExportsFeature() {
    return {
exportInventoryCSV() {
    const headers = ['Part Number', 'Description', 'Store', 'Store Type', 'Quantity', 'Min Threshold', 'Work Order', 'Status'];
    const rows = this.filteredInventory.map(item => [
        item.part_number,
        item.description,
        item.store_name,
        item.store_type,
        item.quantity,
        item.min_threshold,
        item.work_order || 'Original',
        this.isLowStock(item) ? 'Low Stock' : 'OK'
    ]);

    this.downloadCSV(headers, rows, `inventory_${new Date().toISOString().split('T')[0]}.csv`);
},

exportAllPartsCSV() {
    const headers = ['Part Number', 'Description', 'Category', 'Unit Cost', 'Total Quantity in System'];
    const rows = this.parts.map(part => [
        part.part_number,
        part.description,
        part.category,
        part.unit_cost.toFixed(2),
        this.inventory
            .filter(i => i.part_number === part.part_number)
            .reduce((sum, i) => sum + i.quantity, 0)
    ]);

    this.downloadCSV(headers, rows, `parts_catalog_${new Date().toISOString().split('T')[0]}.csv`);
},

exportStoresCSV() {
    const headers = ['Store Name', 'Type', 'Location', 'Assigned To', 'Total Items', 'Total Quantity'];
    const rows = this.stores.map(store => {
        const storeItems = this.inventory.filter(i => i.store_id === store.id);
        return [
            store.name,
            store.type,
            store.location || 'N/A',
            this.getUserName(store.assigned_user_id),
            storeItems.length,
            storeItems.reduce((sum, i) => sum + i.quantity, 0)
        ];
    });

    this.downloadCSV(headers, rows, `stores_${new Date().toISOString().split('T')[0]}.csv`);
},

exportUsersCSV() {
    const headers = ['Name', 'Email', 'Role', 'Territory', 'Created At'];
    const rows = this.users.map(user => [
        user.name,
        user.email,
        user.role,
        user.territory || 'N/A',
        'N/A' // Created date if you add it to the API
    ]);

    this.downloadCSV(headers, rows, `users_${new Date().toISOString().split('T')[0]}.csv`);
},

exportLowStockCSV() {
    const headers = ['Part Number', 'Description', 'Store', 'Current Quantity', 'Min Threshold', 'Shortage'];
    const rows = this.lowStockItems.map(item => [
        item.part_number,
        item.description,
        item.store_name,
        item.quantity,
        item.min_threshold,
        item.min_threshold - item.quantity
    ]);

    this.downloadCSV(headers, rows, `low_stock_alert_${new Date().toISOString().split('T')[0]}.csv`);
},

exportMyPartsCSV() {
    const headers = ['Part Number', 'Description', 'Store', 'Quantity', 'Work Order'];
    const rows = this.myPartsView.map(item => [
        item.part_number,
        item.description,
        item.store_name,
        item.quantity,
        item.work_order || 'Original'
    ]);

    this.downloadCSV(headers, rows, `my_parts_${new Date().toISOString().split('T')[0]}.csv`);
},

exportStoreInventoryCSV(storeId) {
    const store=this.stores.find(s=>s.id===Number(storeId));
    if (!store) return;
    const headers = ['Part Number', 'Description', 'Quantity', 'Min Threshold', 'Work Order', 'Status'];
    const rows = this.inventory.filter(item=>item.store_id===store.id).map(item => [
        item.part_number,
        item.description,
        item.quantity,
        item.min_threshold,
        item.work_order || 'Original',
        this.isLowStock(item) ? 'Low Stock' : 'OK'
    ]);

    const safeStoreName = store.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    this.downloadCSV(headers, rows, `${safeStoreName}_inventory_${new Date().toISOString().split('T')[0]}.csv`);
},

// Helper function to download CSV
downloadCSV(headers, rows, filename) {
    // Escape function for CSV fields
    const escapeCSV = (field) => {
        if (field === null || field === undefined) return '';
        const str = String(field);
        // If field contains comma, quote, or newline, wrap in quotes and escape quotes
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    };

    // Build CSV content
    const csvContent = [
        headers.map(escapeCSV).join(','),
        ...rows.map(row => row.map(escapeCSV).join(','))
    ].join('\n');

    // Create blob and download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
},

// export all data as a single comprehensive report
exportComprehensiveReport() {
    const reportZone=this.movementTimeContext?.timezone;
    const timestamp = InventoryTime.formatInstant(new Date().toISOString(),reportZone);
    const date = new Date().toISOString().split('T')[0];

    let report = `Spares Tracker - Comprehensive Inventory Report\n`;
    report += `Generated (${reportZone || 'Unknown'}): ${timestamp}\n`;
    report += `Generated By: ${this.currentUser.name} (${this.currentUser.email})\n\n`;

    // Summary Statistics
    report += `SUMMARY STATISTICS\n`;
    report += `Total Parts: ${this.stats.total_parts}\n`;
    report += `Total Stores: ${this.stats.total_stores}\n`;
    report += `Low Stock Alerts: ${this.stats.low_stock}\n`;
    report += `Total Inventory Items: ${this.inventory.length}\n`;
    report += `Available Stock Quantity: ${this.inventory.reduce((sum, i) => sum + i.quantity, 0)}\nIn Transit Quantity: ${this.stats.in_transit_quantity || 0}\n\n`;

    // Parts Catalog
    report += `\nPARTS CATALOG\n`;
    report += `Part Number,Description,Category,Unit Cost,Total Qty\n`;
    this.parts.forEach(part => {
        const totalQty = this.inventory
            .filter(i => i.part_number === part.part_number)
            .reduce((sum, i) => sum + i.quantity, 0);
        report += `${part.part_number},"${part.description}",${part.category},${part.unit_cost.toFixed(2)},${totalQty}\n`;
    });

    // Stores
    report += `\n\nSTORES\n`;
    report += `Store Name,Type,Location,Assigned To,Items,Total Qty\n`;
    this.stores.forEach(store => {
        const storeItems = this.inventory.filter(i => i.store_id === store.id);
        const totalQty = storeItems.reduce((sum, i) => sum + i.quantity, 0);
        report += `"${store.name}",${store.type},"${store.location || 'N/A'}","${this.getUserName(store.assigned_user_id)}",${storeItems.length},${totalQty}\n`;
    });

    // Current Inventory
    report += `\n\nCURRENT INVENTORY\n`;
    report += `Part Number,Description,Store,Quantity,Min Threshold,Status,Work Order\n`;
    this.inventory.forEach(item => {
        const status = this.isLowStock(item) ? 'LOW STOCK' : 'OK';
        report += `${item.part_number},"${item.description}","${item.store_name}",${item.quantity},${item.min_threshold},${status},"${item.work_order || 'Original'}"\n`;
    });

    // Low Stock Alerts
    if (this.lowStockItems.length > 0) {
        report += `\n\nLOW STOCK ALERTS\n`;
        report += `Part Number,Description,Store,Current,Minimum,Shortage\n`;
        this.lowStockItems.forEach(item => {
            const shortage = item.min_threshold - item.quantity;
            report += `${item.part_number},"${item.description}","${item.store_name}",${item.quantity},${item.min_threshold},${shortage}\n`;
        });
    }

    // Recent Movements
    report += `\n\nRECENT MOVEMENTS (Last 50)\n`;
    report += `Date/Time (${reportZone || 'Unknown'}),Type,Part,Qty,From,To,Work Order,By,Transfer Status,Confirmed By,Confirmed At (${reportZone || 'Unknown'})\n`;
    this.movements.slice(0, 50).forEach(m => {
        report += `"${this.formatBusinessInstant(m.created_at,this.movementTimeContext)}",${m.movement_type},${m.part_number},${m.quantity},"${m.from_store_name || '-'}","${m.to_store_name || '-'}","${m.work_order || '-'}","${m.created_by_name}","${m.transfer_status || '-'}","${m.completed_by_name || '-'}","${m.completed_at ? this.formatBusinessInstant(m.completed_at,this.movementTimeContext) : '-'}"\n`;
    });

    // Download the report
    const blob = new Blob([report], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `comprehensive_report_${date}.csv`;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
},


        exportStoreTypesCSV() {
            const headers = ['Type Code', 'Type Name', 'Description', 'Display Order', 'Status', 'Stores Using'];
            const rows = this.storeTypes.map(type => [
                type.type_code,
                type.type_name,
                type.description || '',
                type.display_order,
                type.is_active ? 'Active' : 'Inactive',
                this.stores.filter(s => s.type === type.type_code).length
            ]);

            this.downloadCSV(headers, rows, `store_types_${new Date().toISOString().split('T')[0]}.csv`);
        },

        downloadStoreTypeTemplate() {
            const csv = 'type_code,type_name,description,display_order\nwarehouse,Warehouse,Main warehouse storage,1\nfield_office,Field Office,Regional field office,2';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'store_types_template.csv';
            a.click();
            URL.revokeObjectURL(url);
        },

        exportCSV() {
            const headers = ['Part Number', 'Description', 'Store', 'Quantity', 'Work Order'];
            const rows = this.filteredInventory.map(item => [
                item.part_number,
                item.description,
                item.store_name,
                item.quantity,
                item.work_order || 'Original'
            ]);

            const csvContent = [headers, ...rows].map(row => row.join(',')).join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'inventory_export.csv';
            a.click();
        }
    };
}
