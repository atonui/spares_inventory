function inventoryBrowsingFeature() {
    return {
        searchTerm: '',
        storeFilter: '',
        storeSearchTerm: '',
        selectedStore: null,
        storeInventory: [],
        filteredInventory: [],
        advancedSearch: {
            partNumber: '',
            description: '',
            category: '',
            storeType: '',
            minQuantity: '',
            maxQuantity: '',
            lowStockOnly: false
        },

        matchInventoryRows(rows, query) {
            const terms=String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
            return rows.filter(item=>{
                const text=[item.part_number,item.description,item.store_name,item.work_order].map(value=>String(value || '').toLowerCase()).join(' ');
                return terms.every(term=>text.includes(term));
            });
        },

        filterInventory() {
            let rows=this.matchInventoryRows(this.inventory,this.searchTerm);
            if (this.storeFilter) rows=rows.filter(item=>item.store_id===Number(this.storeFilter));
            this.filteredInventory=rows;
        },

        clearInventoryFilters() {
            this.searchTerm='';this.storeFilter='';
            this.openPanel('showInventoryPanel');this.filterInventory();
        },

        get filteredStoreInventory() { return this.matchInventoryRows(this.storeInventory,this.storeSearchTerm); },

        filterInventoryAdvanced() {
            let filtered = this.inventory;

            if (this.advancedSearch.partNumber) {
                filtered = filtered.filter(item =>
                    item.part_number.toLowerCase().includes(this.advancedSearch.partNumber.toLowerCase())
                );
            }

            if (this.advancedSearch.category) {
                const parts = this.parts.filter(p => p.category === this.advancedSearch.category);
                const partNumbers = parts.map(p => p.part_number);
                filtered = filtered.filter(item => partNumbers.includes(item.part_number));
            }

            if (this.advancedSearch.lowStockOnly) {
                filtered = filtered.filter(item => this.isLowStock(item));
            }

            if (this.advancedSearch.minQuantity) {
                filtered = filtered.filter(item => item.quantity >= parseInt(this.advancedSearch.minQuantity));
            }

            if (this.advancedSearch.maxQuantity) {
                filtered = filtered.filter(item => item.quantity <= parseInt(this.advancedSearch.maxQuantity));
            }

            this.filteredInventory = filtered;
        },

        // UI helpers
        getStoreClass(storeType, storeOwner) {
            if (storeOwner === this.currentUser.id) return 'store-mine';
            return 'store-' + storeType;
        },

        canEdit(storeOwner, storeType) {
            if (!this.currentUser) return false;
            return ['admin', 'superadmin'].includes(this.currentUser.role) ||
                storeOwner === this.currentUser.id || storeType === 'central';
        },

        get editableStores() {
            return this.stores.filter(store => this.canEdit(store.assigned_user_id, store.type));
        },

        get allPartsView() {
            return this.parts;
        },

        get allStoresView() {
            return this.stores;
        },

        isLowStock(item) {
            return item.min_threshold > 0 && item.quantity < item.min_threshold && !item.is_allocated && !item.work_order;
        },

        get lowStockItems() {
            return this.inventory.filter(item => this.isLowStock(item));
        },

        get myPartsView() {
            return this.inventory.filter(item => item.store_owner === this.currentUser?.id);
        },

        async viewStoreInventory(store) {
            if (!store) return;
            this.selectedStore = store;
            this.storeSearchTerm = '';
            this.storeInventory = this.inventory.filter(item => item.store_id === store.id);
            this.openPanel('showStoreInventoryPanel');
        },

    };
}
