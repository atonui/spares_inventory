function navigationFeature() {
    return {
        showProfileModal: false,

        // panels
        showUsersPanel: false,
        showStoresPanel: false,
        showPartsPanel: false,
        showAllPartsPanel: false,
        showAllStoresPanel: false,
        showMyPartsPanel: false,
        showStoreInventoryPanel: false,
        showStoreTypesPanel: false,
        showInventoryPanel: true,

        get currentViewLabel() {
            const views=[['showStoreInventoryPanel',this.selectedStore?.name + ' inventory'],['showInventoryPanel','Inventory'],['showAllStoresPanel','Stores'],['showAllPartsPanel','Parts catalog'],['showMyPartsPanel','My parts'],['showLowStockPanel','Replenishment'],['showEquipmentPanel','Equipment'],['showMovementsPanel','Movement history'],['showUsersPanel','Manage users'],['showStoresPanel','Manage stores'],['showPartsPanel','Manage parts'],['showStoreTypesPanel','Store types'],['showArchivedPanel','Archived records'],['showLogsPanel','Activity logs'],['showReportsPanel','Reports']];
            return views.find(([key])=>this[key])?.[1] || 'Inventory';
        },

        closeAllOtherPanels() {
            this.showArchivedPanel = false;
            this.showUsersPanel = false;
            this.showStoresPanel = false;
            this.showPartsPanel = false;
            this.showMovementsPanel = false;
            this.showAllPartsPanel = false;
            this.showAllStoresPanel = false;
            this.showLowStockPanel = false;
            this.showMyPartsPanel = false;
            this.showStoreInventoryPanel = false;
            this.showLogsPanel = false;
            this.showReportsPanel = false;
            this.showEquipmentPanel = false;
            this.showStoreTypesPanel = false;
            // Don't close inventory panel
        },

        closeAllPanels() {
            this.showArchivedPanel = false;
            this.showUsersPanel = false;
            this.showStoresPanel = false;
            this.showPartsPanel = false;
            this.showMovementsPanel = false;
            this.showAllPartsPanel = false;
            this.showAllStoresPanel = false;
            this.showLowStockPanel = false;
            this.showMyPartsPanel = false;
            this.showStoreInventoryPanel = false;
            this.showLogsPanel = false;
            this.showReportsPanel = false;
            this.showEquipmentPanel = false;
            this.showStoreTypesPanel = false;
            this.showInventoryPanel = true;
        },

        openPanel(panelName) {
            this.closeAllPanels();
            // Also close all modals
            this.showAddModal = false;
            this.showEditModal = false;
            this.showTransferModal = false;
            this.showUserModal = false;
            this.showStoreModal = false;
            this.showPartModal = false;
            this.showInventoryPanel = false;
            this.showProfileModal = false;
            this.showEquipmentModal = false;
            this.showCalibrationModal = false;
            this.showTransferEquipmentModal = false;
            this.showEquipmentHistoryModal = false;
            this.showCalibrationSettingsModal = false;
            this.showStoreTypeModal = false;

            // Keep the user's filters when returning to inventory.
            if (panelName === 'showInventoryPanel') {
                this.filterInventory();
            }
            // open the requested panel
            this[panelName] = true;
            if(panelName === 'showReportsPanel') this.loadConsumptionReport();
            if(panelName === 'showLowStockPanel') this.loadReplenishment();

        },

    };
}
