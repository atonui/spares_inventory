function inventoryApp() {
    const core = {
        timezoneContext: null,
        timezoneError: '',
        timezoneLoading: false,
        async loadTimezoneContext() {
            if (this.timezoneLoading) return;
            const actor=this.currentUser?.id;
            this.timezoneLoading=true;this.timezoneError='';
            try {
                const data=await this.apiCall('/timezone-context');
                if (actor!==this.currentUser?.id) return;
                if (!validTimezoneContext(data)) throw Error('Timezone settings are unavailable.');
                this.timezoneContext=data;
            } catch(error) { if(actor===this.currentUser?.id) {this.timezoneContext=null;this.timezoneError=error.message;} }
            finally {this.timezoneLoading=false;}
        },
        formatInstant(value) { return InventoryTime.formatInstant(value,this.timezoneContext?.display_timezone); },
        formatBusinessInstant(value,context) { return InventoryTime.formatInstant(value,context?.timezone); },
        formatDate(value) { return InventoryTime.formatDate(value); },
        businessToday() { return InventoryTime.today(this.timezoneContext?.business_timezone); },
        // Authentication state
        isAuthenticated: false,
        currentUser: null,
        token: null,

        // UI state
        loading: false,
        error: '',
        successMessage: '',

        // Forms
        loginForm: {
            email: '',
            password: '',
            remember_me: false
        },

        // Search and filters
        searchTerm: '',
        storeFilter: '',
        storeSearchTerm: '',
        inventoryLoadFailed: false,
        inventoryLoadError: '',
        // modals
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

        // logging
        // selected store for inventory view
        selectedStore: null,
        storeInventory: [],

        // Movement filters
        // advanced search
        advancedSearch: {
            partNumber: '',
            description: '',
            category: '',
            storeType: '',
            minQuantity: '',
            maxQuantity: '',
            lowStockOnly: false
        },

        // Data
        stats: {},
        stores: [],
        parts: [],
        inventory: [],
        workOrders: [],
        users: [],
        archivedRecords: [],
        showArchivedPanel: false,
        filteredInventory: [],
        storeTypes: [],
        csrfToken: '',

        // Equipment-related state
        // API Base URL
        apiUrl: '/api',

        // Initialize
        async checkAuth() {
            // Check if user info exists in localStorage
            const userStr = localStorage.getItem('currentUser');
            if (userStr) {
                try {
                    this.currentUser = JSON.parse(userStr);
                    await this.getCurrentUser();
                    this.isAuthenticated = true;
                    try { await this.getCsrfToken(); }
                    catch (error) { this.error = error.message; }
                    await this.loadAllData();
                } catch (error) {
                    localStorage.removeItem('currentUser');
                    this.currentUser = null;
                    this.isAuthenticated = false;
                }
            }
        },

        // Authentication
        async login() {
            this.loading = true;
            this.error = '';

            try {
                const response = await InventoryCsrf.request(this, `${this.apiUrl}/auth/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include', // IMPORTANT: Include cookies
                    body: JSON.stringify(this.loginForm)
                });

                if (!response.ok) {
                    throw new Error('Invalid credentials');
                }

                const data = await response.json();

                // No longer store token in localStorage
                this.currentUser = data.user;
                this.isAuthenticated = true;

                // Store user info (but not token)
                localStorage.setItem('currentUser', JSON.stringify(data.user));

                await this.loadAllData();

            } catch (error) {
                this.error = error.message;
            } finally {
                this.loading = false;
            }
        },

        async getCurrentUser() {
            const response = await fetch(`${this.apiUrl}/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) {
                throw new Error('Authentication failed');
            }

            this.currentUser = await response.json();
        },

        async logout({localOnly = false} = {}) {
            this.timezoneContext=null;this.timezoneError='';this.movementTimeContext=null;this.activityTimeContext=null;
            try {
                if (!localOnly) await this.apiCall('/auth/logout', { method: 'POST' });
            } catch (error) {
                console.error('Logout error:', error);
            }

            resetConsumptionReports(this);
            // Clear local state
            this.currentUser = null;
            this.isAuthenticated = false;
            localStorage.removeItem('currentUser');

            // Redirect to login
            window.location.href = '/static/index.html';
        },

        async getCsrfToken() {
            return InventoryCsrf.token(this, this.apiUrl);
        },

        async apiCall(endpoint, options = {}, onTimeContext = null) {
            /**
             * Universal API call handler for both JSON and file uploads
             * Automatically handles:
             * - CSRF tokens for state-changing operations
             * - HTTPOnly cookies (credentials: include)
             * - File uploads (FormData detection)
             * - Error handling and token refresh
             * - Rate limiting
             */

            const isFileUpload = options.body instanceof FormData;

            const defaultHeaders = {};

            // Only set Content-Type for JSON requests (FormData sets its own)
            if (!isFileUpload) {
                defaultHeaders['Content-Type'] = 'application/json';
            }

            const config = {
                ...options,
                credentials: 'include', // Always include cookies
                headers: {
                    ...defaultHeaders,
                    ...options.headers
                }
            };

            try {
                const response = await InventoryCsrf.request(this, `${this.apiUrl}${endpoint}`, config, this.apiUrl);

                // Handle 401 - Authentication failed
                if (response.status === 401) {
                    await this.logout({localOnly: true});
                    this.error = "Session expired. Please login again.";
                    return null;
                }

                if (response.status === 403) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.detail || 'Access forbidden');
                }

                // Handle 422 - Validation error
                if (response.status === 422) {
                    const errorData = await response.json().catch(() => ({}));
                    console.error('Validation error:', errorData);

                    // Extract detailed error message if available
                    if (errorData.detail) {
                        if (Array.isArray(errorData.detail)) {
                            const messages = errorData.detail.map(err =>
                                `${err.loc?.join('.')}: ${err.msg}`
                            ).join(', ');
                            throw new Error(`Validation error: ${messages}`);
                        }
                        throw new Error(errorData.detail);
                    }
                    throw new Error('Validation error');
                }

                // Handle 429 - Rate limit exceeded
                if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After') || '60';
                    throw new Error(`Too many requests. Please try again in ${retryAfter} seconds.`);
                }

                // Handle other errors
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.detail || `API error: ${response.status}`);
                }

                // Handle 204 No Content
                if (response.status === 204) {
                    return null;
                }

                // Parse and return JSON response
                const data=await response.json();
                if(onTimeContext) {
                    let metadata=null;
                    try {metadata=JSON.parse(response.headers?.get('X-Report-Time-Context') || 'null');} catch(error) {}
                    onTimeContext(metadata && InventoryTime.isValidZone(metadata.timezone) && Number.isSafeInteger(metadata.timezone_revision) ? metadata : null);
                }
                return data;

            } catch (error) {
                // Don't log if it's a logout scenario
                if (!error.message.includes('Session expired')) {
                    console.error('API call error:', error);
                }
                this.error = error.message;
                throw error;
            }
        },

        // Data loading
        async loadAllData() {
            this.loading = true;
            try {
                await this.loadTimezoneContext();
                const promises = [
                    this.loadStats(),
                    this.loadStores(),
                    this.loadParts(),
                    this.loadInventory(),
                    this.loadMovements(),
                    this.loadPendingTransfers(),
                    this.loadEquipment(),
                    this.loadEquipmentStats(),
                    this.loadCalibrationSettings(),
                    this.loadStoreTypes()
                ];

                if (['admin','superadmin'].includes(this.currentUser?.role)) {
                    promises.push(this.loadUsers());
                }

                await Promise.all(promises);
            } catch (error) {
                this.error = 'Failed to load data: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async loadStats() {
            console.log('🔄 Loading stats...'); // Debug log
            try {
                const response = await this.apiCall('/stats');
                console.log('📊 Stats response:', response); // Debug log

                // Force Alpine reactivity by creating a new object
                this.stats = {
                    total_parts: response.total_parts || 0,
                    total_stores: response.total_stores || 0,
                    low_stock: response.low_stock || 0,
                    my_parts: response.my_parts || 0,
                    in_transit_quantity: response.in_transit_quantity || 0
                };

                console.log('✅ Stats updated:', this.stats); // Debug log
            } catch (error) {
                console.error('❌ Failed to load stats:', error);
            }
        },

        async loadStores() {
            this.stores = await this.apiCall('/stores');
        },

        // function to load store types
        async loadStoreTypes() {
            try {
                this.storeTypes = await this.apiCall('/store-types');
            } catch (error) {
                console.error('Failed to load store types:', error);
                this.storeTypes = [];
            }
        },

        async loadParts() {
            this.parts = await this.apiCall('/parts');
        },

        async loadInventory({refreshReplenishment=true}={}) {
            this.loading = true;
            try {
                const response = await this.apiCall('/inventory');
                this.inventory = response;
                if (this.error === this.inventoryLoadError) this.error = '';
                this.inventoryLoadError = '';
                this.inventoryLoadFailed = false;
                this.filterInventory();
                if (this.selectedStore) this.storeInventory=this.inventory.filter(i=>i.store_id===this.selectedStore.id);
                if(this.showLowStockPanel && refreshReplenishment) await this.loadReplenishment();
            } catch (error) {
                this.inventoryLoadFailed = true;
                this.inventoryLoadError = 'Inventory could not refresh. Retry or reload the page: ' + error.message;
                this.error = this.inventoryLoadError;
            } finally {
                this.loading = false;
            }
        },

        async loadUsers() {
            if (['admin','superadmin'].includes(this.currentUser?.role)) {
                this.users = await this.apiCall('/users');
            }
        },

        async loadArchivedRecords() {
            this.error='';
            try {
                const kinds=['parts','stores','users'];
                const groups=await Promise.all(kinds.map(kind=>this.apiCall('/'+kind+'?include_archived=true')));
                this.archivedRecords=groups.flatMap((rows,index)=>rows.filter(row=>row.archived_at).map(row=>({
                    kind:kinds[index],id:row.id,label:row.part_number || row.name,archived_at:row.archived_at
                })));
            } catch(error) { this.error='Failed to load archived records: '+error.message; }
        },

        async restoreArchivedRecord(record) {
            if(this.loading || !['parts','stores','users'].includes(record.kind)) return;
            if(!confirm(`Restore ${record.label} to active use?`)) return;
            this.loading=true; this.error='';
            try {
                const result=await this.apiCall(`/${record.kind}/${record.id}/restore`,{method:'POST'});
                this.successMessage=result.message;
                await this.loadParts(); await this.loadStores(); await this.loadUsers();
                await this.loadInventory(); await this.loadStats(); await this.loadArchivedRecords();
            } catch(error) { this.error='Failed to restore record: '+error.message; }
            finally { this.loading=false; }
        },

        // Filtering - FIXED SEARCH FUNCTION
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

        get currentViewLabel() {
            const views=[['showStoreInventoryPanel',this.selectedStore?.name + ' inventory'],['showInventoryPanel','Inventory'],['showAllStoresPanel','Stores'],['showAllPartsPanel','Parts catalog'],['showMyPartsPanel','My parts'],['showLowStockPanel','Replenishment'],['showEquipmentPanel','Equipment'],['showMovementsPanel','Movement history'],['showUsersPanel','Manage users'],['showStoresPanel','Manage stores'],['showPartsPanel','Manage parts'],['showStoreTypesPanel','Store types'],['showArchivedPanel','Archived records'],['showLogsPanel','Activity logs'],['showReportsPanel','Reports']];
            return views.find(([key])=>this[key])?.[1] || 'Inventory';
        },

        // advanced search filter
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

        // search parts for selection
        // Store Type Management
// CSV Export Functions

        // Actions
        // User management
        // Equipment Management Functions

        // Store management
        // Parts management
        // Helper functions

        async refreshDashboard() {
            // helper method to refresh all key data on the dashboard after changes
            console.log('🔄 Refreshing dashboard...');
            await Promise.all([
                this.loadStats(),
                this.loadEquipmentStats()
            ]);
            console.log('✅ Dashboard refreshed');
        },

        getUserName(userId) {
            if (!userId) return 'Unassigned';
            const user = this.users.find(u => u.id === userId);
            return user ? user.name : 'Unknown';
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

        // Bulk import functions
    };
    return composeInventoryFeatures(core, consumptionReportsFeature(), replenishmentFeature(), stockCountsFeature(), stockImportsFeature(), transferReceiptsFeature(), stockDispatchFeature(), stockEntryFeature(), stockConsumptionFeature(), partsAdminFeature(), storesAdminFeature(), usersAdminFeature(), storeTypesAdminFeature(), equipmentFeature(), activityLogsFeature(), movementHistoryFeature(), inventoryExportsFeature());
}
