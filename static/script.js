function inventoryApp() {
    return {
        // Authentication state
        isAuthenticated: false,
        currentUser: null,
        token: null,
        
        // UI state
        loading: false,
        addingStock: false,
        error: '',
        successMessage: '',
        
        // Forms
        loginForm: {
            email: '',
            password: '',
            remember_me: false
        },
        
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
        
        transferForm: {
            inventory_id: '',
            to_store_id: '',
            quantity: ''
        },
        
        userForm: {
            email: '',
            name: '',
            password: '',
            role: 'engineer',
            territory: ''
        },
        
        storeForm: {
            name: '',
            type: 'customer_site',
            location: '',
            assigned_user_id: ''
        },
        
        partForm: {
            part_number: '',
            description: '',
            category: '',
            unit_cost: ''
        },
        
        // Search and filters
        searchTerm: '',
        storeFilter: '',
        storeSearchTerm: '',
        inventoryLoadFailed: false,
        inventoryLoadError: '',
        partSearchTerm: '',
        filteredPartsForSelection: [],
        // modals
        showAddModal: false,
        showEditModal: false,
        showTransferModal: false,
        showUserModal: false,
        showStoreModal: false,
        showPartModal: false,
        showProfileModal: false,
        showStoreTypeModal: false,
        showConsumeModal: false,

        // part import modal properties
        showDuplicateResolutionModal: false,
        csvDuplicates: [],
        storeConflicts: [],
        pendingImportData: null,
        
        // panels
        showUsersPanel: false,
        showStoresPanel: false,
        showPartsPanel: false,
        showMovementsPanel: false,
        showAllPartsPanel: false,
        showAllStoresPanel: false,
        showLowStockPanel: false,
        showMyPartsPanel: false,
        showStoreInventoryPanel: false,
        showStoreTypesPanel: false,
        showInventoryPanel: true,
        
        // logging
        showLogsPanel: false,
        showStatsModal: false,
        showLogDetailsModal: false,
        activityLogs: [],
        activityStats:{},
        selectedLog: null,
        logFilters: {
            startDate: '',
            endDate: '',
            action: '',
            targetUserId: '',
            status: ''
        },
        // selected store for inventory view
        selectedStore: null,
        storeInventory: [],
        editingUser: null,
        editingStore: null,
        editingPart: null,
        editingStoreType: null,
        
        // Movement filters
        movementFilters: {
            startDate: '',
            endDate: '',
            movementType: '',
            partId: '',
            storeId: ''
        },

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
        stockCount: null,
        stockCountPreview: null,
        stockCountBusy: false,
        stockCountTrigger: null,
        workOrders: [],
        users: [],
        movements: [],
        pendingTransfers: [],
        archivedRecords: [],
        showArchivedPanel: false,
        filteredInventory: [],
        storeTypes: [],
        csrfToken: '',

        // Equipment-related state
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

        storeTypeForm: {
            type_code: '',
            type_name: '',
            description: '',
            display_order: 0,
            is_active: true
        },

        consumeForm: {
            inventory_id: '',
            part_number: '',
            description: '',
            store_name: '',
            available_quantity: 0,
            quantity: '',
            work_order_number: '',
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
                    await this.getCsrfToken(); // Get CSRF token
                    this.isAuthenticated = true;
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
                const response = await fetch(`${this.apiUrl}/auth/login`, {
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

        async logout() {
            try {
                await this.apiCall('/auth/logout', { method: 'POST' });
            } catch (error) {
                console.error('Logout error:', error);
            }
            
            // Clear local state
            this.currentUser = null;
            this.isAuthenticated = false;
            localStorage.removeItem('currentUser');
            
            // Redirect to login
            window.location.href = '/static/index.html';
        },

        // function to get CSRF token
        async getCsrfToken() {
            try {
                const response = await fetch(`${this.apiUrl}/csrf-token`, {
                    credentials: 'include'
                });
                const data = await response.json();
                this.csrfToken = data.csrf_token;
            } catch (error) {
                console.error('Failed to get CSRF token:', error);
            }
        },
    
        async apiCall(endpoint, options = {}) {
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
            
            // Add CSRF token for state-changing operations
            if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
                if (this.csrfToken) {
                    defaultHeaders['X-CSRF-Token'] = this.csrfToken;
                } else {
                    console.warn('CSRF token not available, fetching...');
                    await this.getCsrfToken();
                    if (this.csrfToken) {
                        defaultHeaders['X-CSRF-Token'] = this.csrfToken;
                    }
                }
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
                const response = await fetch(`${this.apiUrl}${endpoint}`, config);
                
                // Handle 401 - Authentication failed
                if (response.status === 401) {
                    this.logout();
                    this.error = "Session expired. Please login again.";
                    return null;
                }
                
                // Handle 403 - CSRF token might be expired
                if (response.status === 403) {
                    const errorData = await response.json().catch(() => ({}));
                    
                    // If it's a CSRF error, try to refresh the token and retry ONCE
                    if (errorData.detail && errorData.detail.toLowerCase().includes('csrf')) {
                        console.log('CSRF token expired, refreshing and retrying...');
                        await this.getCsrfToken();
                        
                        // Retry the request once with new token
                        if (this.csrfToken) {
                            config.headers = {
                                ...defaultHeaders,
                                'X-CSRF-Token': this.csrfToken,
                                ...options.headers
                            };
                            
                            const retryResponse = await fetch(`${this.apiUrl}${endpoint}`, config);
                            
                            if (retryResponse.status === 401) {
                                this.logout();
                                this.error = "Session expired. Please login again.";
                                return null;
                            }
                            
                            if (!retryResponse.ok) {
                                const retryError = await retryResponse.json().catch(() => ({}));
                                throw new Error(retryError.detail || `Request failed: ${retryResponse.status}`);
                            }
                            
                            if (retryResponse.status === 204) return null;
                            return await retryResponse.json();
                        }
                    }
                    
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
                return await response.json();
                
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

        async loadInventory() {
            this.loading = true;
            try {
                const response = await this.apiCall('/inventory');
                this.inventory = response;
                if (this.error === this.inventoryLoadError) this.error = '';
                this.inventoryLoadError = '';
                this.inventoryLoadFailed = false;
                this.filterInventory();
                if (this.selectedStore) this.storeInventory=this.inventory.filter(i=>i.store_id===this.selectedStore.id);
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

        async loadPendingTransfers() {
            this.pendingTransfers = await this.apiCall('/inventory/transfers');
        },

        async refreshTransfers() {
            this.error = '';
            try {
                await this.loadPendingTransfers();
                await this.loadStats();
            } catch (error) { this.error = 'Failed to refresh transfers: ' + error.message; }
        },

        async confirmTransfer(transfer, action) {
            if (this.loading || (action === 'receive' ? !transfer.can_receive : !transfer.can_return)) return;
            const message = action === 'receive'
                ? `Confirm physical receipt of all ${transfer.quantity} x ${transfer.part_number} at ${transfer.to_store_name}?`
                : `Confirm all ${transfer.quantity} x ${transfer.part_number} have physically returned to ${transfer.from_store_name}? Source stock will be restored.`;
            if (!confirm(message)) return;
            this.loading = true;
            this.error = '';
            try {
                const result = await this.apiCall(`/inventory/transfers/${transfer.id}/${action}`, {
                    method:'POST', body:JSON.stringify({confirmed:true})
                });
                this.successMessage = result.message;
                await this.loadPendingTransfers();
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory = this.inventory.filter(i=>i.store_id===this.selectedStore.id);
                await this.loadMovements();
                await this.loadStats();
            } catch (error) { this.error = 'Confirmation failed: ' + error.message; }
            finally { this.loading = false; }
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
            this.movements = await this.apiCall(endpoint);
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
            const views=[['showStoreInventoryPanel',this.selectedStore?.name + ' inventory'],['showInventoryPanel','Inventory'],['showAllStoresPanel','Stores'],['showAllPartsPanel','Parts catalog'],['showMyPartsPanel','My parts'],['showLowStockPanel','Low stock'],['showEquipmentPanel','Equipment'],['showMovementsPanel','Movement history'],['showUsersPanel','Manage users'],['showStoresPanel','Manage stores'],['showPartsPanel','Manage parts'],['showStoreTypesPanel','Store types'],['showArchivedPanel','Archived records'],['showLogsPanel','Activity logs']];
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
                filtered = filtered.filter(item => item.quantity <= item.min_threshold);
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

        get lowStockItems() {
            return this.inventory.filter(item => item.quantity <= item.min_threshold);
        },

        get myPartsView() {
            return this.inventory.filter(item => item.store_owner === this.currentUser?.id);
        },

        get recentActivity() {
            // Get last 20 movements
            return this.movements.slice(0, 20);
        },

        getImportPreview() {
            if (!this.pendingImportData) return [];
            const groups = new Map();
            for (const row of this.pendingImportData.parsedRows) {
                if (!groups.has(row.partNumber)) groups.set(row.partNumber, []);
                groups.get(row.partNumber).push(row.quantity);
            }
            return [...groups].map(([partNumber, quantities]) => {
                const duplicate = this.csvDuplicates.find(d => d.partNumber === partNumber);
                const conflict = this.storeConflicts.find(c => c.partNumber === partNumber);
                const unresolved = duplicate && !duplicate.action;
                const quantity = duplicate?.action === 'tally' ? quantities.reduce((a,b)=>a+b,0) : quantities[0];
                const action = unresolved ? 'resolve' : duplicate?.action === 'skip' || conflict?.action === 'skip' ? 'skip' : conflict ? 'replace' : 'create';
                return {partNumber, quantity, action, currentQuantity: conflict ? conflict.currentQuantity : null};
            });
        },

        getResolutionSummary() {
            const rows = this.getImportPreview();
            return {willAdd: rows.filter(r=>r.action==='create').length,
                    willUpdate: rows.filter(r=>r.action==='replace').length,
                    willSkip: rows.filter(r=>r.action==='skip').length};
        },

        setAllCsvDuplicates(action) {
            this.csvDuplicates.forEach(dup => dup.action = action);
        },

        setAllStoreConflicts(action) {
            this.storeConflicts.forEach(conflict => conflict.action = action);
        },

        setAllActions(action) {
            this.setAllCsvDuplicates(action);
            this.setAllStoreConflicts(action);
        },

        cancelDuplicateResolution() {
            this.showDuplicateResolutionModal = false;
            this.csvDuplicates = [];
            this.storeConflicts = [];
            this.pendingImportData = null;
        },

        async processDuplicateResolution() {
            if (this.loading) return;
            this.loading = true;
            this.error = '';
            try {
                if (!this.pendingImportData) throw new Error('No pending import');
                const preview = this.getImportPreview();
                if (preview.some(r=>r.action==='resolve')) throw new Error('Choose how to handle each duplicate CSV part');
                if (preview.some(r=>!Number.isSafeInteger(r.quantity))) throw new Error('Combined quantity is too large');
                const rows = preview.filter(r=>r.action!=='skip').map(r=>({
                    part_number:r.partNumber, quantity:r.quantity, expected_quantity:r.currentQuantity
                }));
                if (!rows.length) throw new Error('No rows selected for import');
                const result = await this.apiCall('/inventory/import-balances', {
                    method:'POST', body:JSON.stringify({store_id:this.pendingImportData.storeId,rows})
                });
                this.successMessage = `Import saved: ${result.added} created, ${result.updated} updated, ${result.unchanged} unchanged.`;
                this.cancelDuplicateResolution();
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory = this.inventory.filter(i=>i.store_id===this.selectedStore.id);
                await this.loadStats();
            } catch (error) {
                this.error = 'Import not saved: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async viewStoreInventory(store) {
            if (!store) return;
            this.selectedStore = store;
            this.storeSearchTerm = '';
            this.storeInventory = this.inventory.filter(item => item.store_id === store.id);
            this.openPanel('showStoreInventoryPanel');
        },

        async startStockCount(store, trigger = null) {
            if (!store || this.stockCountBusy) return;
            this.stockCountBusy = true;
            this.error = '';
            try {
                const sheet = await this.apiCall(`/inventory/count-sheet/${store.id}`);
                this.stockCount = {...sheet, rows:sheet.rows.map(row=>({...row,counted_quantity:'',reason:''}))};
                this.stockCountPreview = null;
                if (trigger) this.stockCountTrigger = trigger;
            } catch (error) {
                this.error = 'Count could not start: ' + error.message;
            } finally { this.stockCountBusy = false; this.focusStockCountDialog(); }
        },

        async previewStockCount() {
            if (!this.stockCount || this.stockCountBusy) return;
            this.stockCountBusy = true;
            this.error = '';
            this.stockCountPreview = null;
            try {
                const rows = this.stockCount.rows.filter(row=>String(row.counted_quantity).trim()!=='').map(row=>{
                    const quantity = Number(row.counted_quantity);
                    if (!Number.isSafeInteger(quantity) || quantity<0 || quantity>2147483647)
                        throw new Error('Enter whole physical counts from 0 to 2,147,483,647');
                    const reason = row.reason.trim();
                    if (quantity!==row.quantity && !reason) throw new Error('Enter a reason for every correction');
                    return {inventory_id:row.inventory_id,counted_quantity:quantity,reason};
                });
                if (!rows.length) throw new Error('Enter at least one physical count');
                this.stockCountPreview = await this.apiCall('/inventory/count-preview',{
                    method:'POST',body:JSON.stringify({sheet_token:this.stockCount.sheet_token,rows})
                });
            } catch (error) { this.error = 'Count preview failed: ' + error.message; }
            finally { this.stockCountBusy = false; this.focusStockCountDialog(); }
        },

        editStockCount() {
            if (this.stockCountBusy) return;
            this.stockCountPreview = null;
            this.focusStockCountDialog();
        },

        focusStockCountDialog() {
            if (this.stockCount && this.$nextTick)
                this.$nextTick(()=>this.$refs.stockCountDialog?.focus());
        },

        restoreStockCountFocus() {
            const trigger = this.stockCountTrigger;
            this.stockCountTrigger = null;
            if (this.$nextTick) this.$nextTick(()=>trigger?.focus());
            else trigger?.focus();
        },

        async restartStockCount() {
            if (!this.stockCount || this.stockCountBusy) return;
            if (!confirm('Discard these entered counts and load fresh balances? You will need to recount the stock.')) return;
            await this.startStockCount({id:this.stockCount.store_id});
        },

        cancelStockCount() {
            if (this.stockCountBusy) return;
            this.stockCount = null;
            this.stockCountPreview = null;
            this.restoreStockCountFocus();
        },

        trapStockCountFocus(event, dialog) {
            const controls = [...dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), [tabindex="0"]')].filter(el=>el.offsetParent!==null);
            if (!controls.length) { event.preventDefault(); dialog.focus(); return; }
            const first = controls[0], last = controls[controls.length-1];
            const active = dialog.ownerDocument.activeElement;
            if (event.shiftKey && (active===first || !controls.includes(active))) {
                event.preventDefault(); last.focus();
            } else if (!event.shiftKey && (active===last || !controls.includes(active))) {
                event.preventDefault(); first.focus();
            }
        },

        async confirmStockCount() {
            if (!this.stockCountPreview || this.stockCountBusy) return;
            if (!confirm('Confirm these physical counts and save the listed corrections? Blank entries will stay unchanged.')) return;
            this.stockCountBusy = true;
            this.error = '';
            let saved = false;
            try {
                const result = await this.apiCall('/inventory/count-confirm',{
                    method:'POST',body:JSON.stringify({preview_token:this.stockCountPreview.preview_token,confirmed:true})
                });
                saved = true;
                this.stockCount = null;
                this.stockCountPreview = null;
                this.successMessage = `Stock count saved: ${result.changed} corrected, ${result.unchanged} unchanged.`;
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory=this.inventory.filter(row=>row.store_id===this.selectedStore.id);
                await this.loadStats();
            } catch (error) { this.error = saved ? 'Stock count saved, but refresh failed. Reload the page: ' + error.message : 'Count not saved: ' + error.message; }
            finally {
                this.stockCountBusy = false;
                if (saved) this.restoreStockCountFocus();
                else this.focusStockCountDialog();
            }
        },
        async addStockToStore(store) {
            this.addForm.store_id = store.id;
            this.addForm.part_id = '';
            this.addForm.quantity = '';
            this.addForm.work_order_number = '';
            this.partSearchTerm = '';  // Reset search
            this.filteredPartsForSelection = this.parts;  // Show all parts initially
            this.showAddModal = true;
        },

        async importPartsToStore(event, storeId) {
            const file = event.target.files[0];
            if (!file || this.loading) return;
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            this.cancelDuplicateResolution();
            try {
                const text = (await file.text()).replace(/^\uFEFF/, '');
                const lines = text.split(/\r?\n/).filter(line=>line.trim());
                const parseLine = (line, number) => {
                    const match = line.match(/^\s*("(?:[^\"]|\"\")*"|[^",]*),\s*("(?:[^\"]|\"\")*"|[^",]*)\s*$/);
                    if (!match) throw new Error(`Row ${number}: expected exactly two CSV columns`);
                    return match.slice(1).map(value=> {
                        value=value.trim();
                        return value.startsWith('"') ? value.slice(1,-1).replace(/""/g,'"').trim() : value;
                    });
                };
                if (lines.length < 2) throw new Error('CSV has no stock rows');
                const header = parseLine(lines[0],1);
                if (header[0] !== 'part_number' || header[1] !== 'quantity') throw new Error('Use the part_number,quantity template headers');
                if (lines.length > 1001) throw new Error('Maximum 1,000 stock rows per import');
                const parsedRows = lines.slice(1).map((line,index)=> {
                    const [partNumber,quantityText] = parseLine(line,index+2);
                    const quantity = Number(quantityText);
                    if (!partNumber || !/^\d+$/.test(quantityText) || !Number.isSafeInteger(quantity)) {
                        throw new Error(`Row ${index+2}: enter a part number and a whole quantity of zero or more`);
                    }
                    return {partNumber,quantity};
                });
                await this.loadParts();
                this.inventory = await this.apiCall('/inventory');
                for (const row of parsedRows) {
                    if (!this.parts.some(p=>p.part_number===row.partNumber)) throw new Error(`Part ${row.partNumber} not found in catalog`);
                }
                const groups = new Map();
                for (const row of parsedRows) {
                    if (!groups.has(row.partNumber)) groups.set(row.partNumber,[]);
                    groups.get(row.partNumber).push(row);
                }
                this.csvDuplicates = [...groups].filter(([,rows])=>rows.length>1).map(([partNumber,rows])=>({
                    partNumber,rows,count:rows.length,quantities:rows.map(r=>r.quantity),
                    totalQuantity:rows.reduce((sum,r)=>sum+r.quantity,0),action:''
                }));
                this.storeConflicts = [];
                for (const [partNumber,rows] of groups) {
                    const stock = this.inventory.filter(i=>i.part_number===partNumber &&
                        i.store_id===storeId && !i.work_order);
                    if (stock.length > 1) throw new Error(`Duplicate stock for ${partNumber}; reconcile it before importing`);
                    if (stock.length) this.storeConflicts.push({
                        partNumber,currentQuantity:stock[0].quantity,action:'replace'
                    });
                }
                this.pendingImportData = {parsedRows,storeId};
                this.showDuplicateResolutionModal = true;
            } catch (error) {
                this.cancelDuplicateResolution();
                this.error = 'Import not saved: ' + error.message;
            } finally {
                this.loading = false;
                event.target.value = '';
            }
        },

        downloadStoreImportTemplate() {
            const csv = 'part_number,quantity\nPART-001,10\nPART-002,5';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'store_parts_import_template.csv';
            a.click();
            URL.revokeObjectURL(url);
        },

        // search parts for selection
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

        // Store Type Management
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

        // logging functions
        async loadActivityLogs() {
            this.loading = true;
            this.error = '';

            try {
                const params = new URLSearchParams();
                
                if (this.logFilters.startDate) {
                    params.append('start_date', this.logFilters.startDate);
                }
                if (this.logFilters.endDate) {
                    params.append('end_date', this.logFilters.endDate);
                }
                if (this.logFilters.action) {
                    params.append('action', this.logFilters.action);
                }
                if (this.logFilters.targetUserId) {
                    params.append('target_user_id', this.logFilters.targetUserId);
                }
                if (this.logFilters.status) {
                    params.append('status', this.logFilters.status);
                }
                
                params.append('limit', '200'); // Get last 200 logs
                
                const queryString = params.toString();
                const endpoint = queryString ? `/logs/activity?${queryString}` : '/logs/activity';
                
                const response = await fetch(`${this.apiUrl}${endpoint}`, {
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.detail || `Failed to load logs: ${response.status}`);
                }
                
                this.activityLogs = await response.json();
                
            } catch (error) {
                console.error('Error loading activity logs:', error);
                this.error = 'Failed to load activity logs: ' + error.message;
                this.activityLogs = [];
            } finally {
                this.loading = false;
            }
        },

        //-------------Logging testing function------------------------------
        async testLogging() {
            try {
                const response = await fetch(`${this.apiUrl}/logs/test`, {
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                const data = await response.json();
                console.log('Logging test result:', data);
                
                if (data.status === 'ok') {
                    alert(`✅ Logging system OK!\n\nTable exists: ${data.table_exists}\nLog count: ${data.log_count}\nYou are: ${data.current_user?.name}\nCan view logs: ${data.can_view_logs}`);
                } else {
                    alert(`❌ Error: ${data.error}`);
                }
            } catch (error) {
                console.error('Test failed:', error);
                alert('Test failed: ' + error.message);
            }
        },
//---------------------End of logging testing function--------------------------

        async loadActivityStats() {
            try {
                const params = new URLSearchParams();
                
                if (this.logFilters.startDate) {
                    params.append('start_date', this.logFilters.startDate);
                }
                if (this.logFilters.endDate) {
                    params.append('end_date', this.logFilters.endDate);
                }
                
                const queryString = params.toString();
                const endpoint = queryString ? `/logs/activity/stats?${queryString}` : '/logs/activity/stats';
                
                this.activityStats = await this.apiCall(endpoint);
                this.showStatsModal = true;
            } catch (error) {
                this.error = 'Failed to load activity stats: ' + error.message;
            }
        },

        clearLogFilters() {
            this.logFilters = {
                startDate: '',
                endDate: '',
                action: '',
                targetUserId: '',
                status: ''
            };
            this.loadActivityLogs();
        },

        showLogDetails(log) {
            this.selectedLog = log;
            this.showLogDetailsModal = true;
        },

        async cleanupOldLogs() {
            const days = prompt('Delete logs older than how many days?', '90');
            if (!days) return;
            
            if (!confirm(`Are you sure you want to delete logs older than ${days} days? This cannot be undone.`)) {
                return;
            }
            
            this.loading = true;
            try {
                const response = await this.apiCall(`/logs/activity/cleanup?days=${days}`, {
                    method: 'DELETE'
                });
                
                this.successMessage = `Deleted ${response.deleted_count} old log entries`;
                await this.loadActivityLogs();
                setTimeout(() => this.successMessage = '', 5000);
            } catch (error) {
                this.error = 'Failed to cleanup logs: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        exportActivityLogsCSV() {
            const headers = [
                'Date/Time', 
                'User', 
                'Action', 
                'Resource Type',
                'Resource ID',
                'Status', 
                'IP Address',
                'Error Message',
                'Details'
            ];
            
            const rows = this.activityLogs.map(log => [
                new Date(log.created_at).toLocaleString(),
                log.username,
                log.action,
                log.resource_type || '-',
                log.resource_id || '-',
                log.status,
                log.ip_address || '-',
                log.error_message || '-',
                log.details ? JSON.stringify(JSON.parse(log.details)) : '-'
            ]);
            
            this.downloadCSV(
                headers, 
                rows, 
                `activity_logs_${new Date().toISOString().split('T')[0]}.csv`
            );
        },

        //---------------------End of logging functions------------------------------------
// CSV Export Functions

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
        item.quantity <= item.min_threshold ? 'Low Stock' : 'OK'
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

exportMovementsCSV() {
    const headers = ['Date/Time', 'Type', 'Part Number', 'Quantity', 'From Store', 'To Store', 'Work Order', 'Created By', 'Transfer Status', 'Confirmed By', 'Confirmed At'];
    const rows = this.movements.map(m => [
        new Date(m.created_at).toLocaleString(),
        m.movement_type,
        m.part_number,
        m.quantity,
        m.from_store_name || '-',
        m.to_store_name || '-',
        m.work_order || '-',
        m.created_by_name, m.transfer_status || '', m.completed_by_name || '', m.completed_at || ''
    ]);
    
    this.downloadCSV(headers, rows, `movement_history_${new Date().toISOString().split('T')[0]}.csv`);
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
        item.quantity <= item.min_threshold ? 'Low Stock' : 'OK'
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
    const timestamp = new Date().toLocaleString();
    const date = new Date().toISOString().split('T')[0];
    
    let report = `Inventory Management System - Comprehensive Report\n`;
    report += `Generated: ${timestamp}\n`;
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
        const status = item.quantity <= item.min_threshold ? 'LOW STOCK' : 'OK';
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
    report += `Date/Time,Type,Part,Qty,From,To,Work Order,By,Transfer Status,Confirmed By,Confirmed At\n`;
    this.movements.slice(0, 50).forEach(m => {
        report += `"${new Date(m.created_at).toLocaleString()}",${m.movement_type},${m.part_number},${m.quantity},"${m.from_store_name || '-'}","${m.to_store_name || '-'}","${m.work_order || '-'}","${m.created_by_name}","${m.transfer_status || '-'}","${m.completed_by_name || '-'}","${m.completed_at || '-'}"\n`;
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
        

        // Actions
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

        async transferItem(item) {
            this.transferForm.inventory_id = item.id;
            this.transferForm.quantity = 1;
            this.transferForm.to_store_id = '';
            this.showTransferModal = true;
        },

        consumeItem(item) {
            this.consumeForm = {
                inventory_id: item.id,
                part_number: item.part_number,
                description: item.description,
                store_name: item.store_name,
                available_quantity: item.quantity,
                quantity: 1,
                work_order_number: '',
                notes: ''
            };
            this.showConsumeModal = true;
        },

        async consumeStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                const result = await this.apiCall('/inventory/consume', {
                    method: 'POST',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.consumeForm.inventory_id),
                        quantity: parseInt(this.consumeForm.quantity),
                        work_order_number: this.consumeForm.work_order_number.trim(),
                        notes: this.consumeForm.notes || null
                    })
                });
                
                this.successMessage = result.message;
                this.showConsumeModal = false;
                this.consumeForm = {};
                
                await this.loadInventory();
                await this.loadMovements();
                await this.refreshDashboard();
                
                if (this.selectedStore) {
                    this.storeInventory = this.inventory.filter(item => item.store_id === this.selectedStore.id);
                }
                
                setTimeout(() => this.successMessage = '', 5000);
                
            } catch (error) {
                this.error = 'Failed to consume stock: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async transferStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                const result = await this.apiCall('/inventory/transfer', {
                    method: 'POST',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.transferForm.inventory_id),
                        to_store_id: parseInt(this.transferForm.to_store_id),
                        quantity: parseInt(this.transferForm.quantity)
                    })
                });
                
                this.successMessage = result.message;
                this.showTransferModal = false;
                this.transferForm = { inventory_id: '', to_store_id: '', quantity: '' };
                
                await this.loadInventory();
                await this.loadStats();
                await this.loadPendingTransfers();
                
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to transfer stock: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        // User management
        async createUser() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                await this.apiCall('/users', {
                    method: 'POST',
                    body: JSON.stringify(this.userForm)
                });
                
                this.successMessage = 'User created successfully!';
                this.showUserModal = false;
                this.userForm = { email: '', name: '', password: '', role: '', territory: '' };
                
                await this.loadUsers();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to create user: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        editUser(user) {
            this.editingUser = user.id;
            this.userForm = {
                email: user.email,
                name: user.name,
                password: '',
                role: user.role,
                territory: user.territory || ''
            };
            this.showUserModal = true;
        },

        async updateUser() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                const updateData = {
                    name: this.userForm.name,
                    role: this.userForm.role,
                    territory: this.userForm.territory || null
                };
                
                if (this.userForm.password) {
                    updateData.password = this.userForm.password;
                }
                
                await this.apiCall(`/users/${this.editingUser}`, {
                    method: 'PUT',
                    body: JSON.stringify(updateData)
                });
                
                this.successMessage = 'User updated successfully!';
                this.showUserModal = false;
                this.editingUser = null;
                this.userForm = { email: '', name: '', password: '', role: '', territory: '' };
                
                await this.loadUsers();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to update user: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deleteUser(userId, userName) {
            if (!confirm(`Archive user ${userName}? History will be preserved.`)) {
                return;
            }
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                const result = await this.apiCall(`/users/${userId}`, {
                    method: 'DELETE'
                });
                
                this.successMessage = result.message;
                await this.loadUsers();
                await this.loadInventory();
                if (this.showArchivedPanel) await this.loadArchivedRecords();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to archive user: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        // Equipment Management Functions

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
                calibration_date: new Date().toISOString().split('T')[0],
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
            
            const now = new Date();
            const nextCal = new Date(equipment.next_calibration_date);
            const daysUntil = Math.ceil((nextCal - now) / (1000 * 60 * 60 * 24));
            
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
            const now = new Date();
            return this.equipment.filter(eq => {
                if (!eq.next_calibration_date) return false;
                const nextCal = new Date(eq.next_calibration_date);
                const daysUntil = Math.ceil((nextCal - now) / (1000 * 60 * 60 * 24));
                return daysUntil >= 0 && daysUntil <= this.calibrationReminderDays;
            });
        },

        get overdueEquipment() {
            const now = new Date();
            return this.equipment.filter(eq => {
                if (!eq.next_calibration_date) return false;
                const nextCal = new Date(eq.next_calibration_date);
                return nextCal < now;
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

        // Store management
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

        // Parts management
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

        async toggleMovements() {
            this.showMovementsPanel = !this.showMovementsPanel;
            if (this.showMovementsPanel) {
                await this.loadMovements();
            }
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

        },

        // Bulk import functions
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

        async importStores(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch(`${this.apiUrl}/stores/bulk-import`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    },
                    body: formData
                });
                
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Import failed');
                }
                
                const result = await response.json();
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

        downloadPartTemplate() {
            const csv = 'part_number,description,category,unit_cost\nSAMPLE-001,Sample Part Description,Sample Category,99.99';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'parts_import_template.csv';
            a.click();
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
    }
}

//------------Forgot Password------------------------
        function forgotPassword() {
            return {
                email: '',
                loading: false,
                submitted: false,
                message: { text: '', type: '' },

                async submitRequest() {
                    this.loading = true;
                    this.message = { text: '', type: '' };

                    try {
                        const response = await fetch('/api/forgot-password', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                email: this.email
                            })
                        });

                        const data = await response.json();

                        if (response.ok) {
                            this.submitted = true;
                        } else {
                            this.message = { 
                                text: data.detail || 'An error occurred', 
                                type: 'error' 
                            };
                        }
                    } catch (error) {
                        this.message = { 
                            text: 'Unable to connect to the server', 
                            type: 'error' 
                        };
                    } finally {
                        this.loading = false;
                    }
                }
            }
        }

        //------------Reset Password------------------------
        function resetPassword() {
            return {
                token: '',
                newPassword: '',
                confirmPassword: '',
                loading: false,
                validating: true,
                tokenValid: false,
                success: false,
                message: { text: '', type: '' },
                passwordStrength: '',

                async init() {
                    // Get token from URL
                    const urlParams = new URLSearchParams(window.location.search);
                    this.token = urlParams.get('token');

                    if (!this.token) {
                        this.validating = false;
                        this.message = { text: 'No reset token provided', type: 'error' };
                        return;
                    }

                    // Verify token
                    await this.verifyToken();
                },

                async verifyToken() {
                    try {
                        const response = await fetch(`/api/verify-reset-token/${this.token}`);

                        if (response.ok) {
                            this.tokenValid = true;
                        } else {
                            const data = await response.json();
                            this.message = { 
                                text: data.detail || 'Invalid or expired token', 
                                type: 'error' 
                            };
                        }
                    } catch (error) {
                        this.message = { 
                            text: 'Unable to verify reset token', 
                            type: 'error' 
                        };
                    } finally {
                        this.validating = false;
                    }
                },

                async submitReset() {
                    if (this.newPassword !== this.confirmPassword) {
                        this.message = { text: 'Passwords do not match', type: 'error' };
                        return;
                    }

                    if (this.newPassword.length < 8) {
                        this.message = { 
                            text: 'Password must be at least 8 characters long', 
                            type: 'error' 
                        };
                        return;
                    }

                    this.loading = true;
                    this.message = { text: '', type: '' };

                    try {
                        const response = await fetch('/api/reset-password', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                token: this.token,
                                new_password: this.newPassword
                            })
                        });

                        const data = await response.json();

                        if (response.ok) {
                            this.success = true;
                        } else {
                            this.message = { 
                                text: data.detail || 'Failed to reset password', 
                                type: 'error' 
                            };
                        }
                    } catch (error) {
                        this.message = { 
                            text: 'Unable to connect to the server', 
                            type: 'error' 
                        };
                    } finally {
                        this.loading = false;
                    }
                },

                checkPasswordStrength() {
                    const password = this.newPassword;
                    let strength = 0;

                    if (password.length >= 8) strength++;
                    if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
                    if (password.match(/\d/)) strength++;
                    if (password.match(/[^a-zA-Z\d]/)) strength++;

                    if (strength <= 2) {
                        this.passwordStrength = 'strength-weak';
                    } else if (strength === 3) {
                        this.passwordStrength = 'strength-medium';
                    } else {
                        this.passwordStrength = 'strength-strong';
                    }
                }
            }
        }

    //------------Profile Management------------
        function profileManager() {
    return {
        activeTab: 'profile',
        loading: true,
        saving: false,
        error: '',
        successMessage: '',
        apiUrl: '/api',
        csrfToken: '',
        profile: {
            name: '',
            email: '',
            role: '',
            territory: ''
        },
        passwordForm: {
            current_password: '',
            new_password: '',
            confirm_password: ''
        },
        passwordStrength: '',

        async init() {
            await this.getCsrfToken();
            await this.loadProfile();
        },

        async getCsrfToken() {
            try {
                const response = await fetch(`${this.apiUrl}/csrf-token`, {
                    credentials: 'include'
                });
                const data = await response.json();
                this.csrfToken = data.csrf_token;
            } catch (error) {
                console.error('Failed to get CSRF token:', error);
            }
        },

        async loadProfile() {
            try {
                const response = await fetch('/api/profile', {
                    credentials: 'include'  // Use cookies instead of token
                });

                if (!response.ok) {
                    if (response.status === 401) {
                        // Not authenticated, redirect to login
                        window.location.href = '/static/index.html';
                        return;
                    }
                    throw new Error('Failed to load profile');
                }

                const data = await response.json();
                this.profile = {
                    name: data.name,
                    email: data.email,
                    role: data.role,
                    territory: data.territory || ''
                };
            } catch (error) {
                this.error = 'Failed to load profile: ' + error.message;
                setTimeout(() => {
                    window.location.href = '/static/index.html';
                }, 2000);
            } finally {
                this.loading = false;
            }
        },

        async updateProfile() {
            this.saving = true;
            this.error = '';
            this.successMessage = '';

            try {
                const response = await fetch('/api/profile', {
                    method: 'PUT',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify({
                        email: this.profile.email
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    this.successMessage = 'Profile updated successfully!';
                    setTimeout(() => this.successMessage = '', 5000);
                } else {
                    this.error = data.detail || 'Failed to update profile';
                    setTimeout(() => this.error = '', 5000);
                }
            } catch (error) {
                this.error = 'An error occurred: ' + error.message;
                setTimeout(() => this.error = '', 5000);
            } finally {
                this.saving = false;
            }
        },

        async changePassword() {
            if (this.passwordForm.new_password !== this.passwordForm.confirm_password) {
                this.error = 'Passwords do not match';
                setTimeout(() => this.error = '', 5000);
                return;
            }

            if (this.passwordForm.new_password.length < 8) {
                this.error = 'Password must be at least 8 characters long';
                setTimeout(() => this.error = '', 5000);
                return;
            }

            this.saving = true;
            this.error = '';
            this.successMessage = '';

            try {
                const response = await fetch('/api/profile/change-password', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify({
                        current_password: this.passwordForm.current_password,
                        new_password: this.passwordForm.new_password
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    this.successMessage = data.message + ' Redirecting to login...';
                    this.passwordForm = {
                        current_password: '',
                        new_password: '',
                        confirm_password: ''
                    };
                    this.passwordStrength = '';
                    
                    // Clear any stored user data
                    localStorage.removeItem('currentUser');
                    
                    // Redirect to login after 2 seconds
                    setTimeout(() => {
                        window.location.href = '/static/index.html';
                    }, 2000);
                } else {
                    this.error = data.detail || 'Failed to change password';
                    setTimeout(() => this.error = '', 5000);
                }
            } catch (error) {
                this.error = 'An error occurred: ' + error.message;
                setTimeout(() => this.error = '', 5000);
            } finally {
                this.saving = false;
            }
        },

        checkPasswordStrength() {
            const password = this.passwordForm.new_password;
            let strength = 0;

            if (password.length >= 8) strength++;
            if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
            if (password.match(/\d/)) strength++;
            if (password.match(/[^a-zA-Z\d]/)) strength++;

            if (strength <= 2) {
                this.passwordStrength = 'strength-weak';
            } else if (strength === 3) {
                this.passwordStrength = 'strength-medium';
            } else {
                this.passwordStrength = 'strength-strong';
            }
        }
    }
}
