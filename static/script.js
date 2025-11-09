// script.js - Inventory Management Application
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
            password: ''
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
        // modals
        showAddModal: false,
        showEditModal: false,
        showTransferModal: false,
        showUserModal: false,
        showStoreModal: false,
        showPartModal: false,
        showProfileModal: false,
        
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
        workOrders: [],
        users: [],
        movements: [],
        filteredInventory: [],
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
            const defaultHeaders = {
                'Content-Type': 'application/json'
            };

            // CSRF token for state-changing operations
            if (options.method && ['POST', 'PUT', 'DELETE'].includes(options.method.toUpperCase())) {
                if (this.csrfToken) {
                    defaultHeaders['X-CSRF-Token'] = this.csrfToken;
                }
            }
            
            const config = {
                ...options,
                credentials: 'include', // IMPORTANT: Include cookies in all requests
                headers: {
                    ...defaultHeaders,
                    ...options.headers
                }
            };
            
            try {
                const response = await fetch(`${this.apiUrl}${endpoint}`, config);
                
                // Handle 401/403 - session expired or unauthorized
                if (response.status === 401 || response.status === 403) {
                    // If CSRF token expired, try to refresh it
                    if (response.status === 403) {
                        await this.getCsrfToken();
                    } else {
                        this.logout();
                        this.error = "Session expired. Please login again.";
                    }
                    return null;
                }
                
                // Handle 422 - Validation error
                if (response.status === 422) {
                    const errorData = await response.json().catch(() => ({}));
                    console.error('Validation error:', errorData);
                    throw new Error(errorData.detail || 'Validation error');
                }
                
                // Handle 429 - Rate limit exceeded
                if (response.status === 429) {
                    throw new Error('Too many requests. Please try again later.');
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
                console.error('API call error:', error);
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
                    this.loadEquipment(),
                    this.loadEquipmentStats(),
                    this.loadCalibrationSettings()
                ];
                
                if (this.currentUser?.role === 'admin') {
                    promises.push(this.loadUsers());
                }
                
                await Promise.all(promises);
            } catch (error) {
                this.error = 'Failed to load data: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        // async apiCall(endpoint, options = {}) {
        //     const response = await fetch(`${this.apiUrl}${endpoint}`, {
        //         headers: {
        //             'Authorization': `Bearer ${this.token}`,
        //             'Content-Type': 'application/json',
        //             ...options.headers
        //         },
        //         ...options
        //     });
            
        //     if (!response.ok) {
        //         const errorData = await response.json().catch(() => ({}));
        //         throw new Error(errorData.detail || `API error: ${response.status}`);
        //     }
            
        //     return response.json();
        // },

        async loadStats() {
            this.stats = await this.apiCall('/stats');
        },

        async loadStores() {
            this.stores = await this.apiCall('/stores');
        },

        async loadParts() {
            this.parts = await this.apiCall('/parts');
        },

        async loadInventory() {
            this.loading = true;
            try {
                const response = await this.apiCall('/inventory');
                this.inventory = response;
                this.filterInventory(); // <-- Make sure this is called!
            } catch (error) {
                this.error = 'Failed to load inventory: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async loadUsers() {
            if (this.currentUser?.role === 'admin') {
                this.users = await this.apiCall('/users');
            }
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
        filterInventory() {
            let filtered = this.inventory;
            
            if (this.searchTerm) {
                const term = this.searchTerm.toLowerCase();
                filtered = filtered.filter(item => 
                    item.part_number.toLowerCase().includes(term) ||
                    item.description.toLowerCase().includes(term) ||
                    item.store_name.toLowerCase().includes(term)
                );
                // When searching, close other panels and show inventory
                    if (term.length > 0) {
                        this.closeAllOtherPanels();
                        this.showInventoryPanel = true;
                    }
            }
            
            if (this.storeFilter) {
                const storeId = parseInt(this.storeFilter);
                const storeName = this.stores.find(s => s.id === storeId)?.name;
                filtered = filtered.filter(item => item.store_name === storeName);
            }
            
            this.filteredInventory = filtered;
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
            if (this.currentUser.role === 'admin') return true;
            return storeOwner === this.currentUser.id || storeType === 'central';
        },

        get editableStores() {
            if (!this.currentUser) return [];
            if (this.currentUser?.role === 'admin') return this.stores;
            return this.stores.filter(store => 
                store.assigned_user_id === this.currentUser.id || 
                store.type === 'central'
            );
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

        async viewStoreInventory(store) {
            this.selectedStore = store;
            this.storeInventory = this.inventory.filter(item => item.store_name === store.name);
            this.openPanel('showStoreInventoryPanel');
        },
        async addStockToStore(store) {
            // Pre-fill the add form with the store
            this.addForm.store_id = store.id;
            this.addForm.part_id = '';
            this.addForm.quantity = '';
            this.addForm.work_order_number = '';
            this.showAddModal = true;
        },

        async importPartsToStore(event, storeId) {
            const file = event.target.files[0];
            if (!file) return;
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                // Read CSV file
                const text = await file.text();
                const lines = text.split('\n').filter(line => line.trim());
                
                // Skip header line
                const dataLines = lines.slice(1);
                
                let addedCount = 0;
                let skippedCount = 0;
                let errors = [];
                
                for (const line of dataLines) {
                    const [partNumber, quantity] = line.split(',').map(s => s.trim());
                    
                    if (!partNumber || !quantity) {
                        skippedCount++;
                        continue;
                    }
                    
                    // Find part by part number
                    const part = this.parts.find(p => p.part_number === partNumber);
                    if (!part) {
                        errors.push(`Part ${partNumber} not found`);
                        skippedCount++;
                        continue;
                    }
                    
                    try {
                        await this.apiCall('/inventory/add', {
                            method: 'POST',
                            body: JSON.stringify({
                                part_id: part.id,
                                store_id: storeId,
                                quantity: parseInt(quantity)
                            })
                        });
                        addedCount++;
                    } catch (error) {
                        errors.push(`Failed to add ${partNumber}: ${error.message}`);
                        skippedCount++;
                    }
                }
                
                this.successMessage = `Import complete! Added: ${addedCount}, Skipped: ${skippedCount}`;
                
                if (errors.length > 0) {
                    console.error('Import errors:', errors);
                    this.error = `Some errors occurred. Check console for details.`;
                }
                
                await this.loadInventory();
                if (this.selectedStore) {
                    this.storeInventory = this.inventory.filter(item => item.store_name === this.selectedStore.name);
                }
                
                event.target.value = ''; // Reset file input
                
                setTimeout(() => {
                    this.successMessage = '';
                    this.error = '';
                }, 5000);
                
            } catch (error) {
                this.error = 'Failed to import: ' + error.message;
            } finally {
                this.loading = false;
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
        const storeItems = this.inventory.filter(i => i.store_name === store.name);
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
    const headers = ['Date/Time', 'Type', 'Part Number', 'Quantity', 'From Store', 'To Store', 'Work Order', 'Created By'];
    const rows = this.movements.map(m => [
        new Date(m.created_at).toLocaleString(),
        m.movement_type,
        m.part_number,
        m.quantity,
        m.from_store_name || '-',
        m.to_store_name || '-',
        m.work_order || '-',
        m.created_by_name
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

exportStoreInventoryCSV(storeName) {
    const headers = ['Part Number', 'Description', 'Quantity', 'Min Threshold', 'Work Order', 'Status'];
    const rows = this.storeInventory.map(item => [
        item.part_number,
        item.description,
        item.quantity,
        item.min_threshold,
        item.work_order || 'Original',
        item.quantity <= item.min_threshold ? 'Low Stock' : 'OK'
    ]);
    
    const safeStoreName = storeName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
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

// Bonus: Export all data as a single comprehensive report
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
    report += `Total Parts Quantity: ${this.inventory.reduce((sum, i) => sum + i.quantity, 0)}\n\n`;
    
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
        const storeItems = this.inventory.filter(i => i.store_name === store.name);
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
    report += `Date/Time,Type,Part,Qty,From,To,Work Order,By\n`;
    this.movements.slice(0, 50).forEach(m => {
        report += `"${new Date(m.created_at).toLocaleString()}",${m.movement_type},${m.part_number},${m.quantity},"${m.from_store_name || '-'}","${m.to_store_name || '-'}","${m.work_order || '-'}","${m.created_by_name}"\n`;
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
                        part_id: parseInt(this.addForm.part_id),
                        store_id: parseInt(this.addForm.store_id),
                        quantity: parseInt(this.addForm.quantity),
                        // work_order_number: this.addForm.work_order_number || null
                    })
                });
                
                this.successMessage = 'Stock added successfully!';
                this.showAddModal = false;
                this.addForm = { part_id: '', store_id: '', quantity: '', work_order_number: '' };
                
                await this.loadAllData();
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
                
                await this.loadAllData();
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

        async transferStock() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                await this.apiCall('/inventory/transfer', {
                    method: 'POST',
                    body: JSON.stringify({
                        inventory_id: parseInt(this.transferForm.inventory_id),
                        to_store_id: parseInt(this.transferForm.to_store_id),
                        quantity: parseInt(this.transferForm.quantity)
                    })
                });
                
                this.successMessage = 'Stock transferred successfully!';
                this.showTransferModal = false;
                this.transferForm = { inventory_id: '', to_store_id: '', quantity: '' };
                
                await this.loadAllData();
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
            if (!confirm(`Are you sure you want to delete user ${userName}?`)) {
                return;
            }
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                await this.apiCall(`/users/${userId}`, {
                    method: 'DELETE'
                });
                
                this.successMessage = 'User deleted successfully!';
                await this.loadUsers();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to delete user: ' + error.message;
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
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to update store: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deleteStore(storeId, storeName) {
            if (!confirm(`Are you sure you want to delete store ${storeName}?`)) {
                return;
            }
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                await this.apiCall(`/stores/${storeId}`, {
                    method: 'DELETE'
                });
                
                this.successMessage = 'Store deleted successfully!';
                await this.loadStores();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to delete store: ' + error.message;
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
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to update part: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async deletePart(partId, partNumber) {
            if (!confirm(`Are you sure you want to delete part ${partNumber}?`)) {
                return;
            }
            
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            
            try {
                await this.apiCall(`/parts/${partId}`, {
                    method: 'DELETE'
                });
                
                this.successMessage = 'Part deleted successfully!';
                await this.loadParts();
                setTimeout(() => this.successMessage = '', 3000);
                
            } catch (error) {
                this.error = 'Failed to delete part: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        // Helper functions
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
            // Don't close inventory panel
        },

        closeAllPanels() {
            this.showUsersPanel = false;
            this.showStoresPanel = false;
            this.showPartsPanel = false;
            this.showMovementsPanel = false;
            this.showAllPartsPanel = false;
            this.showAllStoresPanel = false;
            this.showLowStockPanel = false;
            this.showMyPartsPanel = false;
            this.showStoreInventoryPanel = false;
            this.showInventoryPanel = true;
            this.showLogsPanel = false;
            this.showEquipmentPanel = false;
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

            // Reset filters for inventory panel
            if (panelName === 'showInventoryPanel') {
                this.searchTerm = '';
                this.storeFilter = '';
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
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch(`${this.apiUrl}/parts/bulk-import`, {
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
                
                await this.loadParts();
                event.target.value = ''; // Reset file input
                setTimeout(() => {
                    this.successMessage = '';
                    this.error = '';
                }, 5000);
                
            } catch (error) {
                this.error = 'Failed to import parts: ' + error.message;
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
                token: localStorage.getItem('token'),
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
                    if (!this.token) {
                        window.location.href = '/static/index.html';
                        return;
                    }
                    await this.loadProfile();
                },

                async loadProfile() {
                    try {
                        const response = await fetch('/api/profile', {
                            headers: {
                                'Authorization': `Bearer ${this.token}`
                            }
                        });

                        if (!response.ok) {
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
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${this.token}`
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
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${this.token}`
                            },
                            body: JSON.stringify({
                                current_password: this.passwordForm.current_password,
                                new_password: this.passwordForm.new_password
                            })
                        });

                        const data = await response.json();

                        if (response.ok) {
                            this.successMessage = data.message;
                            this.passwordForm = {
                                current_password: '',
                                new_password: '',
                                confirm_password: ''
                            };
                            this.passwordStrength = '';
                            
                            // Redirect to login after 3 seconds
                            setTimeout(() => {
                                localStorage.removeItem('token');
                                window.location.href = '/static/index.html';
                            }, 3000);
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