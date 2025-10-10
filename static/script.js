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
        // modala
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
        showInventoryPanel: false,
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
        
        // Data
        stats: {},
        stores: [],
        parts: [],
        inventory: [],
        workOrders: [],
        users: [],
        movements: [],
        filteredInventory: [],

        // API Base URL
        apiUrl: '/api',

        // Initialize
        async checkAuth() {
            this.token = localStorage.getItem('token');
            if (this.token) {
                try {
                    await this.getCurrentUser();
                    this.isAuthenticated = true;
                    await this.loadAllData();
                } catch (error) {
                    localStorage.removeItem('token');
                    this.token = null;
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
                    body: JSON.stringify(this.loginForm)
                });
                
                if (!response.ok) {
                    throw new Error('Invalid credentials');
                }
                
                const data = await response.json();
                this.token = data.access_token;
                this.currentUser = data.user;
                localStorage.setItem('token', this.token);
                this.isAuthenticated = true;
                
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

        logout() {
            this.token = null;
            this.currentUser = null;
            this.isAuthenticated = false;
            localStorage.removeItem('token');
            localStorage.removeItem('currentUser');
            // Optionally, redirect to login or home
        },

        async apiCall(url, options = {}) {
            if (!options.headers) options.headers = {};
            if (this.token) {
                options.headers['Authorization'] = 'Bearer ' + this.token;
            }
            try {
                const response = await fetch(this.apiUrl + url, options);
                if (response.status === 401 || response.status === 403) {
                    // Session invalid or expired
                    this.logout();
                    this.error = "You have been logged out because your account was accessed from another device or your session expired.";
                    return null;
                }
                if (!response.ok) {
                    throw new Error(await response.text());
                }
                return await response.json();
            } catch (err) {
                this.error = err.message;
                return null;
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
                    this.loadMovements()
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

        async apiCall(endpoint, options = {}) {
            const response = await fetch(`${this.apiUrl}${endpoint}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `API error: ${response.status}`);
            }
            
            return response.json();
        },

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
            }
            
            if (this.storeFilter) {
                const storeId = parseInt(this.storeFilter);
                const storeName = this.stores.find(s => s.id === storeId)?.name;
                filtered = filtered.filter(item => item.store_name === storeName);
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
            
            const csvContent = [headers, ...rows].map(row => 
                row.map(cell => `"${cell}"`).join(',')
            ).join('\n');
            
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `movement_history_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
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
                this.userForm = { email: '', name: '', password: '', role: 'engineer', territory: '' };
                
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
                this.userForm = { email: '', name: '', password: '', role: 'engineer', territory: '' };
                
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
            this.showInventoryPanel = false;
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

    //------------Profile Management (NEW)------------
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