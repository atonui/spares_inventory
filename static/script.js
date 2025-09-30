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
            email: 'john@company.com',
            password: 'password123'
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
        showAddModal: false,
        showEditModal: false,
        showTransferModal: false,
        showUserModal: false,
        showStoreModal: false,
        showPartModal: false,
        showUsersPanel: false,
        showStoresPanel: false,
        showPartsPanel: false,
        showMovementsPanel: false,
        editingUser: null,
        editingStore: null,
        editingPart: null,
        
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
            localStorage.removeItem('token');
            this.token = null;
            this.currentUser = null;
            this.isAuthenticated = false;
        },

        // Data loading
        async loadAllData() {
            this.loading = true;
            try {
                const promises = [
                    this.loadStats(),
                    this.loadStores(),
                    this.loadParts(),
                    this.loadInventory()
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
            this.inventory = await this.apiCall('/inventory');
            this.filteredInventory = this.inventory;
        },

        async loadUsers() {
            if (this.currentUser?.role === 'admin') {
                this.users = await this.apiCall('/users');
            }
        },

        async loadMovements() {
            this.movements = await this.apiCall('/movements');
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
            if (this.currentUser?.role === 'admin') return this.stores;
            return this.stores.filter(store => 
                store.assigned_user_id === this.currentUser.id || 
                store.type === 'central'
            );
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
                        work_order_number: this.addForm.work_order_number || null
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