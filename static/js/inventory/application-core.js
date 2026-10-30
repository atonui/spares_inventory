const inventoryAuthRequests = new WeakMap();

function inventoryCoreFeature() {
    return {
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
        authState: 'checking',
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
        inventoryLoadFailed: false,
        inventoryLoadError: '',
        // modals
        // logging
        // selected store for inventory view

        // Movement filters
        // advanced search
        // Data
        stats: {},
        stores: [],
        storeOptions: [],
        parts: [],
        inventory: [],
        workOrders: [],
        users: [],
        storeTypes: [],
        csrfToken: '',

        // Equipment-related state
        // API Base URL
        apiUrl: '/api',

        // Initialize
        async checkAuth() {
            const request = Symbol();
            inventoryAuthRequests.set(this, request);
            this.authState = 'checking';
            this.error = '';
            // The HTTPOnly session cookie is authoritative; user storage is only a cache.
            try {
                const user = await this.getCurrentUser();
                if (inventoryAuthRequests.get(this) !== request) return;
                this.currentUser = user;
                this.isAuthenticated = true;
                this.authState = 'authenticated';
                try { localStorage.setItem('currentUser', JSON.stringify(this.currentUser)); }
                catch (_) { /* Storage availability must not invalidate a session. */ }
            } catch (error) {
                if (inventoryAuthRequests.get(this) !== request) return;
                this.currentUser = null;
                this.isAuthenticated = false;
                this.authState = error.status === 401 ? 'anonymous' : 'error';
                try { localStorage.removeItem('currentUser'); } catch (_) {}
                if (error.status !== 401) this.error = 'Unable to check your session. Retry.';
                return;
            }
            try { await this.getCsrfToken(); }
            catch (error) { this.error = error.message; }
            if (inventoryAuthRequests.get(this) !== request) return;
            try { await this.loadAllData(); }
            catch (error) { this.error = error.message; }
            if (inventoryAuthRequests.get(this) !== request) return;
            if (typeof this.applyNotificationLink === 'function') {
                await this.applyNotificationLink();
            }
        },

        // Authentication
        async login() {
            inventoryAuthRequests.delete(this);
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
                this.authState = 'authenticated';

                // Store user info (but not token)
                try { localStorage.setItem('currentUser', JSON.stringify(data.user)); } catch (_) {}
                if(typeof notifyAnnouncementIdentityChange==='function')notifyAnnouncementIdentityChange();

                await this.loadAllData();

            } catch (error) {
                this.error = error.message;
            } finally {
                this.loading = false;
            }
        },

        async getCurrentUser() {
            const response = await fetch(`${this.apiUrl}/me`, {
                credentials: 'include',
                cache: 'no-store'
            });

            if (!response.ok) {
                const error = new Error('Authentication failed');
                error.status = response.status;
                throw error;
            }

            return response.json();
        },

        async logout({localOnly = false} = {}) {
            inventoryAuthRequests.delete(this);
            try {
                if (!localOnly) await this.apiCall('/auth/logout', { method: 'POST' });
            } catch (error) {
                console.error('Logout error:', error);
                this.error = 'Logout failed. You are still signed in. Please retry: ' + error.message;
                return;
            }

            this.timezoneContext=null;this.timezoneError='';this.movementTimeContext=null;this.activityTimeContext=null;
            resetConsumptionReports(this);
            // Clear local state
            this.currentUser = null;
            this.isAuthenticated = false;
            this.authState = 'anonymous';
            try { localStorage.removeItem('currentUser'); } catch (_) {}
            if(typeof notifyAnnouncementIdentityChange==='function')notifyAnnouncementIdentityChange();

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

                if (['owner','admin','superadmin'].includes(this.currentUser?.role)) {
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
            const [stores, options] = await Promise.all([
                this.apiCall('/stores'),
                this.apiCall('/store-options'),
            ]);
            this.stores = stores;
            this.storeOptions = options;
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
            if (['owner','admin','superadmin'].includes(this.currentUser?.role)) {
                this.users = await this.apiCall('/users');
                if (this.currentUser?.saas_mode && typeof this.loadInvitations === 'function') {
                    await this.loadInvitations();
                }
            }
        },

        // Filtering - FIXED SEARCH FUNCTION
        // advanced search filter
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

        // Bulk import functions
    };
}
