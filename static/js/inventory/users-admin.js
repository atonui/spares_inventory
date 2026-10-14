function usersAdminFeature() {
    return {
        userForm: {
            email: '',
            name: '',
            password: '',
            role: 'engineer',
            territory: ''
        },

        showUserModal: false,
        editingUser: null,

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

    };
}
