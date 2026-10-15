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
        invitations: [],
        invitationsLoading: false,

        async loadInvitations() {
            if (!this.currentUser?.saas_mode) return;
            this.invitationsLoading = true;
            try {
                this.invitations = await this.apiCall('/users/invitations');
            } catch (error) {
                this.error = 'Failed to load invitations: ' + error.message;
            } finally {
                this.invitationsLoading = false;
            }
        },

        async inviteUser() {
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            try {
                await this.apiCall('/users/invitations', {
                    method: 'POST',
                    body: JSON.stringify({ email: this.userForm.email, role: this.userForm.role })
                });
                this.successMessage = 'Invitation sent. It expires in seven days.';
                this.showUserModal = false;
                this.userForm = { email: '', name: '', password: '', role: 'engineer', territory: '' };
                await this.loadInvitations();
                setTimeout(() => this.successMessage = '', 3000);
            } catch (error) {
                this.error = 'Failed to invite user: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async cancelInvitation(invitationId) {
            this.loading = true;
            this.error = '';
            try {
                await this.apiCall('/users/invitations/' + invitationId, { method: 'DELETE' });
                await this.loadInvitations();
            } catch (error) {
                this.error = 'Failed to cancel invitation: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async resendInvitation(invitationId) {
            this.loading = true;
            this.error = '';
            try {
                await this.apiCall('/users/invitations/' + invitationId + '/resend', { method: 'POST' });
                this.successMessage = 'A fresh invitation link was sent.';
                await this.loadInvitations();
                setTimeout(() => this.successMessage = '', 3000);
            } catch (error) {
                this.error = 'Failed to resend invitation: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

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
