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
        emailChangeDraft: '',
        pendingEmailChange: null,
        emailChangeBusy: false,
        emailChangeLoading: false,
        emailChangeError: '',
        emailChangeMessage: '',
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
                this.successMessage = 'Invitation queued for delivery. It expires in seven days.';
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
            this.emailChangeDraft = '';
            this.pendingEmailChange = null;
            this.emailChangeError = '';
            this.emailChangeMessage = '';
            this.userForm = {
                email: user.email,
                name: user.name,
                password: '',
                role: user.role,
                territory: user.territory || ''
            };
            this.showUserModal = true;
            if (this.currentUser?.saas_mode && this.canManageEditedEmail) this.loadMemberEmailChange();
        },

        get editedEmailTarget() {
            return this.users.find(user => Number(user.id) === Number(this.editingUser)) || null;
        },

        get canManageEditedEmail() {
            const target = this.editedEmailTarget;
            return Boolean(this.currentUser?.saas_mode && target && target.id !== this.currentUser.id
                && target.role !== 'owner' && (target.role !== 'admin' || this.currentUser.role === 'owner'));
        },

        get editedEmailIsOwner() {
            return Boolean(this.editedEmailTarget?.role === 'owner');
        },

        async loadMemberEmailChange() {
            if (!this.canManageEditedEmail || this.emailChangeLoading) return;
            this.emailChangeLoading = true;
            this.emailChangeError = '';
            try {
                const result = await this.apiCall(`/users/${this.editingUser}/email-change-request`);
                this.pendingEmailChange = result.status === 'pending' ? result : null;
            } catch (error) {
                this.emailChangeError = 'Failed to load pending email change: ' + error.message;
            } finally {
                this.emailChangeLoading = false;
            }
        },

        async requestMemberEmailChange() {
            if (!this.canManageEditedEmail || this.emailChangeBusy || !this.emailChangeDraft.trim()) return;
            this.emailChangeBusy = true;
            this.emailChangeError = '';
            this.emailChangeMessage = '';
            try {
                const result = await this.apiCall(`/users/${this.editingUser}/email-change-requests`, {
                    method: 'POST', body: JSON.stringify({email: this.emailChangeDraft.trim()})
                });
                this.emailChangeDraft = '';
                this.emailChangeMessage = result.message || 'If the address can be used, a confirmation email has been sent.';
                await this.loadMemberEmailChange();
            } catch (error) {
                this.emailChangeError = 'Failed to request email change: ' + error.message;
            } finally {
                this.emailChangeBusy = false;
            }
        },

        async cancelMemberEmailChange() {
            if (!this.canManageEditedEmail || !this.pendingEmailChange || this.emailChangeBusy) return;
            this.emailChangeBusy = true;
            this.emailChangeError = '';
            this.emailChangeMessage = '';
            try {
                const result = await this.apiCall(`/users/${this.editingUser}/email-change-request`, {method: 'DELETE'});
                this.pendingEmailChange = null;
                this.emailChangeMessage = result.message || 'Pending email change canceled.';
            } catch (error) {
                this.emailChangeError = 'Failed to cancel email change: ' + error.message;
            } finally {
                this.emailChangeBusy = false;
            }
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

        async removeUser(userId, userName) {
            if (!confirm(`Remove ${userName} from this company? Their account and company history will remain.`)) {
                return;
            }

            this.loading = true;
            this.error = '';
            this.successMessage = '';

            try {
                const result = await this.apiCall(`/users/${userId}/remove`, {
                    method: 'POST'
                });

                this.successMessage = result.message;
                await this.loadUsers();
                setTimeout(() => this.successMessage = '', 3000);

            } catch (error) {
                this.error = 'Failed to remove company member: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

    };
}
