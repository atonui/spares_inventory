//------------Forgot Password------------------------
        function forgotPassword() {
            return {
                email: '',
                csrfToken: '',
                loading: false,
                submitted: false,
                message: { text: '', type: '' },

                async submitRequest() {
                    this.loading = true;
                    this.message = { text: '', type: '' };

                    try {
                        const response = await InventoryCsrf.request(this, '/api/forgot-password', {
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
                            text: error.message || 'Unable to connect to the server',
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
                csrfToken: '',
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
                        const response = await InventoryCsrf.request(this, '/api/reset-password', {
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
                            text: error.message || 'Unable to connect to the server',
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
