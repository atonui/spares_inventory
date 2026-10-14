function activityLogsFeature() {
    return {
        activityTimeContext: null,
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
        formatAuditDetails(details) { return formatStockAuditDetails(details); },

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

                this.activityLogs = await this.apiCall(endpoint,{},context=>this.activityTimeContext=context);

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

            if (!confirm(`Delete general logs older than ${days} days? Stock audit evidence is retained. This cannot be undone.`)) {
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
                `Date/Time (${this.activityTimeContext?.timezone || 'Unknown'})`,
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
                this.formatBusinessInstant(log.created_at,this.activityTimeContext),
                log.username,
                log.action,
                log.resource_type || '-',
                log.resource_id || '-',
                log.status,
                log.ip_address || '-',
                log.error_message || '-',
                this.formatAuditDetails(log.details)
            ]);

            this.downloadCSV(
                headers,
                rows,
                `activity_logs_${new Date().toISOString().split('T')[0]}.csv`
            );
        },

        //---------------------End of logging functions------------------------------------
    };
}
