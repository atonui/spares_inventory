function consumptionReportsFeature() {
    return {
        formatReportInstant(value) { return InventoryTime.formatInstant(value,this.consumptionReport?.timezone); },
        showReportsPanel: false,
        consumptionReport: null,
        reportOptions: {parts:[], stores:[], engineers:[]},
        reportForm: {allDates:false,start_date:'',end_date:'',part_id:'',store_id:'',engineer_id:'',work_order_number:''},
        reportBusy: false,
        reportExportBusy: false,
        reportError: '',
        reportDirty: true,
        reportOffset: 0,
        reportRequest: 0,
        reportAppliedQuery: '',

        markReportDirty() { this.reportDirty=true; },

        reportQuery() {
            if (!this.timezoneContext) throw Error('Load timezone settings before running a report.');
            const f=this.reportForm;
            if(!f.start_date && !f.end_date) {
                f.end_date=this.businessToday();
                f.start_date=InventoryTime.addDays(f.end_date,-29);
            }
            const q=new URLSearchParams();
            if(!f.allDates) {
                if(!/^\d{4}-\d{2}-\d{2}$/.test(f.start_date) || !/^\d{4}-\d{2}-\d{2}$/.test(f.end_date) || f.start_date>f.end_date) throw Error('Choose valid start and end dates, with the end on or after the start.');
                q.set('start_date',f.start_date);q.set('end_date',f.end_date);
            }
            for(const key of ['part_id','store_id','engineer_id','work_order_number']) {
                const value=String(f[key] || '').trim();if(value) q.set(key,value);
            }
            return q;
        },

        async loadConsumptionReport(offset=0) {
            if(this.reportBusy) return;
            this.reportError='';
            let query;
            try { query=this.reportQuery(); }
            catch(error) { this.reportError=error.message;this.reportDirty=true;return; }
            const request=++this.reportRequest, actor=this.currentUser?.id;
            this.reportBusy=true;this.consumptionReport=null;this.reportDirty=true;
            const applied=query.toString();query.set('limit','100');query.set('offset',String(offset));
            try {
                const result=await this.apiCall('/reports/consumption?'+query);
                if(request!==this.reportRequest || actor!==this.currentUser?.id) return;
                if(!result) throw Error('Your session expired. Sign in and refresh the report.');
                this.consumptionReport=result;this.reportOptions=result.filter_options || {parts:[],stores:[],engineers:[]};
                this.reportOffset=result.offset;this.reportAppliedQuery=applied;this.reportDirty=false;
            } catch(error) { if(request===this.reportRequest) this.reportError='Report could not be loaded. Retry: '+error.message; }
            finally { if(request===this.reportRequest) this.reportBusy=false; }
        },

        async openWorkOrderReport(number) {
            if(this.reportBusy) return;
            this.closeAllPanels();this.showInventoryPanel=false;this.showReportsPanel=true;
            this.reportForm.work_order_number=number;this.markReportDirty();
            await this.loadConsumptionReport();
        },

        async exportConsumptionReport() {
            if(this.reportDirty || !this.consumptionReport || this.reportBusy || this.reportExportBusy) return;
            this.reportExportBusy=true;this.reportError='';
            const actor=this.currentUser?.id, request=this.reportRequest;
            try {
                const exportQuery=new URLSearchParams(this.reportAppliedQuery);
                if(Number.isSafeInteger(this.consumptionReport.timezone_revision)) exportQuery.set('expected_timezone_revision',String(this.consumptionReport.timezone_revision));
                const response=await fetch(this.apiUrl+'/reports/consumption.csv?'+exportQuery,{credentials:'include',headers:this.token?{Authorization:'Bearer '+this.token}:{}});
                if(!response.ok) { if(response.status===401) this.logout();throw Error('Download failed ('+response.status+'). Refresh the report and retry.'); }
                const blob=await response.blob();
                if(actor!==this.currentUser?.id || request!==this.reportRequest) return;
                const url=URL.createObjectURL(blob),link=document.createElement('a');
                link.href=url;link.download='consumption_report.csv';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);
            } catch(error) { this.reportError=error.message; }
            finally { this.reportExportBusy=false; }
        },
    };
}

function resetConsumptionReports(app) {
    app.reportRequest++;app.reportBusy=false;app.consumptionReport=null;
    app.reportOptions={parts:[],stores:[],engineers:[]};app.reportAppliedQuery='';app.reportDirty=true;
}
