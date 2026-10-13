function replenishmentFeature() {
    return {
        showLowStockPanel: false,
        replenishmentPlan: null,
        replenishmentBusy: false,
        replenishmentError: '',
        replenishmentStoreFilter: '',
        minimumBusy: false,
        minimumForm: {store_id:'', part_id:'', min_threshold:0, expected_minimum:0},

        get replenishmentRows() {
            return (this.replenishmentPlan?.rows || []).filter(r=>!this.replenishmentStoreFilter || r.store_id===Number(this.replenishmentStoreFilter));
        },

        async loadReplenishment() {
            this.replenishmentBusy=true;
            this.replenishmentError='';
            this.replenishmentPlan=null;
            try {
                this.replenishmentPlan=await this.apiCall('/inventory/replenishment');
                return true;
            } catch(error) {
                this.replenishmentError='Could not refresh replenishment. Retry: '+error.message;
                return false;
            } finally { this.replenishmentBusy=false; }
        },

        selectMinimum() {
            const f=this.minimumForm;
            const item=this.inventory.find(i=>i.store_id===Number(f.store_id) && i.part_id===Number(f.part_id) && i.is_allocated===false);
            f.min_threshold=item?.min_threshold || 0;
            f.expected_minimum=f.min_threshold;
        },

        async saveMinimum() {
            if(this.minimumBusy) return;
            const f=this.minimumForm;
            const values=[Number(f.store_id),Number(f.part_id),Number(f.min_threshold),Number(f.expected_minimum)];
            if(!f.store_id || !f.part_id || f.min_threshold==='' || !values.every(Number.isSafeInteger) || values[2]<0 || values[2]>2147483647) {
                this.replenishmentError='Choose a store and part, then enter a whole minimum of zero or more.';
                return;
            }
            this.minimumBusy=true; this.replenishmentError='';
            let saved=false;
            try {
                await this.apiCall('/inventory/minimum',{method:'PUT',body:JSON.stringify({store_id:values[0],part_id:values[1],min_threshold:values[2],expected_minimum:values[3]})});
                saved=true;
                f.expected_minimum=values[2];
                this.successMessage='Minimum stock saved. Recorded stock quantities have not changed.';
                await this.loadInventory({refreshReplenishment:false});
                await this.loadReplenishment();
                await this.loadStats();
            } catch(error) { this.replenishmentError=(saved?'Minimum saved, but refresh failed. Retry: ':'Minimum was not saved. Reload the current minimum and retry: ')+error.message; }
            finally { this.minimumBusy=false; }
        },

        async reloadMinimum() {
            await this.loadInventory();
            if(!this.inventoryLoadFailed) this.selectMinimum();
        },

        async reviewReplenishmentTransfer(row,suggestion) {
            if(this.replenishmentBusy || this.loading || !suggestion.can_dispatch) return;
            await this.loadInventory({refreshReplenishment:false});
            if(this.inventoryLoadFailed || !await this.loadReplenishment()) return;
            const current=this.replenishmentPlan.rows.find(r=>r.store_id===row.store_id && r.part_id===row.part_id);
            const fresh=current?.suggestions.find(s=>s.inventory_id===suggestion.inventory_id);
            if(!fresh?.can_dispatch || fresh.quantity!==suggestion.quantity) {
                this.replenishmentError='The suggestion changed. Review the refreshed plan before dispatching.';
                return;
            }
            const source=this.inventory.find(i=>i.id===fresh.inventory_id);
            if(!source) { this.replenishmentError='Source stock changed. Refresh the plan and review again.'; return; }
            await this.transferItem(source);
            this.transferForm.to_store_id=row.store_id;
            this.transferForm.quantity=fresh.quantity;
            this.transferForm.max_quantity=fresh.quantity;
            this.transferForm.replenishment=true;
        },

        async exportProcurementCSV() {
            if(this.replenishmentBusy || !await this.loadReplenishment()) return;
            const rows=this.replenishmentRows.filter(r=>r.purchase_quantity>0).map(r=>[r.store_name,r.part_number,r.description,r.quantity,r.min_threshold,r.incoming_quantity,r.internal_quantity,r.purchase_quantity]);
            if(!rows.length) { this.successMessage='No purchases remain in this plan if the suggested transfers proceed.'; return; }
            this.downloadCSV(['Store','Part number','Description','Available','Minimum','Incoming (awaiting receipt)','Suggested internal transfer','Purchase if suggested transfers proceed'],rows,`procurement_${new Date().toISOString().split('T')[0]}.csv`);
        },
    };
}
