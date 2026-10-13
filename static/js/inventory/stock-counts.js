function stockCountsFeature() {
    return {
        stockCount: null,
        stockCountPreview: null,
        stockCountBusy: false,
        stockCountTrigger: null,
        async startStockCount(store, trigger = null) {
            if (!store || this.stockCountBusy) return;
            this.stockCountBusy = true;
            this.error = '';
            try {
                const sheet = await this.apiCall(`/inventory/count-sheet/${store.id}`);
                this.stockCount = {...sheet, rows:sheet.rows.map(row=>({...row,counted_quantity:'',reason:''}))};
                this.stockCountPreview = null;
                if (trigger) this.stockCountTrigger = trigger;
            } catch (error) {
                this.error = 'Count could not start: ' + error.message;
            } finally { this.stockCountBusy = false; this.focusStockCountDialog(); }
        },

        async previewStockCount() {
            if (!this.stockCount || this.stockCountBusy) return;
            this.stockCountBusy = true;
            this.error = '';
            this.stockCountPreview = null;
            try {
                const rows = this.stockCount.rows.filter(row=>String(row.counted_quantity).trim()!=='').map(row=>{
                    const quantity = Number(row.counted_quantity);
                    if (!Number.isSafeInteger(quantity) || quantity<0 || quantity>2147483647)
                        throw new Error('Enter whole physical counts from 0 to 2,147,483,647');
                    const reason = row.reason.trim();
                    if (quantity!==row.quantity && !reason) throw new Error('Enter a reason for every correction');
                    return {inventory_id:row.inventory_id,counted_quantity:quantity,reason};
                });
                if (!rows.length) throw new Error('Enter at least one physical count');
                this.stockCountPreview = await this.apiCall('/inventory/count-preview',{
                    method:'POST',body:JSON.stringify({sheet_token:this.stockCount.sheet_token,rows})
                });
            } catch (error) { this.error = 'Count preview failed: ' + error.message; }
            finally { this.stockCountBusy = false; this.focusStockCountDialog(); }
        },

        editStockCount() {
            if (this.stockCountBusy) return;
            this.stockCountPreview = null;
            this.focusStockCountDialog();
        },

        focusStockCountDialog() {
            if (this.stockCount && this.$nextTick)
                this.$nextTick(()=>this.$refs.stockCountDialog?.focus());
        },

        restoreStockCountFocus() {
            const trigger = this.stockCountTrigger;
            this.stockCountTrigger = null;
            if (this.$nextTick) this.$nextTick(()=>trigger?.focus());
            else trigger?.focus();
        },

        async restartStockCount() {
            if (!this.stockCount || this.stockCountBusy) return;
            if (!confirm('Discard these entered counts and load fresh balances? You will need to recount the stock.')) return;
            await this.startStockCount({id:this.stockCount.store_id});
        },

        cancelStockCount() {
            if (this.stockCountBusy) return;
            this.stockCount = null;
            this.stockCountPreview = null;
            this.restoreStockCountFocus();
        },

        trapStockCountFocus(event, dialog) {
            const controls = [...dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), [tabindex="0"]')].filter(el=>el.offsetParent!==null);
            if (!controls.length) { event.preventDefault(); dialog.focus(); return; }
            const first = controls[0], last = controls[controls.length-1];
            const active = dialog.ownerDocument.activeElement;
            if (event.shiftKey && (active===first || !controls.includes(active))) {
                event.preventDefault(); last.focus();
            } else if (!event.shiftKey && (active===last || !controls.includes(active))) {
                event.preventDefault(); first.focus();
            }
        },

        async confirmStockCount() {
            if (!this.stockCountPreview || this.stockCountBusy) return;
            if (!confirm('Confirm these physical counts and save the listed corrections? Blank entries will stay unchanged.')) return;
            this.stockCountBusy = true;
            this.error = '';
            let saved = false;
            try {
                const result = await this.apiCall('/inventory/count-confirm',{
                    method:'POST',body:JSON.stringify({preview_token:this.stockCountPreview.preview_token,confirmed:true})
                });
                saved = true;
                this.stockCount = null;
                this.stockCountPreview = null;
                this.successMessage = `Stock count saved: ${result.changed} corrected, ${result.unchanged} unchanged.`;
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory=this.inventory.filter(row=>row.store_id===this.selectedStore.id);
                await this.loadStats();
            } catch (error) { this.error = saved ? 'Stock count saved, but refresh failed. Reload the page: ' + error.message : 'Count not saved: ' + error.message; }
            finally {
                this.stockCountBusy = false;
                if (saved) this.restoreStockCountFocus();
                else this.focusStockCountDialog();
            }
        },
    };
}
