function stockImportsFeature() {
    return {
        // part import modal properties
        showDuplicateResolutionModal: false,
        csvDuplicates: [],
        storeConflicts: [],
        pendingImportData: null,

        getImportPreview() {
            if (!this.pendingImportData) return [];
            const groups = new Map();
            for (const row of this.pendingImportData.parsedRows) {
                if (!groups.has(row.partNumber)) groups.set(row.partNumber, []);
                groups.get(row.partNumber).push(row.quantity);
            }
            return [...groups].map(([partNumber, quantities]) => {
                const duplicate = this.csvDuplicates.find(d => d.partNumber === partNumber);
                const conflict = this.storeConflicts.find(c => c.partNumber === partNumber);
                const unresolved = duplicate && !duplicate.action;
                const quantity = duplicate?.action === 'tally' ? quantities.reduce((a,b)=>a+b,0) : quantities[0];
                const action = unresolved ? 'resolve' : duplicate?.action === 'skip' || conflict?.action === 'skip' ? 'skip' : conflict ? 'replace' : 'create';
                return {partNumber, quantity, action, currentQuantity: conflict ? conflict.currentQuantity : null};
            });
        },

        getResolutionSummary() {
            const rows = this.getImportPreview();
            return {willAdd: rows.filter(r=>r.action==='create').length,
                    willUpdate: rows.filter(r=>r.action==='replace').length,
                    willSkip: rows.filter(r=>r.action==='skip').length};
        },

        setAllCsvDuplicates(action) {
            this.csvDuplicates.forEach(dup => dup.action = action);
        },

        setAllStoreConflicts(action) {
            this.storeConflicts.forEach(conflict => conflict.action = action);
        },

        setAllActions(action) {
            this.setAllCsvDuplicates(action);
            this.setAllStoreConflicts(action);
        },

        cancelDuplicateResolution() {
            this.showDuplicateResolutionModal = false;
            this.csvDuplicates = [];
            this.storeConflicts = [];
            this.pendingImportData = null;
        },

        async processDuplicateResolution() {
            if (this.loading) return;
            this.loading = true;
            this.error = '';
            try {
                if (!this.pendingImportData) throw new Error('No pending import');
                const preview = this.getImportPreview();
                if (preview.some(r=>r.action==='resolve')) throw new Error('Choose how to handle each duplicate CSV part');
                if (preview.some(r=>!Number.isSafeInteger(r.quantity))) throw new Error('Combined quantity is too large');
                const rows = preview.filter(r=>r.action!=='skip').map(r=>({
                    part_number:r.partNumber, quantity:r.quantity, expected_quantity:r.currentQuantity
                }));
                if (!rows.length) throw new Error('No rows selected for import');
                const result = await this.apiCall('/inventory/import-balances', {
                    method:'POST', body:JSON.stringify({store_id:this.pendingImportData.storeId,rows})
                });
                this.successMessage = `Import saved: ${result.added} created, ${result.updated} updated, ${result.unchanged} unchanged.`;
                this.cancelDuplicateResolution();
                await this.loadInventory();
                if (this.selectedStore) this.storeInventory = this.inventory.filter(i=>i.store_id===this.selectedStore.id);
                await this.loadStats();
            } catch (error) {
                this.error = 'Import not saved: ' + error.message;
            } finally {
                this.loading = false;
            }
        },

        async importPartsToStore(event, storeId) {
            const file = event.target.files[0];
            if (!file || this.loading) return;
            this.loading = true;
            this.error = '';
            this.successMessage = '';
            this.cancelDuplicateResolution();
            try {
                const text = (await file.text()).replace(/^\uFEFF/, '');
                const lines = text.split(/\r?\n/).filter(line=>line.trim());
                const parseLine = (line, number) => {
                    const match = line.match(/^\s*("(?:[^\"]|\"\")*"|[^",]*),\s*("(?:[^\"]|\"\")*"|[^",]*)\s*$/);
                    if (!match) throw new Error(`Row ${number}: expected exactly two CSV columns`);
                    return match.slice(1).map(value=> {
                        value=value.trim();
                        return value.startsWith('"') ? value.slice(1,-1).replace(/""/g,'"').trim() : value;
                    });
                };
                if (lines.length < 2) throw new Error('CSV has no stock rows');
                const header = parseLine(lines[0],1);
                if (header[0] !== 'part_number' || header[1] !== 'quantity') throw new Error('Use the part_number,quantity template headers');
                if (lines.length > 1001) throw new Error('Maximum 1,000 stock rows per import');
                const parsedRows = lines.slice(1).map((line,index)=> {
                    const [partNumber,quantityText] = parseLine(line,index+2);
                    const quantity = Number(quantityText);
                    if (!partNumber || !/^\d+$/.test(quantityText) || !Number.isSafeInteger(quantity)) {
                        throw new Error(`Row ${index+2}: enter a part number and a whole quantity of zero or more`);
                    }
                    return {partNumber,quantity};
                });
                await this.loadParts();
                this.inventory = await this.apiCall('/inventory');
                for (const row of parsedRows) {
                    if (!this.parts.some(p=>p.part_number===row.partNumber)) throw new Error(`Part ${row.partNumber} not found in catalog`);
                }
                const groups = new Map();
                for (const row of parsedRows) {
                    if (!groups.has(row.partNumber)) groups.set(row.partNumber,[]);
                    groups.get(row.partNumber).push(row);
                }
                this.csvDuplicates = [...groups].filter(([,rows])=>rows.length>1).map(([partNumber,rows])=>({
                    partNumber,rows,count:rows.length,quantities:rows.map(r=>r.quantity),
                    totalQuantity:rows.reduce((sum,r)=>sum+r.quantity,0),action:''
                }));
                this.storeConflicts = [];
                for (const [partNumber,rows] of groups) {
                    const stock = this.inventory.filter(i=>i.part_number===partNumber &&
                        i.store_id===storeId && !i.work_order);
                    if (stock.length > 1) throw new Error(`Duplicate stock for ${partNumber}; reconcile it before importing`);
                    if (stock.length) this.storeConflicts.push({
                        partNumber,currentQuantity:stock[0].quantity,action:'replace'
                    });
                }
                this.pendingImportData = {parsedRows,storeId};
                this.showDuplicateResolutionModal = true;
            } catch (error) {
                this.cancelDuplicateResolution();
                this.error = 'Import not saved: ' + error.message;
            } finally {
                this.loading = false;
                event.target.value = '';
            }
        },

        downloadStoreImportTemplate() {
            const csv = 'part_number,quantity\nPART-001,10\nPART-002,5';
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'store_parts_import_template.csv';
            a.click();
            URL.revokeObjectURL(url);
        },

    };
}
