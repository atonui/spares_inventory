function archivedRecordsFeature() {
    return {
        archivedRecords: [],
        showArchivedPanel: false,
        async loadArchivedRecords() {
            this.error='';
            try {
                const kinds=['parts','stores','users'];
                const groups=await Promise.all(kinds.map(kind=>this.apiCall('/'+kind+'?include_archived=true')));
                this.archivedRecords=groups.flatMap((rows,index)=>rows.filter(row=>row.archived_at).map(row=>({
                    kind:kinds[index],id:row.id,label:row.part_number || row.name,archived_at:row.archived_at
                })));
            } catch(error) { this.error='Failed to load archived records: '+error.message; }
        },

        async restoreArchivedRecord(record) {
            if(this.loading || !['parts','stores','users'].includes(record.kind)) return;
            if(!confirm(`Restore ${record.label} to active use?`)) return;
            this.loading=true; this.error='';
            try {
                const result=await this.apiCall(`/${record.kind}/${record.id}/restore`,{method:'POST'});
                this.successMessage=result.message;
                await this.loadParts(); await this.loadStores(); await this.loadUsers();
                await this.loadInventory(); await this.loadStats(); await this.loadArchivedRecords();
            } catch(error) { this.error='Failed to restore record: '+error.message; }
            finally { this.loading=false; }
        },

    };
}
