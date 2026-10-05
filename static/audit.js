// Plain text only: audit content is always rendered with x-text, never HTML.
function formatStockAuditDetails(raw) {
    if (!raw) return 'No details recorded';
    let data=raw;
    if(typeof raw==='string') { try { data=JSON.parse(raw); } catch { return raw; } }
    if(!data || typeof data!=='object') return String(data);
    if(data.schema_version!==1 || !Array.isArray(data.balance_changes)) return JSON.stringify(data,null,2);
    const snapshotValid=value=>value && typeof value==='object' && !Array.isArray(value) && typeof value.quantity==='number';
    if(!data.balance_changes.every(change=>change && snapshotValid(change.before) && snapshotValid(change.after))
       || (data.movement_ids!==undefined && !Array.isArray(data.movement_ids))) return JSON.stringify(data,null,2);
    const lines=data.balance_changes.map((change,index)=>{
        const before=change.before || {},after=change.after || {};
        let line=`${before.store_name || after.store_name} · ${before.part_number || after.part_number} · ${before.work_order || after.work_order || 'Unallocated'}: ${before.quantity} → ${after.quantity}`;
        if(before.min_threshold!==after.min_threshold) line+=`; minimum ${before.min_threshold} → ${after.min_threshold}`;
        const reason=data.rows?.[index]?.reason;
        if(reason) line+=`; ${reason}`;
        return line;
    });
    if(data.transfer_id) lines.push(`Transfer #${data.transfer_id}: ${data.before_status || 'Not dispatched'} → ${data.after_status}`);
    if(data.to_store_name) lines.push(`Destination: ${data.to_store_name} (awaiting receipt)`);
    if(data.consumed_work_order) lines.push(`Consumed for work order ${data.consumed_work_order}`);
    if(data.movement_ids?.length) lines.push(`Movements: ${data.movement_ids.map(id=>'#'+id).join(', ')}`);
    if(data.notes) lines.push(`Notes: ${data.notes}`);
    if(!lines.length) lines.push('No balances changed');
    return lines.join('\n');
}
