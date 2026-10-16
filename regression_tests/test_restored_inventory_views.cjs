const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const html=fs.readFileSync('static/index.html','utf8');

test('every inventory shortcut has a rendered management or personal view',()=>{
    for(const view of ['showMyPartsPanel','showUsersPanel','showEquipmentPanel','showStoreTypesPanel']) {
        assert.match(html,new RegExp(`x-show="[^\"]*${view}`),`${view} should render a panel`);
    }
});

test('equipment workflow includes accessible dialogs for each equipment action',()=>{
    for(const [state,title] of [
        ['showEquipmentModal','equipment-modal-title'],
        ['showCalibrationModal','calibration-modal-title'],
        ['showTransferEquipmentModal','transfer-equipment-modal-title'],
        ['showEquipmentHistoryModal','equipment-history-modal-title'],
        ['showCalibrationSettingsModal','calibration-settings-modal-title']
    ]) {
        const dialog=html.match(new RegExp(`<div[^>]*x-show="${state}"[^>]*>`))?.[0];
        assert.ok(dialog,`${state} should have a dialog`);
        assert.match(dialog,/role="dialog"/);
        assert.match(dialog,/aria-modal="true"/);
        assert.match(dialog,new RegExp(`aria-labelledby="${title}"`));
    }
});

test('restored management tables use mobile cards and SaaS invitation actions',()=>{
    for(const marker of ['<!-- My Parts Panel -->','<!-- User Management Panel','<!-- Equipment Management Panel','<!-- Store Types Management Panel']) {
        const start=html.indexOf(marker);
        const next=html.indexOf('<!-- ',start+marker.length);
        const panel=html.slice(start,next<0?undefined:next);
        assert.match(panel,/<table class="stock-table">/);
        assert.match(panel,/<td[^>]*data-label="[^"]+"/);
    }
    const users=html.slice(html.indexOf('<!-- User Management Panel'),html.indexOf('<!-- Equipment Management Panel'));
    assert.match(users,/x-show="currentUser\?\.saas_mode"/);
    assert.match(users,/resendInvitation\(invitation\.id\)/);
    assert.match(users,/cancelInvitation\(invitation\.id\)/);
    for(const action of ['exportUsersCSV','exportLowStockCSV','exportMyPartsCSV','exportStoreTypesCSV']) assert.match(html,new RegExp(action+'\\(\\)'));
});
