const {loadPageScripts}=require('./helpers/frontend.cjs');
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');

function setup(fetch) {
 const context={console,Intl,Date,URLSearchParams,fetch,window:{location:{href:''}}};
 vm.createContext(context);loadPageScripts('profile.html',context);return context.profileManager();
}

test('desktop profile creates a no-store QR pairing request and polls device status',async()=>{
 const calls=[];
 const p=setup(async(url,options={})=>{
  calls.push({url,options});
  if(url==='/api/profile/mobile-pairings') return {ok:true,json:async()=>({request_id:'pair-id',qr_svg:'<svg></svg>',expires_at:'2026-10-21T12:02:00Z'})};
  return {ok:true,json:async()=>({status:'pending',device_name:'Android phone',expires_at:'2026-10-21T12:02:00Z'})};
 });
 p.profile.saas_mode=true;p.csrfToken='csrf';
 await p.createMobilePairing();
 await new Promise(resolve=>setTimeout(resolve,5));p.stopMobilePairingPolling();
 assert.equal(calls[0].url,'/api/profile/mobile-pairings');
 assert.equal(calls[0].options.cache,'no-store');
 assert.equal(calls[0].options.headers['X-CSRF-Token'],'csrf');
 assert.match(p.mobilePairing.qrDataUrl,/data:image\/svg\+xml/);
 assert.equal(p.mobilePairing.status,'pending');
 assert.equal(p.mobilePairing.deviceName,'Android phone');
});

test('desktop profile sends explicit approval with CSRF protection',async()=>{
 let call;
 const p=setup(async(url,options)=>{call={url,options};return {ok:true,json:async()=>({success:true})};});
 p.profile.saas_mode=true;p.csrfToken='csrf';p.mobilePairing={requestId:'pair-id',status:'pending',qrDataUrl:'data:image/svg+xml,x',deviceName:'Android phone'};
 await p.approveMobilePairing();
 assert.equal(call.url,'/api/profile/mobile-pairings/pair-id/approve');
 assert.equal(call.options.method,'POST');
 assert.equal(call.options.headers['X-CSRF-Token'],'csrf');
 assert.equal(p.mobilePairing.status,'approved');
 assert.match(p.mobilePairingMessage,/Approved/);
});

test('desktop profile can cancel an active pairing request',async()=>{
 let call;
 const p=setup(async(url,options)=>{call={url,options};return {ok:true,json:async()=>({success:true})};});
 p.csrfToken='csrf';p.mobilePairing={requestId:'pair-id',status:'pending',qrDataUrl:'data:image/svg+xml,x'};
 await p.cancelMobilePairing();
 assert.equal(call.url,'/api/profile/mobile-pairings/pair-id/cancel');
 assert.equal(p.mobilePairing,null);
 assert.match(p.mobilePairingSuccess,/canceled/i);
});
