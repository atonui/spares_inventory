const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {loadPageScripts} = require('./helpers/frontend.cjs');

function setup(fetch) {
  const replaced=[];
  const c=vm.createContext({
    Headers, FormData, URLSearchParams, Response, fetch, console,
    document:{title:'Accept invitation'},
    window:{
      location:{search:'?organization_id=tenant-uuid&token=raw-invitation-secret',pathname:'/static/accept_invitation.html'},
      history:{replaceState(_state,_title,url){replaced.push(url);}},
    },
  });
  loadPageScripts('accept_invitation.html',c);
  const page=c.acceptInvitation();
  page.init();
  return {c,page,replaced};
}

test('acceptance consumes the query token from the URL and clears it after success',async()=>{
  const calls=[];
  const fetch=async(url,options)=>{
    calls.push([url,options]);
    if(url==='/api/csrf-token')return new Response(JSON.stringify({csrf_token:'csrf'}),{status:200});
    return new Response(JSON.stringify({success:true}),{status:200});
  };
  const {page,replaced}=setup(fetch);
  assert.equal(page.token,'raw-invitation-secret');
  assert.deepEqual(replaced,['/static/accept_invitation.html']);
  page.name='New Person';page.password='long-password';
  await page.submit();
  const request=calls.find(([url])=>url==='/api/invitations/accept')[1];
  assert.deepEqual(JSON.parse(request.body),{
    organization_id:'tenant-uuid',token:'raw-invitation-secret',name:'New Person',password:'long-password',
  });
  assert.equal(page.complete,true);assert.equal(page.token,'');assert.equal(page.organizationId,'');assert.equal(page.password,'');
  assert.equal(calls.some(([url,options])=>url.includes('localStorage')||String(options?.body||'').includes('localStorage')),false);
});

test('failed acceptance keeps the token in memory for retry, not in the URL',async()=>{
  const fetch=async(url)=>{
    if(url==='/api/csrf-token')return new Response(JSON.stringify({csrf_token:'csrf'}),{status:200});
    return new Response(JSON.stringify({detail:'Invitation is invalid or expired'}),{status:400});
  };
  const {page,replaced}=setup(fetch);
  await page.submit();
  assert.equal(page.complete,false);
  assert.equal(page.error,'Invitation is invalid or expired');
  assert.equal(page.token,'raw-invitation-secret');
  assert.deepEqual(replaced,['/static/accept_invitation.html']);
});
