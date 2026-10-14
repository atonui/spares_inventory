// Public and role-filtered notices use server eligibility; messages remain plain text.
function notifyAnnouncementIdentityChange() {
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') window.dispatchEvent(new Event('inventory:identity-change'));
}
function siteAnnouncementBanner() {
    return {
        announcement:null,error:'',loading:false,timer:null,expiryTimer:null,visibilityHandler:null,identityHandler:null,storageHandler:null,pageHandler:null,
        generation:0,destroyed:false,dismissalMode:'browser',viewerKey:'anonymous',dismissPending:false,dismissError:'',csrfToken:'',browserDismissed:{},
        init() {
            this.load();
            this.timer=setInterval(()=>{if(document.visibilityState!=='hidden')this.load();},60000);
            this.visibilityHandler=()=>{if(document.visibilityState!=='hidden'){this.checkExpiry();this.load();}};
            this.identityHandler=()=>{this.generation++;this.loading=false;this.dismissPending=false;this.csrfToken='';this.announcement=null;this.cancelExpiry();this.load();};
            this.storageHandler=event=>{if(event.key==='currentUser')this.identityHandler();};
            this.pageHandler=()=>this.identityHandler();
            document.addEventListener('visibilitychange',this.visibilityHandler);
            if(typeof window!=='undefined') {
                window.addEventListener('inventory:identity-change',this.identityHandler);
                window.addEventListener('storage',this.storageHandler);
                window.addEventListener('pageshow',this.pageHandler);
            }
        },
        destroy() {
            this.destroyed=true;this.generation++;clearInterval(this.timer);this.cancelExpiry();
            document.removeEventListener('visibilitychange',this.visibilityHandler);
            if(typeof window!=='undefined') {
                window.removeEventListener('inventory:identity-change',this.identityHandler);
                window.removeEventListener('storage',this.storageHandler);
                window.removeEventListener('pageshow',this.pageHandler);
            }
        },
        cancelExpiry() {if(this.expiryTimer!==null){clearTimeout(this.expiryTimer);this.expiryTimer=null;}},
        checkExpiry() {
            if(this.announcement?.expires_at && Date.now()>=Date.parse(this.announcement.expires_at)){this.announcement=null;this.cancelExpiry();}
        },
        armExpiry() {
            this.cancelExpiry();this.checkExpiry();
            if(this.announcement?.expires_at) {
                const delay=Math.max(0,Math.min(2147483647,Date.parse(this.announcement.expires_at)-Date.now()));
                this.expiryTimer=setTimeout(()=>this.armExpiry(),delay);
            }
        },
        isBrowserDismissed(revision) {
            if(!revision)return false;
            if(this.browserDismissed[revision])return true;
            try{return localStorage.getItem('inventory:announcement:dismissed:'+revision)==='1';}catch{return false;}
        },
        async load() {
            if(this.destroyed || this.loading || this.dismissPending)return;
            this.loading=true;const generation=++this.generation;
            try {
                const response=await fetch('/api/superadmin/announcement',{credentials:'same-origin',cache:'no-store'});
                if(!response.ok)throw Error('Announcement request failed');
                const data=await response.json();const notice=data.announcement;
                if(notice!==null && (!notice || typeof notice.message!=='string' || !['info','warning','danger'].includes(notice.level) || (notice.expires_at && !Number.isFinite(Date.parse(notice.expires_at)))))throw Error('Invalid announcement');
                if(generation!==this.generation || this.destroyed)return;
                this.dismissalMode=data.dismissal_mode || 'browser';this.viewerKey=data.viewer_key || 'anonymous';
                this.announcement=notice && this.dismissalMode==='browser' && this.isBrowserDismissed(notice.revision)?null:notice;
                this.error='';this.dismissError='';this.armExpiry();
            } catch {
                if(generation!==this.generation || this.destroyed)return;
                if(this.announcement?.audience && this.announcement.audience!=='everyone'){this.announcement=null;this.cancelExpiry();}
                this.checkExpiry();this.error='Announcement updates are unavailable. Any last loaded public notice may be out of date.';
            } finally {if(generation===this.generation)this.loading=false;}
        },
        async dismiss() {
            if(this.destroyed || this.dismissPending || !this.announcement?.dismissible)return;
            const notice=this.announcement,viewerKey=this.viewerKey,generation=++this.generation;
            this.loading=false;this.dismissPending=true;this.dismissError='';
            try {
                if(this.dismissalMode==='account') {
                    const response=await InventoryCsrf.request(this,'/api/superadmin/announcement/dismiss',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:notice.revision,viewer_key:viewerKey})});
                    if(!response.ok){const data=await response.json().catch(()=>({}));throw Error(data.detail || 'Unable to dismiss announcement');}
                } else {
                    this.browserDismissed[notice.revision]=true;
                    try{localStorage.setItem('inventory:announcement:dismissed:'+notice.revision,'1');}catch{}
                }
                if(generation!==this.generation || this.destroyed)return;
                this.announcement=null;this.cancelExpiry();
            } catch(error) {if(generation===this.generation)this.dismissError=error.message;}
            finally {if(generation===this.generation)this.dismissPending=false;}
        },
    };
}
