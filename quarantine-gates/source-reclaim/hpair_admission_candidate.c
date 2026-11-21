/* Offline candidate: atomic cohort reservation in original RC job-admission
 * table under original numbered lock7. Native op1009 and current native TID
 * match original Release admission semantics. No hardware or object Release.
 * Requires a single serialized recovery controller and current code/slot
 * qualification. A lease excludes guarded task APIs, NOT IRQ rearm or SGC
 * callers; those require their own native stop/join before any object release.
 */
typedef unsigned int u32;
struct hp_profile {u32 tryfn,unlockfn,gettidfn,expected_tid;};
struct hp_receipt {u32 active,owner_word,effect_started;};
static u32 rd(u32 a){return *(volatile u32*)a;}
static void wr(u32 a,u32 x){*(volatile u32*)a=x;}
static int identity(const struct hp_profile*p){
 return p->expected_tid &&
 p->tryfn>=0x5f000000 && p->tryfn<0x60000000 && !(p->tryfn&3) &&
 p->unlockfn>=0x5f000000 && p->unlockfn<0x60000000 && !(p->unlockfn&3) &&
 p->gettidfn>=0x5f000000 && p->gettidfn<0x60000000 && !(p->gettidfn&3) &&
 rd(0x635c6240)==p->tryfn &&rd(0x635c6244)==p->unlockfn &&rd(0x635c620c)==p->gettidfn;
}
static int current(const struct hp_profile*p){u32 tid=0;return ((int(*)(u32*))p->gettidfn)(&tid)==0&&tid==p->expected_tid;}
static void unlock(const struct hp_profile*p){((void(*)(u32))p->unlockfn)(7);}
/* 0=owns BOTH native job-admission rows;1=lock/table busy, no changes;
 * 2=identity/context refusal, no changes. No partial acquisition/rollback.
 */
int hp_reserve_once(const struct hp_profile*p,struct hp_receipt*r){
 u32 token;
 if(r->active||!identity(p))return 2;
 if(((int(*)(u32))p->tryfn)(7))return 1;
 if(!identity(p)||!current(p)){unlock(p);return 2;}
 if(rd(0x6438ca2c)||rd(0x6438ca38)){unlock(p);return 1;}
 token=(p->expected_tid<<16)|0x1009;
 wr(0x6438ca2c,token);wr(0x6438ca38,token);
 r->owner_word=token;r->effect_started=0;r->active=1;
 unlock(p);return 0;
}
/* Only undo an UNUSED reservation. A controller MUST set effect_started
 * before any source/IRQ/hardware/ownership change. This is not a final
 * post-stop relinquish API. Successful safe-release completion is separate.
 * 0=canceled,1=lock busy retain receipt,2=refuse retain all rows/receipt.
 */
int hp_cancel_unused_once(const struct hp_profile*p,struct hp_receipt*r){
 if(!r->active||r->effect_started||!identity(p))return 2;
 if(((int(*)(u32))p->tryfn)(7))return 1;
 if(!identity(p)||!current(p)||rd(0x6438ca2c)!=r->owner_word||rd(0x6438ca38)!=r->owner_word){unlock(p);return 2;}
 wr(0x6438ca2c,0);wr(0x6438ca38,0);r->active=0;
 unlock(p);return 0;
}
