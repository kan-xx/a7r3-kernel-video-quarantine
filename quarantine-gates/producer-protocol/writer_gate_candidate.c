/* OFFLINE CANDIDATE, no installer, module, hook, device caller or MMIO.
 * Pins the F3 copied-marker domain together with the ORIGINAL common bsem.
 * A root-owned runtime bridge still has to provide an authenticated F3 context,
 * current immutable code qualification and pinned OSAL descriptor lifetime.
 * All six common acquire-success gateways must already be installed and
 * quiesced before activation. Native RAII ignores acquisition errors; a bare
 * common lease is NOT exclusion against that original error path. Gate denial
 * bytes are monotonic for this transaction; any denial blocks continuation.
 * No single-field CAS substitutes for this multi-field ownership region.
 *
 * First executable scope: channel0 encoder only; siblings must be inactive;
 * common & encoder SM queues and shared pending-create queue must be empty.
 * Nonempty old commands are PRESERVED and refused, never erased or ACKed.
 * A successful call RETAINS THE COMMON LEASE. Do not return to normal F3 pump
 * until downstream admission/join protocol is implemented. This is not full
 * recovery, STOP_DONE, DMM cleanup permission or a permanent-quarantine success.
 */
typedef unsigned int u32;typedef unsigned char u8;
struct pd_submit {
 u32 phase,nonce,expected_pid,expected_task,entry_sp,entry_lr,receiver,message,source;
 u32 active_snapshot,type_snapshot,refs_snapshot,owned_payload,queue,bytes,packet_source;
 u32 submitted,local_committed,free_failed,error,worker_expected_payload,worker_armed,worker_turn_done,late_register;
};
struct wd_gate {
 u32 phase,descriptor,osal_bss,expected_root,expected_l1,expected_l2;
 u32 common_sm,encoder_sm,result,submit_result,lease_pid;
};
enum { WD_NEW=0, WD_HELD=1, WD_HELD_REJECTED=2, WD_SUBMITTED=3, WD_RELEASED=4, WD_RELEASE_UNCERTAIN=5, WD_FAULT_LATCHED=6 };
enum { W_OK=0,W_CONTEXT=1,W_CHAIN=2,W_BUSY=3,W_COHORT=4,W_FIFO=5,W_SUBMIT=6,W_RELEASE=7,W_ADMISSION=8 };
extern int bb_sem_try_task(u32 descriptor);
extern int pd_unsubscribe_submit(struct pd_submit*);
extern int pd_unsubscribe_observed(struct pd_submit*);
extern volatile u32 wd_common_descriptor,wd_gate_active,wd_gate_epoch;
extern volatile u8 wd_gate_denials[6];
#define MAIN 0x64139e18u
#define COMMON 0x6436b670u
#define OWNER (COMMON+0x6de0u)
#define CORE 0x6413a128u
#define VFC 0x6413a08cu
#define COUNTERS 0x6413a05cu
static u32 rd(u32 a){return *(volatile u32*)a;}
static u8 rb(u32 a){return *(volatile u8*)a;}
static int ram(u32 a,u32 n){return !(a&3)&&n&&a>=0x60100000u&&a<=0x78800000u-n;}
static int av(u32 a,u32 n){return !(a&3)&&n&&a>=0x635c6000u&&a<=0x648c6000u-n;}
static int ctx(struct pd_submit*p){
 u32 sp,cpsr,ti,task;__asm__ volatile("mov %0,sp":"=r"(sp));__asm__ volatile("mrs %0,cpsr":"=r"(cpsr));
 if((cpsr&0x9f)!=0x13||(p->entry_sp&7)||p->entry_lr!=0x639fc8afu||!p->nonce)return 0;
 if((sp&~8191u)!=(p->entry_sp&~8191u)||!ram(p->entry_sp,4))return 0;
 ti=sp&~8191u;if(rd(ti+4)!=0)return 0;task=rd(ti+12);
 if(!ram(task,0x108)||task!=p->expected_task||rd(task+0x104)!=p->expected_pid||!p->expected_pid)return 0;
 return p->receiver==0x6413a120u&&p->message==MAIN+0x120u&&p->source==0x6800f3u&&
 rd(MAIN+4)==0x6800f3u&&rd(MAIN+0x2fc)==p->receiver&&rd(p->receiver)==0x646957f0u&&
 rd(p->message)==0x7ff02103u&&rd(p->message+4)==0&&rd(p->message+8)==0x4a4f494eu&&rd(p->message+12)==p->nonce;
}
static int chain(struct wd_gate*g){
 u32 a,b,c;if(rd(COMMON)!=0x6805e6u||!ram(g->descriptor,16))return 0;
 /* .bss may be vmalloc/module VA, qualified mapped RAM; not direct-map-only. */
 if((g->osal_bss&3)||g->osal_bss<0x5f000000u||g->osal_bss>0x60000000u-0x1770u)return 0;
 a=rd(g->osal_bss+0x176c);if(a!=g->expected_root||!ram(a,0x20))return 0;
 b=rd(a+0x1c);if(b!=g->expected_l1||!ram(b,0x14))return 0;
 c=rd(b+0x10);if(c!=g->expected_l2||!ram(c,0x1c))return 0;
 return rd(c+0x18)==g->descriptor;
}
static int emptyq(u32 q,u32 capacity){
 u32 count=rd(q),w=rd(q+4),r=rd(q+8);return !count&&r<capacity&&w==r;
}
static int cohort(struct wd_gate*g){
 u32 i,w,sm,v,ch,active,kind,refs;
 if(rd(CORE)!=0x6413a0e0u||rd(CORE+8)!=COMMON)return W_COHORT;
 for(i=0;i<3;i++){
  v=VFC+i*28;ch=0x6413a0e0u+i*16;
  if(rd(v)!=6+i||rd(v+4)!=COUNTERS||rd(ch)!=i||rd(ch+4)!=0x6800f3u||rd(ch+12)!=v)return W_COHORT;
  if(i&&rb(v+8))return W_COHORT;
 }
 if(rd(MAIN+0xf14c)||rd(MAIN+0x1df9c))return W_COHORT;
 active=rb(VFC+8);kind=rd(VFC+12);if(active!=1||(kind!=0&&kind!=2))return W_COHORT;
 refs=kind==0?COUNTERS:COUNTERS+12;
 for(i=0;i<4;i++)if(rd(COUNTERS+i*12+4)!=0x6800f3u||rd(COUNTERS+i*12+8)!=1||rd(COUNTERS+i*12)!=(COUNTERS+i*12==refs?1u:0u))return W_COHORT;
 w=rd(CORE+4);if(!av(w,4))return W_COHORT;sm=rd(w);if(!av(sm,0x554)||rd(sm)!=CORE)return W_COHORT;
 g->encoder_sm=sm;if(rb(sm+8)||!emptyq(sm+0x520,10))return W_FIFO;
 w=rd(OWNER);if(!av(w,4))return W_COHORT;sm=rd(w);if(!av(sm,0x218)||rd(sm)!=OWNER)return W_COHORT;
 g->common_sm=sm;if(rb(sm+8)||!emptyq(sm+0x1e4,10)||!emptyq(OWNER+0xb8c0,2))return W_FIFO;
 return W_OK;
}
static int gates(struct wd_gate*g,struct pd_submit*p){
 u32 i;if(wd_gate_active!=1)return 0;__asm__ volatile("dmb sy":::"memory");
 if(wd_common_descriptor!=g->descriptor||wd_gate_epoch!=p->nonce)return 0;
 for(i=0;i<6;i++)if(wd_gate_denials[i])return 0;
 return 1;
}
int wd_enter_and_submit(struct wd_gate*g,struct pd_submit*p){
 int rc;
 if(g->phase!=WD_NEW||p->phase||!ctx(p))return g->result=W_CONTEXT;
 if(!chain(g))return g->result=W_CHAIN;
 if(!gates(g,p))return g->result=W_ADMISSION;
 rc=bb_sem_try_task(g->descriptor);if(rc)return g->result=W_BUSY;
 g->phase=WD_HELD;g->lease_pid=p->expected_pid;
 /* Exclusion is conditional on the separately installed six entry gates;
  * the original unchecked-acquire error path invalidates a bare-lease claim. */
 if(!gates(g,p)){g->phase=WD_FAULT_LATCHED;return g->result=W_ADMISSION;}
 if(!ctx(p)||!chain(g)){g->phase=WD_HELD_REJECTED;return g->result=W_CONTEXT;}
 rc=cohort(g);if(rc){g->phase=WD_HELD_REJECTED;return g->result=rc;}
 if(!gates(g,p)){g->phase=WD_FAULT_LATCHED;return g->result=W_ADMISSION;}
 rc=pd_unsubscribe_submit(p);g->submit_result=(u32)rc;
 if(!gates(g,p)){g->phase=WD_FAULT_LATCHED;return g->result=W_ADMISSION;}
 if(rc){g->phase=WD_HELD_REJECTED;return g->result=W_SUBMIT;}
 g->phase=WD_SUBMITTED;return g->result=W_OK;
}
/* Only unwind an attempt that did not transfer a message or modify refs.
 * Original sig_sem is called once and may hand ownership to an existing waiter.
 * It has native scheduler/spinlock bounds, NOT a strict elapsed-time bound.
 * After any successful/partial send this function refuses to resume anything.
 */
int wd_unwind_before_submit(struct wd_gate*g,struct pd_submit*p){
 int rc;
 if(g->phase!=WD_HELD_REJECTED||!ctx(p)||!chain(g)||!gates(g,p)||g->lease_pid!=p->expected_pid||
 p->submitted||p->local_committed||p->owned_payload||p->free_failed||p->worker_armed||
 *(volatile unsigned short*)(g->descriptor+4)!=1||rd(g->descriptor+12)!=g->lease_pid)return W_RELEASE;
 g->phase=WD_RELEASE_UNCERTAIN;
 rc=((int(*)(u32))0x635e4515u)(0x6805e6u);
 if(rc)return W_RELEASE;
 g->phase=WD_RELEASED;return W_OK;
}

/* Revalidate immediately before any NEXT protocol step. This function grants
 * only a current cmd2 worker-turn observation, never cleanup/STOP_DONE/resume.
 * A denial can arrive later, so it cannot be stored as a permanent permit. */
int wd_submission_observed(struct wd_gate*g,struct pd_submit*p){
 if(g->phase!=WD_SUBMITTED||!ctx(p)||!chain(g)||
    *(volatile unsigned short*)(g->descriptor+4)!=1||rd(g->descriptor+12)!=g->lease_pid||
    g->lease_pid!=p->expected_pid)return 0;
 if(!gates(g,p)){g->phase=WD_FAULT_LATCHED;g->result=W_ADMISSION;return 0;}
 return pd_unsubscribe_observed(p);
}
