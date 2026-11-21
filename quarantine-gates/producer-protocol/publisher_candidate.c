/* OFFLINE ONE-SHOT PUBLISHER CORE. No module wrapper, loader, native calls, MMIO,
 * scheduling, messages or cleanup. The module packager must provide reviewed
 * immutable code/PTE/current-epoch qualification BEFORE invoking this core.
 * Every exposed entry/continuation/data word remains resident the entire boot.
 * Function return is suitable for init: after any publication it ALWAYS returns
 * zero so a failed partial install cannot cause the module loader to free code.
 * Actual outcome is recorded in ctrl.phase/status, never inferred from init0.
 */
typedef unsigned int u32;typedef unsigned char u8;
#include "queue_waiter_witness.h"
extern volatile u32 wa_gate_active,wa_publication_live,wa_publication_epoch;
extern volatile u32 wa_loop_seen[2],wa_tasks[4];
extern volatile u8 wa_gate_denials[6],wa_coverage_fault;
struct wp_config {u32 native_wait,native_receive,wait_gateway,receive_gateway,epoch,task_f3,pid_f3,task_f5,pid_f5,max_polls;};
struct wp_control {u32 phase,status,ever_published,polls,restore_wait,restore_receive,keep_resident,join_observed,controller_started,control_lock;};
enum { WP_NEW=0,WP_OBSERVING=1,WP_JOINED=2,WP_DECLINED=3,WP_DISARMED=4,WP_CONFLICT=5,WP_RECOVERY_OWNED=6 };
enum { WP_OK=0,WP_BAD_PROFILE=1,WP_RECEIVE_INSTALL=2,WP_WAIT_INSTALL=3,WP_TIMEOUT=4,WP_COVERAGE=5,WP_NATIVE_ERROR=6,WP_POINTER_CHANGED=7 };
#define WS ((volatile u32*)0x635c6278u)
#define RS ((volatile u32*)0x635c6294u)
static void barrier(void){__asm__ volatile("dmb sy":::"memory");}
static int replace(volatile u32*p,u32 expected,u32 desired){
 u32 n,seen,status;
 for(n=0;n<4;n++){
  __asm__ volatile("ldrex %0,[%2]\n cmp %0,%3\n bne 1f\n strex %1,%4,[%2]\n b 2f\n1: clrex\n mov %1,#2\n2:"
   :"=&r"(seen),"=&r"(status):"r"(p),"r"(expected),"r"(desired):"cc","memory");
  if(status==0){barrier();return 1;}
  if(status==2)return 0;
 }
 return 0;
}
static int ptr(u32 a){return !(a&3)&&a>=0x5f000000u&&a<0x60000000u;}
static int task(u32 a,u32 pid){
 u32 ti;if(!pid||(a&3)||a<0x60100000u||a>0x787ffef8u)return 0;
 if(*(volatile u32*)(a+0x104)!=pid)return 0;ti=*(volatile u32*)(a+8);
 if((ti&8191)||ti<0x60100000u||ti>0x787fe000u)return 0;
 return *(volatile u32*)(ti+12)==a;
}
static int faults(void){u32 i;if(wa_coverage_fault)return WP_COVERAGE;for(i=0;i<6;i++)if(wa_gate_denials[i])return WP_NATIVE_ERROR;return WP_OK;}
static void disarm(struct wp_control*c,const struct wp_config*q){
 /* New observed boundaries cannot authorize a trial after this point. */
 wa_publication_live=0;wa_gate_active=0;barrier();
 c->restore_wait=*WS==q->native_wait?1u:(u32)replace(WS,q->wait_gateway,q->native_wait);
 c->restore_receive=*RS==q->native_receive?1u:(u32)replace(RS,q->receive_gateway,q->native_receive);
 if(!c->restore_wait||!c->restore_receive)c->phase=WP_CONFLICT;
 /* Do not erase epoch/seen/denial/coverage or claim late call retirement. */
}
__attribute__((noinline)) static int publish_locked(struct wp_control*c,const struct wp_config*q){
 u32 i;
 if(c->ever_published)return 0; /* one shot: cannot reinitialize exposed state */
 if(c->phase!=WP_NEW||c->controller_started||!q->epoch||!q->max_polls||q->max_polls>128||
    !ptr(q->native_wait)||!ptr(q->native_receive)||!ptr(q->wait_gateway)||!ptr(q->receive_gateway)||
    q->native_wait==q->wait_gateway||q->native_receive==q->receive_gateway||q->wait_gateway==q->receive_gateway||
    q->task_f3==q->task_f5||q->pid_f3==q->pid_f5||!task(q->task_f3,q->pid_f3)||!task(q->task_f5,q->pid_f5)||
    wa_gate_active||wa_publication_live||wa_publication_epoch||wa_loop_seen[0]||wa_loop_seen[1]||faults()){
  c->phase=WP_DECLINED;c->status=WP_BAD_PROFILE;return c->ever_published?0:-16;
 }
 for(i=0;i<4;i++)if(wa_tasks[i]){c->phase=WP_DECLINED;c->status=WP_BAD_PROFILE;return -16;}
 /* root's qualified task values; exact same cells used by both ASM gateways. */
 wa_tasks[0]=q->task_f3;wa_tasks[1]=q->pid_f3;wa_tasks[2]=q->task_f5;wa_tasks[3]=q->pid_f5;
 wa_publication_epoch=q->epoch;barrier();
 if(!replace(RS,q->native_receive,q->receive_gateway)){
  c->phase=WP_DECLINED;c->status=WP_RECEIVE_INSTALL;return -16;
 }
 c->ever_published=1;c->keep_resident=1;barrier();
 if(!replace(WS,q->native_wait,q->wait_gateway)){
  c->phase=WP_DECLINED;c->status=WP_WAIT_INSTALL;disarm(c,q);return 0;
 }
 c->ever_published=3;wa_gate_active=1;barrier();
 c->phase=WP_OBSERVING;c->status=WP_OK;wa_publication_live=1;barrier();return 0;
}
/* One finite observation step; caller uses its finite external observation
 * schedule. No sleep/wait is performed here. READY is a current SOFTWARE old-
 * caller witness only; it is never producer/DMA drain or cleanup permission. */
__attribute__((noinline)) static int poll_locked(struct wp_control*c,const struct wp_config*q){
 int f;
 if(c->phase!=WP_OBSERVING&&c->phase!=WP_JOINED&&c->phase!=WP_RECOVERY_OWNED)return -1;
 barrier();
 if(*WS!=q->wait_gateway||*RS!=q->receive_gateway||wa_publication_live!=1||wa_gate_active!=1||wa_publication_epoch!=q->epoch||
    !task(q->task_f3,q->pid_f3)||!task(q->task_f5,q->pid_f5)){
  c->status=WP_POINTER_CHANGED;if(c->controller_started)return -2;
  c->phase=WP_DECLINED;disarm(c,q);return -1;
 }
 f=faults();if(f){c->status=(u32)f;if(c->controller_started)return -2;c->phase=WP_DECLINED;disarm(c,q);return -1;}
 if(wa_loop_seen[0]==q->epoch&&wa_loop_seen[1]==q->epoch){if(!c->controller_started)c->phase=WP_JOINED;c->join_observed=1;return 1;}
 if(c->controller_started)return -2;
 if(++c->polls>=q->max_polls){c->phase=WP_DECLINED;c->status=WP_TIMEOUT;disarm(c,q);return -1;}
 return 0;
}
/* Observation stopped before a recovery controller starts. A transferred cmd2
 * or hardware mutation requires its separate protocol and may NOT use this as
 * rollback. The caller must enforce that ownership boundary. */
__attribute__((noinline)) static int claim_locked(struct wp_control*c,const struct wp_config*q){
 if(c->controller_started||poll_locked(c,q)!=1)return 0;
 c->controller_started=1;c->phase=WP_RECOVERY_OWNED;barrier();return 1;
}
__attribute__((noinline)) static int stop_locked(struct wp_control*c,const struct wp_config*q){
 if(c->controller_started)return 0;
 c->phase=WP_DISARMED;disarm(c,q);return 1;
}

/* This module-owned lock serializes ONLY controller APIs. Native wait/receive
 * gateways never take it. Single bounded CAS attempt sequence; no spin/wait.
 * publish is called only once by module init; a contended call still returns0
 * conservatively retaining code, never allowing module-loader free while another
 * controller may be publishing. Return0 is explicitly not a success status. */
static void leave(struct wp_control*c){barrier();c->control_lock=0;}
int wp_publish(struct wp_control*c,const struct wp_config*q){
 int rc;if(!replace(&c->control_lock,0,1))return 0;rc=publish_locked(c,q);leave(c);return rc;
}
int wp_poll(struct wp_control*c,const struct wp_config*q){
 int rc;if(!replace(&c->control_lock,0,1))return -3;rc=poll_locked(c,q);leave(c);return rc;
}
int wp_claim_ready(struct wp_control*c,const struct wp_config*q){
 int rc;if(!replace(&c->control_lock,0,1))return 0;rc=claim_locked(c,q);leave(c);return rc;
}
int wp_stop_observation(struct wp_control*c,const struct wp_config*q){
 int rc;if(!replace(&c->control_lock,0,1))return 0;rc=stop_locked(c,q);leave(c);return rc;
}
/* Alternative to a new natural receive entry: inspect an ALREADY parked native
 * receive under its real queue lock. This runs only before controller claim.
 * The same controller lock prevents disarm/claim races while the witness is
 * established. No new message, native wake, queue mutation or forced parking.
 * Neither worker is used as controller; the adapter checks current task != F3/F5.
 * The caller must provide the separately qualified original module/lifetime
 * profile; this core does not infer that from numeric addresses.
 */
int wp_probe_parked(struct wp_control*c,const struct wp_config*q,const struct qw_profile*p,struct qw_result*r){
 int rc=0;u32 task,pid;
 r->valid=0;
 if(!replace(&c->control_lock,0,1))return 0;
 if(c->controller_started||(c->phase!=WP_OBSERVING&&c->phase!=WP_JOINED)||p->index>1)goto done;
 task=p->index?q->task_f5:q->task_f3;pid=p->index?q->pid_f5:q->pid_f3;
 if(p->epoch!=q->epoch||p->task!=task||p->pid!=pid||p->wait_gateway!=q->wait_gateway||p->receive_gateway!=q->receive_gateway)goto done;
 if(faults())goto done;
 rc=qw_probe_task(p,r);
 if(rc!=1)goto done;
 barrier();
 if(faults()||wa_publication_live!=1||wa_gate_active!=1||wa_publication_epoch!=q->epoch||
    *WS!=q->wait_gateway||*RS!=q->receive_gateway){rc=0;goto done;}
 wa_loop_seen[p->index]=q->epoch;barrier();
done:leave(c);return rc;
}
