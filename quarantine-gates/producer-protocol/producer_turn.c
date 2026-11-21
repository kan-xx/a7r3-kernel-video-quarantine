/* OFFLINE SYSV-only successor. No installation or hardware access. Existing
 * whole-boot F3/SYSV queue/task lifetimes and published common-acquire gateways
 * are prerequisites, not inferred from historical numeric addresses.
 *
 * Fix the first-receive publication gap: arm only while SYSV's original receive
 * is parked, its queue is empty under its REAL lock, and F3 is still registered.
 * Under the F3-owned common lease no other qualified VFC writer can enqueue
 * cmd1/cmd2. The next entry with target removed/monitor3 must follow original
 * cmd2 handler AND original free, even if that receive began before publication.
 * Never dereference the transferred payload or treat refs0 alone as this proof.
 */
#include "producer_turn.h"
extern volatile u32 wa_gate_active,wa_publication_live,wa_publication_epoch,wa_loop_seen[2],wa_tasks[4];
extern volatile u8 wa_coverage_fault,wa_gate_denials[6];
#define MAIN 0x64139e18u
#define TARGET 0x6800f3u
#define QID 0xc2019fu
#define REGISTRY 0x641cb344u
static u32 rd(u32 p){return *(volatile u32*)p;}
static int ram(u32 p,u32 n){return !(p&3)&&n&&p>=0x60100000u&&p<=0x78800000u-n;}
static void barrier(void){__asm__ volatile("dmb sy":::"memory");}
static int common(struct pp_config*c){
 u32 i;struct pd_submit*t=c->submit;
 if(!c->epoch||wa_gate_active!=1||wa_publication_live!=1||wa_publication_epoch!=c->epoch||
    wa_loop_seen[0]!=c->epoch||wa_loop_seen[1]!=c->epoch||wa_coverage_fault||
    wa_tasks[0]!=c->f3_task||wa_tasks[1]!=c->f3_pid||!c->f3_pid||
    rd(0x635c6278)!=c->wait_gateway||rd(0x635c6294)!=c->receive_gateway)return 0;
 for(i=0;i<6;i++)if(wa_gate_denials[i])return 0;
 if(!ram(c->common_bsem,16)||*(volatile unsigned short*)(c->common_bsem+4)!=1||rd(c->common_bsem+12)!=c->f3_pid)return 0;
 if(t->nonce!=c->epoch||t->expected_task!=c->f3_task||t->expected_pid!=c->f3_pid||
    t->entry_lr!=0x639fc8af||t->receiver!=0x6413a120||t->message!=MAIN+0x120||t->source!=TARGET)return 0;
 return rd(t->message)==0x7ff02103&&rd(t->message+4)==0&&rd(t->message+8)==0x4a4f494e&&rd(t->message+12)==c->epoch;
}
static int worker(struct pp_config*c){
 return ram(c->task,0x108)&&c->pid&&ram(c->ti,8192)&&!(c->ti&8191)&&rd(c->task+8)==c->ti&&
  rd(c->task+0x104)==c->pid&&rd(c->ti+12)==c->task&&c->task!=c->f3_task&&
  c->monitor>=0x646a1960&&c->monitor<=0x646a1960+0x108-12&&(c->monitor-0x646a1960)%12==0&&rd(c->monitor+4)==TARGET;
}
static u32 registered(void){u32 i,n=0;for(i=0;i<32;i++)n+=rd(REGISTRY+4*i)==TARGET;return n;}
u32 pp_resolve(struct pp_config*c){
 u32 a,b,d,sp,task;
 __asm__ volatile("mov %0,sp":"=r"(sp));task=rd((sp&~8191u)+12);
 if(task!=c->f3_task||!common(c)||!worker(c)||!ram(c->queue,32)||
    (c->osal_bss&3)||c->osal_bss<0x5f000000||c->osal_bss>0x60000000-0xd44||
    (c->osal_text&3)||c->osal_text<0x5f000000||c->osal_text>0x60000000-0x36c4||
    (c->liro_text&3)||c->liro_text<0x5f000000||c->liro_text>0x60000000-0xa98)return 0;
 /* queue019f -> root42, level6, level3, leaf7, existing objects only. */
 a=rd(c->osal_bss+0xc38+0x42*4);if(!ram(a,28))return 0;
 b=rd(a+6*4);if(!ram(b,16))return 0;d=rd(b+3*4);if(!ram(d,32))return 0;
 return rd(d+7*4)==c->queue?c->queue:0;
}
int pp_arm_locked(struct pp_config*c){
 u32 q=c->queue,w,s;struct pd_submit*t=c->submit;
 if(c->phase||c->invalid||c->turn_seen||t->phase||t->worker_armed||pp_resolve(c)!=q||!(rd(q)&0x80000000u))return 0;
 if(*(volatile u8*)(q+4)||rd(q+12))return 0;
 w=rd(q+8);if(!ram(w,136)||w<c->ti+64||w>c->ti+8192-136)return 0;s=w+96;
 if((s&7)||rd(w)||rd(w+8)!=c->osal_text+0x2774||*(volatile u8*)(w+12)||*(volatile u8*)(w+13)!=4||rd(w+16)||
    rd(w+20)!=c->task||rd(w+24)!=s+0x24||rd(s+0x24)||
    rd(w+36)!=s+0x24||rd(w+40)!=QID||rd(w+52)!=s-32||rd(w+56)!=c->liro_text+0xa88||
    rd(w+84)!=s||rd(w+88)!=0x635e45b3||rd(w+100)!=0x636ee16d)return 0;
 /* Pending cmd1/cmd2 excluded by empty queue and current native receive.
  * Existing target must be unique and NOT already marked removed. */
 if(registered()!=1||rd(c->monitor+8)==3)return 0;
 c->baseline_waiter=w;c->baseline_sp=s;barrier();c->phase=1;barrier();return 1;
}
void pp_receive_before(struct pp_config*c,u32 sp,u32 lr,u32 output){
 u32 task,caller,cpsr;struct pd_submit*t=c->submit;
 if((c->phase!=1&&c->phase!=2)||c->invalid)return;
 __asm__ volatile("mrs %0,cpsr":"=r"(cpsr));
 if((cpsr&0x9f)!=0x13||lr!=0x635e45b3||(sp&7)||sp<c->ti+512||sp>c->ti+8192-40||output!=sp+0x24)return;
 task=rd((sp&~8191u)+12);if(task!=c->task||!worker(c))return;
 caller=rd(sp+4);if(caller!=0x636ee16d&&caller!=0x636ee1a9)return;
 if(!common(c)){c->invalid=1;barrier();return;}
 if(registered()!=0){if(c->turn_seen){c->invalid=1;t->late_register=1;barrier();}return;}
 if(rd(c->monitor+8)!=3||!t->worker_armed||!t->worker_expected_payload||t->queue!=QID||t->type_snapshot!=0){c->invalid=1;barrier();return;}
 /* Native worker already executed command2 and free before this entry.
  * Early completion while native send has not returned is permitted. */
 c->turn_seen=1;barrier();t->worker_turn_done=1;c->phase=2;barrier();
}
int pp_disarm_before_send(struct pp_config*c){
 struct pd_submit*t=c->submit;u32 sp;__asm__ volatile("mov %0,sp":"=r"(sp));
 if(c->phase!=1||c->turn_seen||c->invalid||rd((sp&~8191u)+12)!=c->f3_task||!common(c)||
    t->submitted||t->local_committed||t->worker_armed||t->owned_payload||t->free_failed)return 0;
 c->phase=3;barrier();return 1;
}
