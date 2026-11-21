/* OFFLINE ONLY. No module, loader, message, MMIO, free or hardware call.
 * Requires module-owned immutable current-epoch profile and controller lock.
 * Queue/task lifetime must be the existing native F3/F5 mainloop lifetime;
 * concurrent task/queue destruction or system shutdown is outside this trial.
 * Neither historical bytes nor a stable pointer are a lifecycle reference.
 *
 * Linked flags4 W is pinned by the REAL native queue lock: native delivery
 * unlinks W before callback under that lock; the receiving task must acquire
 * the same lock before unlinking/returning. This validator is called only by
 * the single-try critical adapter while that lock remains held.
 */
#include "queue_waiter_witness.h"
extern volatile u32 wa_gate_active,wa_publication_live,wa_publication_epoch;
extern volatile u32 wa_tasks[4];
static u32 rd(u32 p){return *(volatile u32*)p;}
static int ram(u32 p,u32 n){return !(p&3)&&n&&p>=0x60100000u&&p<=0x78800000u-n;}
static int module(u32 p,u32 n){return !(p&3)&&n&&p>=0x5f000000u&&p<=0x60000000u-n;}
static int published(const struct qw_profile*p){
 return p->index<2&&p->epoch&&wa_gate_active==1&&wa_publication_live==1&&wa_publication_epoch==p->epoch&&
  rd(0x635c6278u)==p->wait_gateway&&rd(0x635c6294u)==p->receive_gateway&&
  wa_tasks[p->index*2]==p->task&&wa_tasks[p->index*2+1]==p->pid;
}
/* Exact existing-only high-ID path; never calls allocating queue_lookup. */
u32 qw_resolve(const struct qw_profile*p){
 u32 a,b,c;
 if(!published(p)||!module(p->osal_bss,0xd44)||!module(p->osal_text,0x36c4)||!module(p->liro_text,0xa98)||
    !ram(p->queue,32)||!ram(p->task,0x108)||!p->pid||!ram(p->ti,8192)||(p->ti&8191)||
    rd(p->task+8)!=p->ti||rd(p->task+0x104)!=p->pid||rd(p->ti+12)!=p->task)return 0;
 a=rd(p->osal_bss+0xc38+0x42*4);if(!ram(a,16))return 0;
 b=rd(a+3*4);if(!ram(b,28))return 0;
 c=rd(b+6*4);if(!ram(c,32))return 0;
 return rd(c+(p->index?5:3)*4)==p->queue?p->queue:0;
}
int qw_validate_locked(const struct qw_profile*p,struct qw_result*r){
 u32 q=p->queue,w,s,main=p->index?0x640f3f18u:0x64139e18u;
 u32 loop=p->index?0x639fa5d9u:0x639fc6c1u,qid=p->index?0x6800f5u:0x6800f3u;
 r->valid=0;r->reason=2;
 if(qw_resolve(p)!=q||!(rd(q)&0x80000000u))return 0;
 /* Only ordinary empty mainloop receive. Never traverse old tail or messages. */
 if(*(volatile u8*)(q+4)!=0||rd(q+12)!=0)return 0;
 w=rd(q+8);if(!ram(w,152)||w<p->ti+64||w>p->ti+8192-152)return 0;
 s=w+96;
 if((s&7)||rd(w)!=0||rd(w+8)!=p->osal_text+0x2774||
    *(volatile u8*)(w+12)!=0||*(volatile u8*)(w+13)!=4||rd(w+16)!=0||
    rd(w+20)!=p->task||rd(w+24)!=s+16||rd(s+16)!=0)return 0;
 /* Actual native frames, not a stale waiter signature from another receive. */
 if(rd(w+52)!=s-32||rd(w+56)!=p->liro_text+0xa88||
    rd(w+84)!=s||rd(w+88)!=0x635e45b3u||rd(w+96)!=main||
    rd(w+100)!=0x63aad761u||rd(w+148)!=loop||
    rd(w+36)!=s+16||rd(w+40)!=qid||rd(w+72)!=main+12||rd(main+4)!=qid)return 0;
 /* OSAL saved r5/r6 hold receive output/qid; LIRO's earlier saved r5
  * still holds the native AV container main+12. */
 __asm__ volatile("dmb sy":::"memory");
 if(!published(p))return 0;
 r->queue=q;r->waiter=w;r->task=p->task;r->pid=p->pid;r->ti=p->ti;
 r->recvslot=s+16;r->outer_sp=s;r->loop_lr=loop;r->epoch=p->epoch;
 r->reason=0;__asm__ volatile("dmb sy":::"memory");r->valid=1;return 1;
}
