/* Offline-only bounded MBF append adapter. One controller, one outstanding
 * permanent marker, already qualified same-generation worker/MBF/profile.
 * Caller must close actual PIG/source producers before treating marker entry
 * as a boundary for their older callbacks. This does not stop descendants.
 */
typedef unsigned int u32;
struct pqd_profile {u32 handle,row,object,liro_text,liro_bss;};
static u32 rd(u32 a){return *(volatile u32*)a;}
static int ram(u32 a,u32 n){return !(a&3)&&a>=0x60100000&&n&&a+n>a&&a+n<=0x78800000;}
static int inside(u32 a,u32 b,u32 n){return !(a&3)&&a>=b&&a<=b+n-4;}
static void unlock(u32 t,u32 r){((void(*)(u32))(t+0x1198))(r);}
/* 0=native inline copy committed to FIFO;1=lock busy/no change;
 * 2=receiver parked: require separate original waiter witness, no enqueue;
 * 3=refuse/no change. Does not invoke wake_up_process or allocate anything.
 * No queue count/head/tail is manufactured; original append writes all links.
 */
int pqd_append_marker_once(const struct pqd_profile*p,const u32 marker[7]){
 u32 o=p->object,t=p->liro_text,r=p->row,b,n,h,tail,free;
 if(!p->handle||p->handle>128||t<0x5f000000||t>=0x60000000||(t&4095)||
 p->liro_bss<0x5f000000||p->liro_bss>=0x60000000||
 r!=p->liro_bss+0x1278+8*(p->handle-1)||!ram(o,0x44))return 3;
 if(!((int(*)(u32))(t+0x1110))(r))return 1;
 if(rd(r+4)!=o||!rd(o)||rd(o+0xc)!=28||rd(o+0x18)!=o+0x18||rd(o+0x1c)!=o+0x18){unlock(t,r);return 3;}
 if(rd(o+0x24)!=o+0x24||rd(o+0x28)!=o+0x24){unlock(t,r);return 2;}
 b=rd(o+0x14);n=rd(o+0x10);h=rd(o+0x34);tail=rd(o+0x38);free=rd(o+0x40);
 if(n<32||n>0x100000||(n&3)||!ram(b,n)||!inside(rd(o+0x30),b,n)||free<32||free>n||
 (h&&(!inside(h,b,n)||!inside(tail,b,n)))){unlock(t,r);return 3;}
 ((void(*)(u32,const u32*,u32))(t+0x46a4))(o,marker,28);
 unlock(t,r);return 0;
}
struct pqd_worker {u32 task,ti,tcb,native_tid;};
/* 0=no complete witness,1=original worker's next-receive registered,
 * 2=lock busy,3=identity refusal. Does not wake or park the worker itself.
 * A registered receive can be just before schedule; that still follows the
 * return of its previous callback. This does not grant hardware/DMA release.
 */
int pqd_receive_witness_once(const struct pqd_profile*p,const struct pqd_worker*w){
 u32 t=p->liro_text,r=p->row,o=p->object,node,ok=0,sp;
 __asm__ volatile("mov %0,sp":"=r"(sp));
 if(!p->handle||p->handle>128||t<0x5f000000||t>=0x60000000||(t&4095)||
 p->liro_bss<0x5f000000||p->liro_bss>=0x60000000||r!=p->liro_bss+0x1278+8*(p->handle-1)||
 !ram(o,0x44)||!ram(w->task,0x3c8)||!ram(w->ti,8192)||(w->ti&8191)||!ram(w->tcb,0x98)||
 !w->native_tid||w->native_tid>255||(sp&~8191)==w->ti)return 3;
 if(!((int(*)(u32))(t+0x1110))(r))return 2;
 if(rd(r+4)!=o||!rd(o)||rd(o+12)!=28||rd(w->task+8)!=w->ti||rd(w->ti+12)!=w->task||rd(w->ti+0x60)!=w->tcb||
 rd(w->tcb+20)!=w->task||rd(w->tcb+24)!=w->native_tid||rd(w->task+0x3c4)!=w->native_tid){unlock(t,r);return 3;}
 node=rd(o+0x24);
 if(!rd(o+0x34)&&rd(o+0x18)==o+0x18&&rd(o+0x1c)==o+0x18&&
 node>=w->ti+0x80&&node<=w->ti+8192-0x8c&&!(node&3)&&rd(o+0x28)==node&&
 rd(node)==o+0x24&&rd(node+4)==o+0x24&&rd(node+8)==w->tcb&&rd(node+0x10)==0&&
 rd(node+0x14)==node+0x18&&rd(node+0x18)==o&&rd(node+0x20)==0&&rd(node+0x24)==node+0x70&&
 rd(node+0x4c)==0x635e41a7&&rd(node+0x58)==0x63d102b7&&rd(node+0x60)==0x6395b453&&
 rd(w->tcb+0x90)==o+0x24&&rd(w->tcb+0x94)==r)ok=1;
 unlock(t,r);return ok;
}
