/* Candidate primitive, not a module or deployed recovery API.
 * It creates its own disable receipt under the real descriptor lock. Identity
 * profile must first pass the separate parent-reviewed current read package.
 * This joins kernel action execution only; it does NOT drain hardware pending
 * IRQ state or downstream work and does NOT authorize any buffer Release.
 */
typedef unsigned int u32;
struct sr_irq_profile {u32 desc,irq,action,handler,callback,chip,chipdata;};
struct sr_irq_receipt {struct sr_irq_profile p;u32 active,joined;};
extern int sr_irq_lock_try(u32,u32*);
static u32 rd(u32 a){return *(volatile u32*)a;}
static void unlock(u32 d,u32 f){((void(*)(u32,u32))0x603b747c)(d+0x50,f);}
static int same(const struct sr_irq_profile*p){
 u32 a=p->action,d=p->desc;
 return (p->irq>=35&&p->irq<=37&&d==0x604a83e0+p->irq*160&&rd(d)==p->irq&&rd(d+0x10)==p->chip&&rd(d+0x1c)==p->chipdata&&rd(d+0x2c)==0x601750d4&&rd(d+0x30)==a&&rd(a)==p->handler&&rd(a+4)==0x10020&&rd(a+8)==p->callback&&rd(a+12)==0&&rd(a+16)==p->irq&&rd(a+20)==0&&rd(a+24)==0);
}
/* 0=owns native software-disable and GIC-mask receipt; 1=busy/no change;
 * 2=identity/state refusal/no change. Caller keeps this receipt, not a cookie.
 * Common source/producer exclusion and native GIC extension qualification
 * are additional required external preconditions, not supplied by this code.
 */
int sr_irq_disable_once(const struct sr_irq_profile*p,struct sr_irq_receipt*r){
 u32 flags,d=p->desc,disable;
 if(r->active||d!=0x604a83e0+p->irq*160||p->irq<35||p->irq>37)return 2;
 if(!sr_irq_lock_try(d+0x50,&flags))return 1;
 disable=rd(p->chip+0x10);
 if(!same(p)||rd(d+0x3c)!=0||(rd(d+12)&0x10000)||rd(p->chip+0x18)!=0x6011ad78||rd(p->chip+0x20)!=0x6011adcc||rd(p->chip+0x38)||rd(p->chip+0x3c)||rd(0x604e0998)||(disable&&disable!=0x6011ad78)){
  unlock(d,flags);return 2;
 }
 ((void(*)(u32,u32,u32))0x60173e80)(d,p->irq,0);
 if(!disable)((void(*)(u32))0x601755e4)(d);
 r->p=*p;r->joined=0;r->active=1;
 unlock(d,flags);return 0;
}
/* 0=still executing,1=kernel action joined,2=busy,3=identity/receipt broken.
 * No spinning, no waiting, no descriptor state writes, no synthetic completion.
 */
int sr_irq_join_once(struct sr_irq_receipt*r){
 u32 flags,d=r->p.desc,state,ok;
 if(!r->active)return 3;
 if(!sr_irq_lock_try(d+0x50,&flags))return 2;
 if(!same(&r->p)||rd(d+0x3c)!=1||!(rd(d+12)&0x10000)){
  unlock(d,flags);return 3;
 }
 state=rd(d+12);ok=!(state&0x40000)&&!rd(d+0x64);
 if(ok)r->joined=1;
 unlock(d,flags);return ok?1:0;
}
