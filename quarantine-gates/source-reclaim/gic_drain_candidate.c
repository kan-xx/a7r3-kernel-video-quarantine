/* OFFLINE candidate, not linked into a deployable module.
 * One serialized recovery owner must hold the REAL source-stop / no-restart
 * lease and both H admissions before use. Those receipts are NOT implemented
 * here. A quiet result is only the IRQ portion of a larger reclaim protocol.
 * Native software admission stays enabled so a late genuine IRQ can execute
 * its original callback and LIRO EOI. No pending clear, INTACK, fake EOI,
 * callback invocation, Linux disabled-bit write, or buffer operation exists.
 */
typedef unsigned int u32;
struct gd_profile {u32 desc,irq,action,handler,callback,chip,chipdata;};
struct gd_receipt {u32 attempts,masked,quiet,failed,last_pending,last_active,last_line,last_state;};
extern int sr_irq_lock_try(u32,u32*);
static u32 rd(u32 a){return *(volatile u32*)a;}
static void sync(void){__asm__ volatile("dsb sy":::"memory");}
static void unlock(u32 d,u32 f){((void(*)(u32,u32))0x603b747c)(d+0x50,f);}
static int valid_irq(u32 n){return n==35||n==36||n==37||n==40||n==44;}
static int same(const struct gd_profile*p){
 u32 d=p->desc,a=p->action,c=p->chip;
 return valid_irq(p->irq)&&d==0x604a83e0+p->irq*160&&rd(d)==p->irq&&
 rd(d+16)==c&&rd(d+28)==p->chipdata&&rd(d+44)==0x601750d4&&rd(d+48)==a&&
 rd(a)==p->handler&&rd(a+4)==0x10020&&rd(a+8)==p->callback&&rd(a+12)==0&&
 rd(a+16)==p->irq&&!rd(a+20)&&!rd(a+24)&&
 rd(d+60)==1&&(rd(d+52)&0x1000)&&!(rd(d+12)&0x10000)&&
 !rd(c+12)&&!rd(c+16)&&rd(c+24)==0x6011ad78&&rd(c+32)==0x6011adcc&&
 !rd(c+56)&&!rd(c+60)&&!rd(0x604e0998)&&!rd(0x604e09a0)&&
 !rd(p->chipdata)&&rd(p->chipdata+4)==0xf8001000;
}
/* 0=bounded retry with ORIGINAL delivery enabled; 1=masked quiet observation;
 * 2=lock busy; 3=refused/attempt limit. At most eight attempts, no loop/wait.
 * Identity has to be freshly qualified before passing this profile; a wrong
 * raw pointer is not made safe merely by checking its fields here.
 * A previous quiet receipt remains masked; subsequent calls revalidate it.
 * A foreign mask before our first action is refused, not claimed as ours.
 */
int gd_drain_once(const struct gd_profile*p,struct gd_receipt*r){
 u32 d=p->desc,f,bit,en,pending,active,line,state;
 if(r->failed||r->attempts>=8||!valid_irq(p->irq)||d!=0x604a83e0+p->irq*160){r->failed=1;r->quiet=0;return 3;}
 r->attempts++;r->quiet=0;
 if(!sr_irq_lock_try(d+0x50,&f))return 2;
 if(!same(p)){r->failed=1;unlock(d,f);return 3;}
 bit=1u<<(p->irq-32);en=rd(0xf8001104);
 if((!(en&bit)&&!r->masked)||((en&bit)&&r->masked)){r->failed=1;unlock(d,f);return 3;}
 ((void(*)(u32))0x6011ad78)(d);sync();r->masked=1;
 en=rd(0xf8001104);pending=rd(0xf8001204)&bit;active=rd(0xf8001304)&bit;line=rd(0xf8001d04)&bit;sync();
 state=rd(d+12);r->last_pending=pending;r->last_active=active;r->last_line=line;r->last_state=state;
 if(!(en&bit)&&!pending&&!active&&!line&&!(state&0x40000)&&!rd(d+100)){
  r->quiet=1;unlock(d,f);return 1;
 }
 /* Preserve the original native handler/EOI path. The caller must yield to
  * original execution; calling this eight times in a nonpreemptible loop is
  * not a valid controller. A final refusal never authorizes Release.
  */
 ((void(*)(u32))0x6011adcc)(d);sync();r->masked=0;
 if(r->attempts==8)r->failed=1;
 unlock(d,f);return r->failed?3:0;
}
/* Before any actual Release, a controller may abandon an unused IRQ-only
 * receipt and restore native delivery. Once any downstream resource has been
 * released this function MUST NOT be called; that authorization is external.
 */
int gd_cancel_unused_once(const struct gd_profile*p,struct gd_receipt*r){
 u32 d=p->desc,f;
 if(!r->masked)return 1;
 if(!sr_irq_lock_try(d+0x50,&f))return 2;
 if(!same(p)){r->failed=1;unlock(d,f);return 3;}
 ((void(*)(u32))0x6011adcc)(d);sync();r->masked=0;r->quiet=0;
 unlock(d,f);return 0;
}
