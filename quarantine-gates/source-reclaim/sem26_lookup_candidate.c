/* Offline-only native LIRO semaphore lookup replacement. The unchanged native
 * twai_sem(timeout0)/sig_sem continuations perform token transfer and release.
 * This helper substitutes one raw trylock for the original unbounded os_lock.
 * It does not write semaphore count or wake/complete any waiter itself.
 * Profile/code/epoch must be qualified before any future packaging.
 */
typedef unsigned int u32;
struct sl_profile {u32 text,bss,row,object;};
static u32 rd(u32 a){return *(volatile u32*)a;}
static int ram(u32 a,u32 n){return !(a&3)&&a>=0x60100000&&a+n>a&&a+n<=0x78800000;}
int sl_lookup_once(u32 handle,u32*out,const struct sl_profile*p){
 u32 o=p->object,t=p->text,r=p->row,count,max,refs;
 if(handle!=26||t<0x5f000000||t>=0x60000000||(t&4095)||
 p->bss<0x5f000000||p->bss>=0x60000000||r!=p->bss+0x580+25*8||!ram(o,32))return -17;
 if(!((int(*)(u32))(t+0x1110))(r))return -50;
 /* The row may have been deleted/recreated since the readonly profile.
  * Check its current pointer before dereferencing the old object. */
 if(rd(r+4)!=o){((void(*)(u32))(t+0x1198))(r);return -42;}
 count=rd(o+12);max=rd(o+16);refs=rd(o);
 if(!refs||refs==0xffffffffu||max!=1||count>max){
  ((void(*)(u32))(t+0x1198))(r);return -42;
 }
 /* Exact original lookup semantics while owning the original row lock:
  * establish a temporary object reference, output the current object, leave
  * the lock held for the original continuation/release helper183c.
  */
 *(volatile u32*)o=refs+1;*out=o;return 0;
}
