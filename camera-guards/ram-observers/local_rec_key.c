/* One body MOVIE key tap (KEY_TACT_STARTSTOP 0x1f0) on the owner camera.
 * Reconstructed from RcInputRec/InfraInputUtil::SendEvtToInput.
 * This is the original REC key toggle, not a codec test command. Only the original OSAL allocator/sender and owned dynamic-ID
 * APIs are called. All message buffers are prepared before any press.
 * This build has no alternate key mode. No firmware/file/memory
 * write interfaces, full remote-stack initializer or other-process pointers.
 */
typedef unsigned u32;
extern void *dlopen(const char *,int);
extern void *dlsym(void *,const char *);
extern void (*signal(int,void (*)(int)))(int);
extern int siginterrupt(int,int);
typedef int (*dynamic_fn)(u32,u32,u32);
typedef int (*alloc_fn)(u32,void **,u32,u32);
typedef int (*send_fn)(u32,void *);
typedef int (*free_fn)(u32,void *);
static volatile int timeout_requested;
static void input_timeout(int signo) { (void)signo;timeout_requested=1; }
static int sc4(u32 n,u32 a,u32 b,u32 c,u32 d) {
 register u32 r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r3 __asm__("r3")=d,r7 __asm__("r7")=n;
 __asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r3),"r"(r7):"memory");return (int)r0;
}
static __attribute__((noreturn)) void finish(u32 *out,u32 code) {
 sc4(4,1,(u32)out,64,0);sc4(1,code,0,0,0);__builtin_unreachable();
}
__attribute__((noreturn)) void _start(void) {
 u32 out[16]={0x31504853,0,0xffffffff,0,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff};
 u32 timer[4]={0,0,6,0},mask[2]={1u<<13,0};
 struct {u32 before,id,after;} own={0x13579bdf,0,0x2468ace0};
 if(signal(14,(void(*)(int))0)==(void(*)(int))-1 || sc4(175,1,(u32)mask,0,8) || sc4(104,0,(u32)timer,0,0))finish(out,70);
 void *lib=dlopen("libosal_uipc.so",2);if(!lib)finish(out,71);
 dynamic_fn dynamic=(dynamic_fn)dlsym(lib,"osal_dynamic_id");
 alloc_fn allocate=(alloc_fn)dlsym(lib,"osal_valloc_msg_wait");
 send_fn send=(send_fn)dlsym(lib,"osal_snd_msg");
 free_fn free_message=(free_fn)dlsym(lib,"osal_free_msg");
 if(!dynamic || !allocate || !send || !free_message)finish(out,72);
 int rc=dynamic(0x29,0x172,(u32)&own.id);
 out[2]=(u32)rc;out[3]=own.id;out[10]=own.before;out[11]=own.after;
 if(rc)finish(out,73);
 if(own.before!=0x13579bdf || own.after!=0x2468ace0 || (own.id>>16)!=0x172 ||
    !(own.id&0x8000) || (own.id&0x7fff)<0x6000 || (own.id&0x7fff)>=0x7000)finish(out,74);
 out[1]=1;
const u32 physical[2]={0x000001f0,0x000001f0};
 const u32 state[2]={1,0};
 const u32 count=2;
 out[9]=3;

 u32 *messages[4]={0,0,0,0};u32 prepared=0;
 for(u32 i=0;i<count;i++) {
  rc=allocate(0x007a0020,(void **)&messages[i],16,1);
  if(rc || !messages[i] || ((u32)messages[i]&3)) {
   out[12]=(u32)rc;out[13]=i;
   for(u32 j=0;j<prepared;j++)free_message(0x007a0020,messages[j]);
   out[8]=(u32)dynamic(0x49,0,own.id);finish(out,75);
  }
  prepared++;
  messages[i][0]=physical[i];messages[i][1]=0;
  messages[i][2]=state[i];messages[i][3]=0;
  messages[i][-1]=own.id;
 }
 /* A hard timeout is suitable before any press. During the two-event
  * sequence it would itself risk cutting off key-up. Use an async-signal-safe
  * flag and interruptible ioctl instead; never abort the remaining releases.
  * An uninterruptible kernel wait still has no software deadline guarantee.
  */
 u32 soft_timer[4]={1,0,6,0};
 if(signal(14,input_timeout)==(void(*)(int))-1 || siginterrupt(14,1) ||
    sc4(104,0,(u32)soft_timer,0,0) || timeout_requested) {
  for(u32 j=0;j<prepared;j++)free_message(0x007a0020,messages[j]);
  out[8]=(u32)dynamic(0x49,0,own.id);finish(out,78);
 }
 out[1]=2;out[13]=count;
 /* Preserve the exact owned source before key-down, so the host can inspect
  * progress without blocking on this process. A final64B record follows. */
 if(sc4(4,1,(u32)out,64,0)!=64) {
  for(u32 j=0;j<prepared;j++)free_message(0x007a0020,messages[j]);
  out[8]=(u32)dynamic(0x49,0,own.id);finish(out,79);
 }
 /* Never stop between press and release on a send error. Treat every passed
  * buffer as submitted; no guessed free/double-free after a failed sender.
  */
 u32 failed=0;
 for(u32 i=0;i<count;i++) {
  rc=send(0x007a0020,messages[i]);out[4+i]=(u32)rc;out[15]=i+1;if(rc)failed=1;
  /* Current key config has 100 ms. Keep the press for 150 ms, then always
   * attempt release. A signal interrupts the delay but never skips key-up. */
  if(i==0){u32 tap[2]={0,150000000},left[2];sc4(162,(u32)tap,(u32)left,0,0);}
 }
 out[1]=3;
 out[14]=(u32)timeout_requested;
 /* Keep the soft handler: restoring SIG_DFL could act on an already pending
  * critical-phase alarm. Stop periodic delivery before the source hold. */
 u32 stopped_timer[4]={0,0,0,0};
 if(sc4(104,0,(u32)stopped_timer,0,0))finish(out,80);
 /* Keep our source alive briefly after the complete key-up sequence. */
 u32 pause[2]={1,0},remaining[2];
 while(sc4(162,(u32)pause,(u32)remaining,0,0)==-4) {
  pause[0]=remaining[0];pause[1]=remaining[1];
 }
 out[8]=(u32)dynamic(0x49,0,own.id);
 out[1]=4;
 finish(out,failed?76:out[8]?77:timeout_requested?81:0);
}
