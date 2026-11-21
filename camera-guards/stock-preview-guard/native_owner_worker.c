/* Candidate only. Inherited private fds: 3 commands, 4 replies, 5 singleton
 * lock, 6 preallocated durable journal. Parent must qualify fd identities and
 * reserve all pages before exec. No USB, REC key, memory write or reset API.
 * A claimed transaction never self-retires on controller loss. */
#include "dial_owner.h"
typedef uint32_t u32;
extern void *dlopen(const char*,int);
extern void *dlsym(void*,const char*);
extern void (*signal(int,void(*)(int)))(int);
extern int siginterrupt(int,int);
typedef int(*dynamic_fn)(u32,u32,u32);
typedef int(*alloc_fn)(u32,void**,u32,u32);
typedef int(*send_fn)(u32,void*);
static dynamic_fn original_dynamic;
static alloc_fn original_allocate;
static send_fn original_send,original_free;
static volatile int cancelled;
static unsigned journal_seq;
static void soft_cancel(int signo){(void)signo;cancelled=1;}
static int sc4(u32 n,u32 a,u32 b,u32 c,u32 d){
 register u32 r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r3 __asm__("r3")=d,r7 __asm__("r7")=n;
 __asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r3),"r"(r7):"memory");return (int)r0;
}
static __attribute__((noreturn)) void leave(unsigned code){sc4(1,code,0,0,0);__builtin_unreachable();}
static int exact(unsigned op,unsigned fd,void*data,unsigned length){
 unsigned char*p=data;
 while(length){int n=sc4(op,fd,(u32)p,length,0);if(n==-4){if(cancelled)return -1;continue;}
  if(n<=0||(unsigned)n>length)return -1;p+=n;length-=(unsigned)n;}
 return 0;
}
static int dynamic(u32 op,u32 module,uintptr_t value){return original_dynamic(op,module,(u32)value);}
static int event(u32 kind,const u32*payload,u32 count){
 if(count!=8||journal_seq>=48)return -1;
 /* Each record is64B; journal is a physically preallocated4096B page. The
  * parent may read it independently even if its report pipe is lost. */
 u32 row[16]={0x31575053,++journal_seq,kind,8};
 for(unsigned i=0;i<8;i++)row[4+i]=payload[i];
 if(exact(4,6,row,sizeof row)||sc4(118,6,0,0,0))return -1;
 return 0;
}
static void reply(u32 sequence,const struct po_owner*p,int rc){
 u32 row[4]={0x31524750,sequence,p->phase,(u32)rc};
 (void)exact(4,4,row,sizeof row);
}
__attribute__((noreturn)) void _start(void){
 struct po_owner owner={0};
 struct po_api api={dynamic,0,0,0,event};
 if(signal(1,(void(*)(int))1)==(void(*)(int))-1||
    signal(13,(void(*)(int))1)==(void(*)(int))-1||
    signal(2,soft_cancel)==(void(*)(int))-1||
    signal(15,soft_cancel)==(void(*)(int))-1||siginterrupt(2,1)||siginterrupt(15,1))leave(70);
 for(unsigned fd=3;fd<=6;fd++)if(sc4(55,fd,1,0,0)<0)leave(71);
 void*lib=dlopen("libosal_uipc.so",2);if(!lib)leave(72);
 original_dynamic=(dynamic_fn)dlsym(lib,"osal_dynamic_id");
 original_allocate=(alloc_fn)dlsym(lib,"osal_valloc_msg_wait");
 original_send=(send_fn)dlsym(lib,"osal_snd_msg");
 original_free=(send_fn)dlsym(lib,"osal_free_msg");
 if(!original_dynamic||!original_allocate||!original_send||!original_free)leave(73);
 api.allocate=original_allocate;api.send=original_send;api.release=original_free;
 int rc=po_open(&owner,&api);reply(0,&owner,rc);
 if(rc&&owner.phase==PO_RETIRED)leave(74);
 unsigned expected=1;
 while(!rc&&!cancelled){
  u32 command[4];
  if(exact(3,3,command,sizeof command)){rc=po_lost(&owner,&api);break;}
  if(command[0]!=0x31434750||command[1]!=expected||command[3]){
   rc=po_lost(&owner,&api);break;
  }
  expected++;
  rc=po_command(&owner,&api,command[2]);reply(command[1],&owner,rc);
  if(owner.phase==PO_RETIRED)leave(rc?75:0);
 }
 if(cancelled)rc=po_lost(&owner,&api);
 if(owner.phase==PO_RETIRED)leave(rc?76:0);
 /* Do not let a dead supervisor, EOF, signal, failed send or log failure
  * release ownership or run a speculative RETURN. Keep the lock/source. */
 for(;;){u32 duration[2]={1,0};sc4(162,(u32)duration,0,0,0);}
}
