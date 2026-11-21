/* Read-only original Backup API worker. Private fd3 requests/fd4 replies,
 * fd5 inherited exclusion lock. Native synchronous calls may block; parent
 * must retain this process, never kill/retry an ambiguous call. No write API. */
#include <stdint.h>
typedef uint32_t u32;
extern int*__errno_location(void);
extern void *dlopen(const char*,int);extern void *dlsym(void*,const char*);
extern void (*signal(int,void(*)(int)))(int);
static int sc(u32 n,u32 a,u32 b,u32 c){register u32 r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r7 __asm__("r7")=n;__asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r7):"memory");return(int)r0;}
static int exact(u32 op,u32 fd,void*p,u32 n){unsigned char*b=p;while(n){int z=sc(op,fd,(u32)b,n);if(z==-4)continue;if(z<=0||(u32)z>n)return -1;b+=z;n-=z;}return 0;}
static __attribute__((noreturn)) void quit(u32 n){sc(1,n,0,0);__builtin_unreachable();}
__attribute__((noreturn)) void _start(void){
 for(unsigned sig=1;sig<=15;sig++)if(sig==1||sig==2||sig==13||sig==15)if(signal(sig,(void(*)(int))1)==(void(*)(int))-1)quit(70);
 for(unsigned fd=3;fd<=5;fd++)if(sc(55,fd,1,0)<0)quit(71);
 /* libbackup DT_NEEDED omits its OSAL provider. Publish only the pinned
  * original provider in this private process before RTLD_NOW resolves it. */
 void*osal=dlopen("/usr/lib/libosal_uipc.so",0x102);if(!osal)quit(72);
 void*lib=dlopen("/usr/lib/libbackup.so",2);if(!lib)quit(72);
 int(*size)(u32)=(int(*)(u32))dlsym(lib,"Backup_get_datasize");
 int(*read)(u32,void*)=(int(*)(u32,void*))dlsym(lib,"Backup_read");
 if(!size||!read)quit(73);
 u32 sequence=1;
 for(;;){u32 q[4];if(exact(3,3,q,sizeof q))quit(0);
  if(q[0]!=0x31514250||q[1]!=sequence++||q[2]!=1||q[3])quit(74);
  /* First8 words retain the original reply prefix; suffix records independent
   * rc/errno/canary for each key, followed by their size errno values.
   * Unattempted fields are explicit sentinels, never fabricated successes. */
  u32 response[16]={0x31524250,q[1],0,0xffffffff,0xffffffff,0,0,0xffffffff,
   0x80000000,0xffffffff,0xa5a5a5ff,0x80000000,0xffffffff,0xa5a5a5ff,0xffffffff,0xffffffff};
  const u32 keys[2]={0x010708bf,0x01071a8e};
  for(unsigned k=0;k<2;k++){
   *__errno_location()=0;int n=size(keys[k]);response[14+k]=(u32)*__errno_location();response[5+k]=(u32)n;
   if(n!=1){response[2]=1;break;}
   /* Guard canary: service may write exactly its queried one-byte size. */
   u32 value=0xa5a5a5ff;*__errno_location()=0;int rc=read(keys[k],&value);int error=*__errno_location();response[7]=(u32)rc;
   response[8+3*k]=(u32)rc;response[9+3*k]=(u32)error;response[10+3*k]=value;
   if(rc!=1||(value&0xffffff00)!=0xa5a5a500){response[2]=2;break;}
   response[3+k]=value&255;
  }
  if(exact(4,4,response,sizeof response))quit(75);
 }
}
