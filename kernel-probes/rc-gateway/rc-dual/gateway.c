/* OFFLINE CANDIDATE. No upload/load. Both gateways remain resident all boot.
 * Only immutable identity records: no sensor-fps or hardware-recovery claim. */
typedef unsigned int u32; typedef unsigned char u8;
typedef u32 (*build_fn)(u32,u32,u32,u32,u32,u32,u32,u32);
typedef u32 (*complete_fn)(u32,u32,u32,u32*,u32);
#include "anchors.h"
#define B_SLOT ((volatile u32*)0x64696efcu)
#define C_SLOT ((volatile u32*)0x64696ed4u)
#define B_ORIG 0x63a3205du
#define C_ORIG 0x63d5f5e9u
#define BACK 0x6438e4ecu
#define CAP 64u
#define ARMED 1u
#define SEALED 2u
#define REFUSED 3u
#define PRE_ROUTE 1u
#define STACK_OK 2u
#define EC_OK 4u
#define POST_SEQ 8u
#define TAG_SAME 16u
#define UNIT_SAME 32u
#define STATUS_OK 64u
#define PARAMS_OK 128u
#define CONTROLLER_OK 256u
struct event {
 volatile u32 committed;
 u32 kind,flags,error,args[8],sp,lr,callers[4],ec,sequence,job;
 u32 epoch[2],driver[2],state[2],controller,cflags,input_status,output_status;
 u32 status_valid,status_value,ec_mode,controller_index,controller_index_after;
 u32 tag_before[3],tag_after[3],unit_before[10],unit_after[10];
 u32 input_pair[2],output_list[9],params[50];
 u32 input_desc[14],output_desc[14],tail[20];
};
struct state {
 u32 magic,version,capacity,event_bytes;
 volatile u32 phase,reserved,dropped,restore_build,restore_complete;
 u32 no_unload,build_gateway,complete_gateway,ever_published,install_result;
 u32 upstream_complete_proved,timestamp_qualified;
 struct event events[CAP];
};
__attribute__((section(".data.rcdual"),aligned(64),used))
struct state rcdual_state={0x52434432u,2,CAP,sizeof(struct event),0,0,0,0,0,1,0,0,0,0,0,0,{{0}}};
void rcdual_build(void); void rcdual_complete(void);
static __inline__ void barrier(void){__asm__ volatile("dmb sy":::"memory");}
static __inline__ int cas(volatile u32*p,u32 old,u32 next,u32*seen){
 u32 v,f;
 __asm__ volatile("ldrex %0,[%2]\n cmp %0,%3\n bne 1f\n strex %1,%4,[%2]\n b 2f\n1: clrex\n mov %1,#2\n2:"
 :"=&r"(v),"=&r"(f):"r"(p),"r"(old),"r"(next):"cc","memory");*seen=v;return(int)f;
}
static u32 exchange(volatile u32*p,u32 from,u32 to){
 u32 n,v;int r;for(n=0;n<4;n++){r=cas(p,from,to,&v);if(!r||v==to){barrier();return 1;}if(r==2)return 2;}return 3;
}
static void seal(void){
 rcdual_state.phase=SEALED;barrier();
 rcdual_state.restore_build=exchange(B_SLOT,(u32)&rcdual_build,B_ORIG);
 rcdual_state.restore_complete=exchange(C_SLOT,(u32)&rcdual_complete,C_ORIG);
}
static struct event*reserve(void){
 u32 n,old,seen;for(n=0;n<4;n++){
  if(rcdual_state.phase!=ARMED)return (struct event*)0;
  old=rcdual_state.reserved;if(old>=CAP){seal();return (struct event*)0;}
  if(!cas(&rcdual_state.reserved,old,old+1,&seen))return &rcdual_state.events[old];
 }rcdual_state.dropped=1;return (struct event*)0;
}
static void commit(struct event*e){u32 index=(u32)(e-rcdual_state.events);barrier();e->committed=index+1;if(index==CAP-1)seal();}
static u32 rd(u32 p){return *(volatile u32*)p;}
static void copy(u32*d,u32 p,u32 n){u32 i;for(i=0;i<n;i++)d[i]=rd(p+4*i);}
static int equal(const u32*a,const u32*b,u32 n){u32 i;for(i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int ram(u32 p,u32 n){return !(p&3u)&&n&&p>=0x62e68000u&&p<0x648c6000u&&n<=0x648c6000u-p;}
static int stack(u32 s,u32 bytes){return !(s&7u)&&s>=0x60100000u&&s<=0x78800000u-bytes&&((s&~4095u)==((s+bytes-1)&~4095u));}
static int seq(u32 payload){return payload>=0x6438a8f0u&&payload<0x6438a8f0u+22u*376u&&(payload-0x6438a8f0u)%376u==0;}
static u32 route(u32 backend,u32 interface){if(backend!=BACK)return 0;if(interface==0x6438ca50u)return 6;if(interface==0x6438cd88u)return 9;return 0;}
static void sequence_before(struct event*e){u32 s=e->sequence;e->epoch[0]=rd(s+0x16c);e->driver[0]=rd(s+0x160);e->state[0]=rd(s+0x174);}
static void sequence_after(struct event*e){
 u32 s=e->sequence,p=s+8;e->epoch[1]=rd(s+0x16c);e->driver[1]=rd(s+0x160);e->state[1]=rd(s+0x174);
 if(rd(s+0x170)==e->job&&e->epoch[0]==e->epoch[1])e->flags|=POST_SEQ;
 copy(e->input_desc,p+0xc,14);copy(e->output_desc,p+0x64,14);copy(e->tail,p+0xf8,20);
}
/* The chain gate permits reads only from fixed words in one proven stack page.
 * EC values remain candidates: bounded RAM + source chain is not Unit ownership. */
static u32 owner(struct event*e,u32 params){
 u32 s=e->sp,ec,last;if(e->lr!=0x63a27241u||!stack(s,0xd8))return 0;
 e->callers[0]=rd(s+0x4c);e->callers[1]=rd(s+0x6c);e->callers[2]=rd(s+0x7c);
 if(e->callers[0]!=0x63a1f61bu||e->callers[1]!=0x63d5a52fu)return 0;
 if(e->callers[2]==0x63929e27u){
  last=rd(s+0xd4);e->callers[3]=last;
  if(last!=0x63934fe1u&&last!=0x63d2d5cbu&&last!=0x63d2d693u)return 0;
  if(params!=0x64352ad0u)return 0;ec=rd(s+0xb4);
 }else if(e->callers[2]==0x639295b7u){
  last=rd(s+0xb4);e->callers[3]=last;
  if(last!=0x639338bfu&&last!=0x63d2d661u)return 0;
  if(params!=0x64352900u)return 0;ec=rd(s+0x94);
 }else return 0;
 e->flags|=STACK_OK;if(!ram(ec,0x838))return 0;return ec;
}
__attribute__((noinline,used))
u32 rcdual_build_body(u32 b,u32 i,u32 p,u32 d,u32 cb,u32 alt,u32 payload,u32 scratch,u32 sp,u32 lr){
 struct event*e=0;u32 error,j=route(b,i),ec=0;
 if(j&&seq(payload)){
  e=reserve();if(e){e->kind=1;e->sp=sp;e->lr=lr;e->sequence=payload-8;e->job=j;
   e->args[0]=b;e->args[1]=i;e->args[2]=p;e->args[3]=d;e->args[4]=cb;e->args[5]=alt;e->args[6]=payload;e->args[7]=scratch;
   if(rd(e->sequence+0x170)==j){
    e->flags|=PRE_ROUTE;sequence_before(e);ec=owner(e,p);e->ec=ec;
    if(ec&&cb==0x63928b45u&&ram(p,200)){
     e->flags|=EC_OK;copy(e->tag_before,ec+0x19c,3);copy(e->unit_before,ec+0x1c,10);
     copy(e->input_pair,ec+0x73c,2);copy(e->output_list,ec+0x808,9);copy(e->params,p,50);e->ec_mode=rd(ec+0x1b0);
     if(equal(e->output_list,e->params+23,9))e->flags|=PARAMS_OK;
    }else ec=0;
   }
  }
 }
 error=((build_fn)B_ORIG)(b,i,p,d,cb,alt,payload,scratch);
 if(e){e->error=error;if(e->flags&PRE_ROUTE)sequence_after(e);
  if(ec){copy(e->tag_after,ec+0x19c,3);copy(e->unit_after,ec+0x1c,10);if(equal(e->tag_before,e->tag_after,3))e->flags|=TAG_SAME;if(equal(e->unit_before,e->unit_after,10))e->flags|=UNIT_SAME;}
  commit(e);
 }return error;
}
__attribute__((noinline,used))
u32 rcdual_complete_body(u32 b,u32 i,u32 payload,u32*status,u32 job,u32 sp,u32 lr){
 struct event*e=0;u32 error,j=route(b,i);
 if(j==job&&j&&seq(payload)){
  e=reserve();if(e){e->kind=2;e->sp=sp;e->lr=lr;e->sequence=payload-8;e->job=j;
   e->args[0]=b;e->args[1]=i;e->args[2]=payload;e->args[3]=(u32)status;e->args[4]=job;
   if(rd(e->sequence+0x170)==j&&rd(e->sequence+0x160)==BACK){e->flags|=PRE_ROUTE;sequence_before(e);}
  }
 }
 error=((complete_fn)C_ORIG)(b,i,payload,status,job);
 if(e){e->error=error;if(e->flags&PRE_ROUTE){
   sequence_after(e);e->controller=j==6?0x64167720u:0x64167870u;
   /* All controller reads are exact static ordinaryRAM fields; never +118 MMIO. */
   e->controller_index=rd(e->controller+0x80);
   if(rd(e->controller)==0x64696798u&&rd(e->controller+0x118)==i&&rd(e->controller+0x84)==2&&e->controller_index<2&&rd(e->controller+0x60+4*e->controller_index)==e->sequence){
    e->cflags=rd(e->controller+0x8c);e->input_status=rd(e->controller+0x120);e->output_status=rd(e->controller+0x124);
    e->controller_index_after=rd(e->controller+0x80);if(e->controller_index_after==e->controller_index)e->flags|=CONTROLLER_OK;
    if(lr==0x63a2bdc3u&&stack(sp,0x54)&&(u32)status==sp+0x50){
     e->callers[0]=rd(sp+0x2c);if(e->callers[0]==0x63a2a29du){e->status_value=rd((u32)status);e->status_valid=1;e->flags|=STATUS_OK;}
    }
   }
  }commit(e);
 }return error;
}
__attribute__((section(".init.text"),used)) int init_module(void){
 u32 k,n,r;for(k=0;k<sizeof(anchors)/sizeof(anchors[0]);k++)for(n=0;n<anchors[k].n;n++)if(((volatile u8*)anchors[k].va)[n]!=anchors[k].bytes[n])return -22;
 rcdual_state.build_gateway=(u32)&rcdual_build;rcdual_state.complete_gateway=(u32)&rcdual_complete;barrier();
 r=exchange(C_SLOT,C_ORIG,(u32)&rcdual_complete);
 if(r!=1){rcdual_state.phase=REFUSED;rcdual_state.install_result=1;return -16;}
 rcdual_state.ever_published=1;barrier();
 r=exchange(B_SLOT,B_ORIG,(u32)&rcdual_build);
 if(r!=1){seal();rcdual_state.phase=REFUSED;rcdual_state.install_result=2;return 0;}
 rcdual_state.ever_published=3;rcdual_state.install_result=3;barrier();rcdual_state.phase=ARMED;barrier();return 0;
}
__asm__(
".pushsection .text.rcdual_build,\"ax\",%progbits\n.balign 4\n.arm\n.global rcdual_build\n.type rcdual_build,%function\n"
"rcdual_build:\n ldr ip,=0x63a27241\n cmp lr,ip\n bne .Lbuild_forward\n ldr ip,=0x6438e4ec\n cmp r0,ip\n bne .Lbuild_forward\n ldr ip,=0x6438ca50\n cmp r1,ip\n beq .Lbuild_stack\n ldr ip,=0x6438cd88\n cmp r1,ip\n bne .Lbuild_forward\n.Lbuild_stack:\n ubfx ip,sp,#0,#12\n cmp ip,#1024\n blo .Lbuild_forward\n push {r4,lr}\n add r4,sp,#8\n sub sp,sp,#24\n"
"ldr ip,[r4]\n str ip,[sp]\n ldr ip,[r4,#4]\n str ip,[sp,#4]\n ldr ip,[r4,#8]\n str ip,[sp,#8]\n ldr ip,[r4,#12]\n str ip,[sp,#12]\n str r4,[sp,#16]\n ldr ip,[r4,#-4]\n str ip,[sp,#20]\n bl rcdual_build_body\n add sp,sp,#24\n pop {r4,pc}\n.Lbuild_forward:\n ldr ip,=0x63a3205d\n bx ip\n.ltorg\n.size rcdual_build,.-rcdual_build\n.popsection\n"
".pushsection .text.rcdual_complete,\"ax\",%progbits\n.balign 4\n.arm\n.global rcdual_complete\n.type rcdual_complete,%function\n"
"rcdual_complete:\n ldr ip,=0x63a2bdc3\n cmp lr,ip\n bne .Lcomplete_forward\n ldr ip,=0x6438e4ec\n cmp r0,ip\n bne .Lcomplete_forward\n ldr ip,=0x6438ca50\n cmp r1,ip\n beq .Lcomplete_stack\n ldr ip,=0x6438cd88\n cmp r1,ip\n bne .Lcomplete_forward\n.Lcomplete_stack:\n ubfx ip,sp,#0,#12\n cmp ip,#1024\n blo .Lcomplete_forward\n push {r4,lr}\n add r4,sp,#8\n sub sp,sp,#16\n ldr ip,[r4]\n str ip,[sp]\n str r4,[sp,#4]\n ldr ip,[r4,#-4]\n str ip,[sp,#8]\n bl rcdual_complete_body\n add sp,sp,#16\n pop {r4,pc}\n.Lcomplete_forward:\n ldr ip,=0x63d5f5e9\n bx ip\n.ltorg\n.size rcdual_complete,.-rcdual_complete\n.popsection\n"
".pushsection .gnu.linkonce.this_module,\"aw\",%progbits\n.balign 4\n.global __this_module\n.type __this_module,%object\n__this_module:\n.zero 12\n.asciz \"a7r3_rcdual_1101a\"\n.zero 188-(.-__this_module)\n.word init_module\n.zero 316-(.-__this_module)\n.size __this_module,.-__this_module\n.popsection\n"
".pushsection .modinfo,\"a\",%progbits\n.asciz \"license=GPL\"\n.asciz \"description=Resident bounded RC identity observer; no unload\"\n.asciz \"depends=\"\n.asciz \"vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7 \"\n.popsection\n");
