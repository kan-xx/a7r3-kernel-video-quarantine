/* Passive native H activation/completion records. Entire-boot resident.
 * Generation is an observer-local activation ordinal, NEVER a sensor frame ID.
 * Pairing occurs only on complete immutable host snapshots, no IRQ sidecar. */
typedef unsigned int u32;typedef unsigned char u8;
#include "anchors.h"
#include "table_protocol.c"
#define A_SLOT ((volatile u32*)0x64696decu)
#define C_SLOT ((volatile u32*)0x64696df4u)
#define A_ORIG 0x63a2e035u
#define C_ORIG 0x63d5f5e9u
#define BACK 0x6438ce80u
#define CAP 64u
#define ARMED 1u
#define SEALED 2u
#define REFUSED 3u
#define PRE_ROUTE 1u
#define STACK_OK 2u
#define CTRL_OK 4u
#define POST_ROUTE 8u
#define CONFIG_SAME 16u
#define POST_CTRL 32u
#define STATUS_OK 64u
#define SOURCE_OK 128u
#define JIFFIES_LOW32 0x604a8240u
struct event {
 volatile u32 committed;u32 native_r4,native_lr,jiffies_before,jiffies_after;
 u32 kind,flags,return_value,generation,entry_order,return_order,sp,lr,source_lr,args[5];
 u32 sequence,job,controller,epoch[2],driver[2],state[2],arm[2];
 u32 queue_index[2],current_index[2],cflags[2],input_status,output_status,status_valid,status_value;
 u32 io_before[4],io_after[4],input_before[14],input_after[14],output_before[14],output_after[14];
 u32 source_flags,source_stack[5],source_before[5],source_after[5];
 u32 pig_raw_status,pig_functor[5],pig_identity[2][3],pig_callbacks[2][3],producer[2][3],latched[2][3];
};
struct state {
 u32 magic,version,capacity,event_bytes;volatile u32 phase,reserved,dropped,restore_activation,restore_complete;
 u32 no_unload,activation_gateway,complete_gateway,ever_published,install_result,independent_exposure_proved;volatile u32 order_counter;
 u32 pig_gateway_address;volatile u32 restore_pig,table_attempts;u32 table_last[8],source_exposure_proved,padding[4];
 struct event events[CAP];
};
__attribute__((section(".data.rcdual"),aligned(64),used))
struct state rcdual_state={.magic=0x50475331u,.version=1,.capacity=CAP,.event_bytes=sizeof(struct event),.no_unload=1};
void rcdual_build(void);void rcdual_complete(void);void pig_gateway(void);
static void retire_pig(void);
static __inline__ void barrier(void){__asm__ volatile("dmb sy":::"memory");}
static __inline__ int cas(volatile u32*p,u32 old,u32 next,u32*seen){u32 v,f;
 __asm__ volatile("ldrex %0,[%2]\n cmp %0,%3\n bne 1f\n strex %1,%4,[%2]\n b 2f\n1: clrex\n mov %1,#2\n2:":"=&r"(v),"=&r"(f):"r"(p),"r"(old),"r"(next):"cc","memory");*seen=v;return(int)f;}
static u32 exchange(volatile u32*p,u32 from,u32 to){u32 n,v;int r;for(n=0;n<4;n++){r=cas(p,from,to,&v);if(!r||v==to){barrier();return 1;}if(r==2)return 2;}return 3;}
static void retire_pig(void){u32 i,n,seen,old;struct table_result result;
 if(rcdual_state.restore_pig==1)return;
 for(n=0;n<4;n++){old=rcdual_state.table_attempts;if(old>=8)return;
  if(!cas(&rcdual_state.table_attempts,old,old+1,&seen))break;}
 if(n==4)return;
 pig_table_step((u32)&pig_gateway,0,&result);
 for(i=0;i<8;i++)rcdual_state.table_last[i]=((u32*)&result)[i];
 barrier();if(result.result==PT_OK&&!result.own_after)rcdual_state.restore_pig=1;
}
static void seal(void){rcdual_state.phase=SEALED;barrier();rcdual_state.restore_activation=exchange(A_SLOT,(u32)&rcdual_build,A_ORIG);rcdual_state.restore_complete=exchange(C_SLOT,(u32)&rcdual_complete,C_ORIG);retire_pig();}
static struct event*reserve(void){u32 n,old,seen;for(n=0;n<4;n++){if(rcdual_state.phase!=ARMED)return 0;old=rcdual_state.reserved;if(old>=CAP){seal();return 0;}if(!cas(&rcdual_state.reserved,old,old+1,&seen))return &rcdual_state.events[old];}rcdual_state.dropped=1;return 0;}
static u32 mark_order(void){u32 n,old,seen;for(n=0;n<4;n++){old=rcdual_state.order_counter;if(old>=2*CAP){rcdual_state.dropped=1;return 0;}if(!cas(&rcdual_state.order_counter,old,old+1,&seen)){barrier();return old+1;}}rcdual_state.dropped=1;return 0;}
static void commit(struct event*e){u32 n=(u32)(e-rcdual_state.events);barrier();e->committed=n+1;if(n==CAP-1)seal();}
static u32 rd(u32 p){return *(volatile u32*)p;}
static void copy(u32*d,u32 p,u32 n){u32 i;for(i=0;i<n;i++)d[i]=rd(p+4*i);}
static int equal(const u32*a,const u32*b,u32 n){u32 i;for(i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int stack(u32 s,u32 n){return !(s&7u)&&s>=0x60100000u&&s<=0x78800000u-n&&((s&~4095u)==((s+n-1)&~4095u));}
static int seq(u32 p){return p>=0x6438a8f0u&&p<0x6438a8f0u+22u*376u&&(p-0x6438a8f0u)%376u==0;}
static u32 route(u32 b,u32 i){if(b!=BACK)return 0;return i==0x6438cbb4u?5:i==0x6438cc24u?8:0;}
static void snapshot(struct event*e,u32 after){u32 s=e->sequence,p=s+8;u32*io=after?e->io_after:e->io_before;
 e->epoch[after]=rd(s+0x16c);e->driver[after]=rd(s+0x160);e->state[after]=rd(s+0x174);e->arm[after]=rd(s+0x148);
 io[0]=rd(p+0x5c);io[1]=rd(p+0x60);io[2]=rd(p+0xa8);io[3]=rd(p+0xac);
 copy(after?e->input_after:e->input_before,p+0xc,14);copy(after?e->output_after:e->output_before,p+0x64,14);
}
static int controller(struct event*e,u32 after){u32 c=e->controller,i0,i1,q0,q1,slot;
 if(rd(c)!=0x646966e8u||rd(c+0x88)!=e->job||rd(c+0x118)!=e->args[1]||rd(c+0x84)!=2)return 0;
 i0=rd(c+0x80);if(i0>=2)return 0;q0=rd(c+0x60);q1=rd(c+0x64);
 if(q0==e->sequence&&q1!=e->sequence)slot=0;else if(q1==e->sequence&&q0!=e->sequence)slot=1;else return 0;
 e->queue_index[after]=slot;e->current_index[after]=i0;e->cflags[after]=rd(c+0x8c);
 i1=rd(c+0x80);if(i0!=i1)return 0;
 if(e->kind==2&&slot!=i0)return 0;return 1;
}
static int ram(u32 p,u32 n){return !(p&3u)&&p>=0x62e68000u&&p<0x648c6000u&&n<=0x648c6000u-p;}
static void source_copy(u32*d,u32 ec){d[0]=rd(ec+0xcf4);d[1]=rd(ec+0xcf8);copy(d+2,ec+0x19c,3);}
static void source_capture(struct event*e){u32 s=e->sp,ec,lr;
 if(e->kind!=1||e->source_lr!=0x63d5c99fu||!stack(s,0x108))return;
 if(rd(s+0x1c)!=0x63a26f6du||rd(s+0x64)!=0x63a1f469u||rd(s+0x8c)!=0x63d5a523u||rd(s+0x9c)!=0x6392a37fu)return;
 lr=rd(s+0x104);if(lr!=0x6392ee7du&&lr!=0x6392eecbu)return;
 e->source_flags=1;e->source_stack[0]=lr;e->source_stack[1]=ec=rd(s+0xe4);
 e->source_stack[2]=rd(s+0xe8);e->source_stack[3]=rd(s+0xec);e->source_stack[4]=rd(s+0x100);
 if(!ram(ec,0xcfc))return;source_copy(e->source_before,ec);e->source_flags|=2;
}
static void pig_snapshot(struct event*e,u32 after){u32 p=0x641f1258u;
 e->pig_identity[after][0]=rd(p);e->pig_identity[after][1]=rd(p+0x30);e->pig_identity[after][2]=rd(p+0x98);
 copy(e->pig_callbacks[after],p+0x80,3);copy(e->producer[after],0x64352e5cu,3);copy(e->latched[after],0x64352df0u,3);
}
static int pig_identity(struct event*e,u32 after){u32*p=e->pig_identity[after];return p[0]==0x646908f8u&&p[1]==0x640cfe9cu&&p[2]==0x640cff78u;}
__attribute__((noinline,used))struct event*pig_prepare(u32 sp,const u32*f,u32 status){struct event*e;u32 p=f[0],method;
 if(f[5]!=0x63cbb87du||!stack(sp,0x148)||rd(sp+4)!=0x6376efa9u)return 0;
 if(p<sp+8||p>sp+0x148-20||(p-sp-8)%20)return 0;
 if(rd(p)!=(u32)&pig_gateway||rd(p+4)||rd(p+0xc)||rd(p+0x10)!=0x641f1258u)return 0;
 method=rd(p+8);if(method!=0x63cb4f4fu&&method!=0x63cb492du)return 0;
 if((status&(method==0x63cb4f4fu?0x44000000u:0x48000000u))!=(method==0x63cb4f4fu?0x44000000u:0x48000000u))return 0;
 if(rcdual_state.phase==SEALED){retire_pig();return 0;}e=reserve();if(!e)return 0;
 e->entry_order=mark_order();e->kind=3;e->flags=1;e->sp=sp;e->lr=f[5];e->args[0]=p;
 e->jiffies_before=rd(JIFFIES_LOW32);e->pig_raw_status=status;copy(e->pig_functor,p,5);pig_snapshot(e,0);
 if(pig_identity(e,0))e->flags|=2;return e;
}
__attribute__((noinline,used))void pig_finish(u32 ret,struct event*e){u32 i;
 e->return_order=mark_order();e->return_value=ret;e->jiffies_after=rd(JIFFIES_LOW32);pig_snapshot(e,1);
 if(pig_identity(e,1))e->flags|=4;
 for(i=0;i<5;i++)if(rd(e->args[0]+4*i)!=e->pig_functor[i])break;
 if(i==5)e->flags|=8;commit(e);
}
static struct event*prepare(u32 sp,const u32*f,u32 kind){struct event*e;u32 j=route(f[0],f[1]),p=f[2];
 if(!j||!seq(p)||!stack(sp,kind==1?0x30:0x54))return 0;
 if(kind==2&&rd(sp)!=j)return 0;e=reserve();if(!e)return 0;
 e->entry_order=mark_order();e->kind=kind;e->sp=sp;e->lr=f[5];e->job=j;e->sequence=p-8;e->controller=j==5?0x641679c0u:0x641675f8u;
 e->jiffies_before=rd(JIFFIES_LOW32);e->args[0]=f[0];e->args[1]=f[1];e->args[2]=p;e->args[3]=f[3];e->args[4]=kind==2?rd(sp):0;
 if(kind==1)e->generation=(u32)(e-rcdual_state.events)+1;
 snapshot(e,0);
 if(rd(e->sequence+0x170)==j&&e->driver[0]==BACK&&e->state[0]==4&&e->arm[0]==1)e->flags|=PRE_ROUTE;
 if(controller(e,0))e->flags|=CTRL_OK;
 if(kind==1){u32 selected=2;e->source_lr=rd(sp+4);
  if(e->lr==0x63d5e5fbu){
   if(e->source_lr==0x63d5c99fu&&rd(sp+8)==e->controller)selected=rd(sp+0xc);
   else if(e->source_lr==0x63a29197u&&rd(sp)==e->controller)selected=rd(sp+0x2c);
   else if(e->source_lr==0x63a29289u)selected=rd(sp+0x24);
   if((e->flags&CTRL_OK)&&selected==e->queue_index[0])e->flags|=STACK_OK;
  }
 }else{e->source_lr=rd(sp+0x2c);
  if(e->lr==0x63a2bdc3u&&e->args[3]==sp+0x50&&(e->source_lr==0x63a2967du||e->source_lr==0x63a29091u)&&rd(sp+0xc)==e->controller&&rd(sp+0x10)==e->sequence)e->flags|=STACK_OK;
 }
 source_capture(e);return e;
}
__attribute__((noinline,used))struct event*rcdual_prepare_build(u32 sp,const u32*f){return prepare(sp,f,1);}
__attribute__((noinline,used))struct event*rcdual_prepare_complete(u32 sp,const u32*f){return prepare(sp,f,2);}
static void finish(u32 ret,struct event*e){e->return_order=mark_order();e->return_value=ret;e->jiffies_after=rd(JIFFIES_LOW32);snapshot(e,1);
 if(rd(e->sequence+0x170)==e->job&&e->epoch[0]==e->epoch[1]&&e->driver[1]==BACK&&e->state[1]==4&&e->arm[1]==1)e->flags|=POST_ROUTE;
 if(equal(e->io_before,e->io_after,4)&&equal(e->input_before,e->input_after,14)&&equal(e->output_before,e->output_after,14))e->flags|=CONFIG_SAME;
 if(controller(e,1)&&e->queue_index[0]==e->queue_index[1])e->flags|=POST_CTRL;
 if(e->io_before[0]==2&&e->io_before[1]==(e->job==5?0u:1u)&&e->io_before[2]==0&&e->io_before[3]==0&&equal(e->io_before,e->io_after,4))e->flags|=SOURCE_OK;
 if(e->kind==2&&(e->flags&(STACK_OK|CTRL_OK|POST_CTRL))==(STACK_OK|CTRL_OK|POST_CTRL)){
  e->status_value=rd(e->args[3]);e->status_valid=1;e->flags|=STATUS_OK;e->input_status=rd(e->controller+0x120);e->output_status=rd(e->controller+0x124);
 }
 if(e->source_flags&2){source_copy(e->source_after,e->source_stack[1]);if(equal(e->source_before,e->source_after,5))e->source_flags|=4;}
 commit(e);
}
__attribute__((noinline,used))void rcdual_finish_build(u32 r,struct event*e){finish(r,e);}
__attribute__((noinline,used))void rcdual_finish_complete(u32 r,struct event*e){finish(r,e);}
__attribute__((section(".init.text"),used))int init_module(void){u32 k,n,r;struct table_result result;
 for(k=0;k<sizeof(anchors)/sizeof(anchors[0]);k++)for(n=0;n<anchors[k].n;n++)if(((volatile u8*)anchors[k].va)[n]!=anchors[k].bytes[n])return -22;
 rcdual_state.activation_gateway=(u32)&rcdual_build;rcdual_state.complete_gateway=(u32)&rcdual_complete;
 rcdual_state.pig_gateway_address=(u32)&pig_gateway;barrier();
 pig_table_step((u32)&pig_gateway,1,&result);
 for(k=0;k<8;k++)rcdual_state.table_last[k]=((u32*)&result)[k];
 if(result.result!=PT_OK){rcdual_state.phase=REFUSED;rcdual_state.install_result=1;return -16;}
 rcdual_state.ever_published=4;barrier();
 r=exchange(C_SLOT,C_ORIG,(u32)&rcdual_complete);
 if(r!=1){seal();rcdual_state.phase=REFUSED;rcdual_state.install_result=2;return 0;}
 rcdual_state.ever_published=6;barrier();r=exchange(A_SLOT,A_ORIG,(u32)&rcdual_build);
 if(r!=1){seal();rcdual_state.phase=REFUSED;rcdual_state.install_result=3;return 0;}
 rcdual_state.ever_published=7;rcdual_state.install_result=4;barrier();rcdual_state.phase=ARMED;barrier();return 0;
}

__asm__(
".pushsection .text.rcdual_build,\"ax\",%progbits\n"
".balign 4\n"
".arm\n"
".global rcdual_build\n"
".type rcdual_build,%function\n"
"rcdual_build:\n"
"ldr ip,=0x63d5e5fb\n"
"cmp lr,ip\n"
"bne .Lbuild_forward\n"
"ldr ip,=0x6438ce80\n"
"cmp r0,ip\n"
"bne .Lbuild_forward\n"
"ldr ip,=0x6438cbb4\n"
"cmp r1,ip\n"
"beq .Lbuild_stack\n"
"ldr ip,=0x6438cc24\n"
"cmp r1,ip\n"
"bne .Lbuild_forward\n"
".Lbuild_stack:\n"
"ubfx ip,sp,#0,#12\n"
"cmp ip,#1024\n"
"blo .Lbuild_forward\n"
"push {r0,r1,r2,r3,r4,lr}\n"
"add r0,sp,#24\n"
"mov r1,sp\n"
"bl rcdual_prepare_build\n"
"mov ip,r0\n"
"pop {r0,r1,r2,r3,r4,lr}\n"
"cmp ip,#0\n"
"beq .Lbuild_forward\n"
"str r4,[ip,#4]\n"
"str lr,[ip,#8]\n"
"mov r4,ip\n"
"adr lr,.Lbuild_returned\n"
"ldr ip,=0x63a2e035\n"
"bx ip\n"
".Lbuild_returned:\n"
"push {r0,r4,r5,lr}\n"
"mov r5,r4\n"
"mov r1,r4\n"
"bl rcdual_finish_build\n"
"mov ip,r5\n"
"pop {r0,r4,r5,lr}\n"
"ldr r4,[ip,#4]\n"
"ldr lr,[ip,#8]\n"
"bx lr\n"
".Lbuild_forward:\n"
"ldr ip,=0x63a2e035\n"
"bx ip\n"
".ltorg\n"
".size rcdual_build,.-rcdual_build\n"
".popsection\n"
".pushsection .text.rcdual_complete,\"ax\",%progbits\n"
".balign 4\n"
".arm\n"
".global rcdual_complete\n"
".type rcdual_complete,%function\n"
"rcdual_complete:\n"
"ldr ip,=0x63a2bdc3\n"
"cmp lr,ip\n"
"bne .Lcomplete_forward\n"
"ldr ip,=0x6438ce80\n"
"cmp r0,ip\n"
"bne .Lcomplete_forward\n"
"ldr ip,=0x6438cbb4\n"
"cmp r1,ip\n"
"beq .Lcomplete_stack\n"
"ldr ip,=0x6438cc24\n"
"cmp r1,ip\n"
"bne .Lcomplete_forward\n"
".Lcomplete_stack:\n"
"ubfx ip,sp,#0,#12\n"
"cmp ip,#1024\n"
"blo .Lcomplete_forward\n"
"push {r0,r1,r2,r3,r4,lr}\n"
"add r0,sp,#24\n"
"mov r1,sp\n"
"bl rcdual_prepare_complete\n"
"mov ip,r0\n"
"pop {r0,r1,r2,r3,r4,lr}\n"
"cmp ip,#0\n"
"beq .Lcomplete_forward\n"
"str r4,[ip,#4]\n"
"str lr,[ip,#8]\n"
"mov r4,ip\n"
"adr lr,.Lcomplete_returned\n"
"ldr ip,=0x63d5f5e9\n"
"bx ip\n"
".Lcomplete_returned:\n"
"push {r0,r4,r5,lr}\n"
"mov r5,r4\n"
"mov r1,r4\n"
"bl rcdual_finish_complete\n"
"mov ip,r5\n"
"pop {r0,r4,r5,lr}\n"
"ldr r4,[ip,#4]\n"
"ldr lr,[ip,#8]\n"
"bx lr\n"
".Lcomplete_forward:\n"
"ldr ip,=0x63d5f5e9\n"
"bx ip\n"
".ltorg\n"
".size rcdual_complete,.-rcdual_complete\n"
".popsection\n"
".pushsection .gnu.linkonce.this_module,\"aw\",%progbits\n.balign 4\n.global __this_module\n.type __this_module,%object\n__this_module:\n.zero 12\n.asciz \"a7r3_pgs_1101f\"\n.zero 188-(.-__this_module)\n.word init_module\n.zero 316-(.-__this_module)\n.size __this_module,.-__this_module\n.popsection\n"
".pushsection .modinfo,\"a\",%progbits\n.asciz \"license=GPL\"\n.asciz \"description=Resident bounded RC identity observer; no unload\"\n.asciz \"depends=\"\n.asciz \"vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7 \"\n.popsection\n");

__asm__(
".pushsection .text.pig_gateway,\"ax\",%progbits\n"
".arm\n"
".balign 4\n"
".global pig_gateway\n"
".type pig_gateway,%function\n"
"pig_gateway:\n"
" ldr ip,=0x63cbb87d\n"
" cmp lr,ip\n"
" bne .Lforward\n"
" ubfx ip,sp,#0,#12\n"
" cmp ip,#1024\n"
" blo .Lforward\n"
" push {r0,r1,r2,r3,r4,lr}\n"
" add r0,sp,#24\n"
" mov r1,sp\n"
" mov r2,r8\n"
" bl pig_prepare\n"
" mov ip,r0\n"
" pop {r0,r1,r2,r3,r4,lr}\n"
" cmp ip,#0\n"
" beq .Lforward\n"
" str r4,[ip,#4]\n"
" str lr,[ip,#8]\n"
" mov r4,ip\n"
" adr lr,.Lreturned\n"
" ldr ip,=0x63cb3e05\n"
" bx ip\n"
".Lreturned:\n"
" push {r0,r4,r5,lr}\n"
" mov r5,r4\n"
" mov r1,r4\n"
" bl pig_finish\n"
" mov ip,r5\n"
" pop {r0,r4,r5,lr}\n"
" ldr r4,[ip,#4]\n"
" ldr lr,[ip,#8]\n"
" bx lr\n"
".Lforward:\n"
" ldr ip,=0x63cb3e05\n"
" bx ip\n"
".ltorg\n"
".size pig_gateway,.-pig_gateway\n"
".popsection\n"
);
