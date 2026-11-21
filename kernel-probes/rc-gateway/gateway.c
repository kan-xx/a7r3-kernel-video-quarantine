/* Independent one-shot passive gateway candidate. LOCAL ONLY, NOT DEPLOYED.
 * Firmware code is called once through its pre-existing ABI. No cleanup:
 * this module must remain resident until this kernel image is discarded.
 * SPDX-License-Identifier: GPL-2.0-only
 */
typedef unsigned int u32;
typedef unsigned char u8;
typedef u32 (*complete_fn)(u32,u32,u32,u32*,u32);
#include "anchors.h"
#define SLOT ((volatile u32*)0x64696ed4u)
#define ORIGINAL 0x63d5f5e9u
#define CAPACITY 32u
#define ARMED 1u
#define SEALED 2u
#define REFUSED 3u
struct record {
    volatile u32 committed;
    u32 backend, interface, payload, status_pointer, jobid;
    u32 entry_sp, entry_lr, caller_lr, native_error, status_valid, status_value;
};
struct state {
    u32 magic, version, capacity, record_bytes;
    volatile u32 phase, reserved, contention, restore_result;
    u32 slot_address, original_address, gateway_address, no_unload;
    struct record records[CAPACITY];
};
__attribute__((section(".data.rcgate"),aligned(64),used))
struct state rcgate_state = {0x52434731u,1,CAPACITY,sizeof(struct record),0,0,0,0,
                            0x64696ed4u,ORIGINAL,0,1,{{0}}};
void rcgate_entry(void);
static __inline__ void barrier(void) { __asm__ volatile("dmb sy" ::: "memory"); }
/* One attempt, including CLREX on mismatch. All retry loops are explicitly bounded. */
static __inline__ int cas(volatile u32 *p,u32 old,u32 next,u32 *observed) {
    u32 value,failed;
    __asm__ volatile(
        "ldrex %0,[%2]\n\t"
        "cmp %0,%3\n\t"
        "bne 1f\n\t"
        "strex %1,%4,[%2]\n\t"
        "b 2f\n"
        "1: clrex\n\t"
        "mov %1,#2\n"
        "2:"
        : "=&r"(value),"=&r"(failed) : "r"(p),"r"(old),"r"(next) : "cc","memory");
    *observed=value;
    return (int)failed;
}
static void seal(void) {
    u32 seen,i; int result;
    rcgate_state.phase=SEALED;
    barrier();
    for(i=0;i<4;i++) {
        result=cas(SLOT,(u32)&rcgate_entry,ORIGINAL,&seen);
        if(result==0 || seen==ORIGINAL) { barrier();rcgate_state.restore_result=1;return; }
        if(result==2) { rcgate_state.restore_result=2;return; }
    }
    rcgate_state.restore_result=3;
}
static int reserve(void) {
    u32 old,seen,i;
    for(i=0;i<4;i++) {
        if(rcgate_state.phase!=ARMED) return -1;
        old=rcgate_state.reserved;
        if(old>=CAPACITY) { seal();return -1; }
        if(cas(&rcgate_state.reserved,old,old+1,&seen)==0) return (int)old;
    }
    rcgate_state.contention=1; /* At least one dropped record; never a complete event count. */
    return -1;
}
__attribute__((noinline,used))
u32 rcgate_body(u32 backend,u32 interface,u32 payload,u32 *status,u32 jobid,u32 entry_sp,u32 entry_lr) {
    /* Do not touch any input pointer before the original call. */
    u32 error=((complete_fn)ORIGINAL)(backend,interface,payload,status,jobid);
    int index;
    struct record *rec;
    if(rcgate_state.phase!=ARMED) return error;
    index=reserve();
    if(index<0) return error;
    rec=&rcgate_state.records[(u32)index];
    rec->backend=backend;rec->interface=interface;rec->payload=payload;
    rec->status_pointer=(u32)status;rec->jobid=jobid;rec->entry_sp=entry_sp;
    rec->entry_lr=entry_lr;rec->caller_lr=0;
    rec->native_error=error;rec->status_valid=0;rec->status_value=0;
    /* Only the known caller's still-live stack word, never payload/MMIO. */
    if(backend==0x6438e4ecu && (interface==0x6438cb30u || interface==0x6438a864u) && payload>=0x6438a8f0u &&
       payload<0x6438a8f0u+22u*376u && (payload-0x6438a8f0u)%376u==0 &&
       entry_lr==0x63a2bdc3u && entry_sp<=0xffffffafu && (u32)status==entry_sp+0x50u &&
       (entry_sp&7u)==0 && (entry_sp&~4095u)==((u32)status&~4095u) &&
       entry_sp>=0x60100000u && (u32)status<=0x787ffffcu) {
        u32 caller_lr=*(volatile u32*)(entry_sp+0x2cu);
        rec->caller_lr=caller_lr;
        if(caller_lr==0x63a29091u || caller_lr==0x63a2967du || caller_lr==0x63a2a29du) {
            rec->status_value=*(volatile u32*)status;
            rec->status_valid=1;
        }
    }
    barrier();
    rec->committed=(u32)index+1u;
    if((u32)index==CAPACITY-1u) seal();
    return error;
}
__attribute__((section(".init.text"),used))
int init_module(void) {
    u32 i,seen;int result;
    for(i=0;i<32;i++) if(((volatile u8*)0x64696eccu)[i]!=anchor_vtable[i]) return -22;
    for(i=0;i<144;i++) if(((volatile u8*)0x63d5f5e8u)[i]!=anchor_callee[i]) return -22;
    rcgate_state.gateway_address=(u32)&rcgate_entry;
    rcgate_state.phase=ARMED;
    barrier();
    for(i=0;i<4;i++) {
        result=cas(SLOT,ORIGINAL,(u32)&rcgate_entry,&seen);
        if(result==0) { barrier();return 0; }
        if(result==2) break;
    }
    rcgate_state.phase=REFUSED;
    return -16;
}
/* Explicit bridge retains incoming SP without compiler-frame assumptions.
 * C body receives original 5 args plus entry SP and LR; alignment stays 8.
 */
__asm__(
 ".pushsection .text.rcgate_entry,\"ax\",%progbits\n"
 ".balign 4\n.arm\n.global rcgate_entry\n.type rcgate_entry,%function\n"
 "rcgate_entry:\n push {r4,lr}\n add r4,sp,#8\n sub sp,sp,#16\n"
 "ldr ip,[r4]\n str ip,[sp]\n str r4,[sp,#4]\n"
 "ldr ip,[r4,#-4]\n str ip,[sp,#8]\n bl rcgate_body\n"
 "add sp,sp,#16\n pop {r4,pc}\n.size rcgate_entry,.-rcgate_entry\n.popsection\n"
 ".pushsection .gnu.linkonce.this_module,\"aw\",%progbits\n.balign 4\n"
 ".global __this_module\n.type __this_module,%object\n__this_module:\n"
 ".zero 12\n.asciz \"a7r3_rcgate_1101a\"\n.zero 188-(.-__this_module)\n"
 ".word init_module\n.zero 316-(.-__this_module)\n"
 ".size __this_module,.-__this_module\n.popsection\n"
 ".pushsection .modinfo,\"a\",%progbits\n"
 ".asciz \"license=GPL\"\n"
 ".asciz \"description=Resident one-shot RC completion observer; no unload\"\n"
 ".asciz \"depends=\"\n"
 ".asciz \"vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7 \"\n"
 ".popsection\n");
