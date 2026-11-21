typedef unsigned int u32;typedef unsigned char u8;
struct pd_submit {
 u32 phase,nonce,expected_pid,expected_task,entry_sp,entry_lr,receiver,message,source;
 u32 active_snapshot,type_snapshot,refs_snapshot,owned_payload,queue,bytes,packet_source;
 u32 submitted,local_committed,free_failed,error,worker_expected_payload,worker_armed,worker_turn_done,late_register;
};
struct pp_config {
 u32 queue,task,pid,ti,osal_text,osal_bss,liro_text,wait_gateway,receive_gateway,epoch;
 u32 common_bsem,f3_task,f3_pid;struct pd_submit*submit;u32 monitor;
 /* Monotonic transaction facts; all storage remains resident. */
 volatile u32 phase,baseline_waiter,baseline_sp,turn_seen,invalid;
};
/* OFFLINE only. No return of this API authorizes DMA/free/reset or F3 resume. */
u32 pp_resolve(struct pp_config*);
int pp_arm_locked(struct pp_config*);
int pp_arm_task(struct pp_config*);
void pp_receive_before(struct pp_config*,u32 sp,u32 lr,u32 output);
