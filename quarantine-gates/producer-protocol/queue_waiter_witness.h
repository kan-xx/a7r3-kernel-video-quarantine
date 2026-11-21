/* OFFLINE candidate ABI, not a device interface. */
typedef unsigned int u32; typedef unsigned char u8;
struct qw_profile {
 u32 index,queue,task,pid,ti,osal_text,osal_bss,liro_text;
 u32 wait_gateway,receive_gateway,epoch;
};
struct qw_result {
 u32 valid,reason,queue,waiter,task,pid,ti,recvslot,outer_sp,loop_lr,epoch;
};
/* 1 exact parked original mainloop; 0 busy or shape changed; negative context.
 * This is NOT a producer/DMA drain, message cancellation, or cleanup permit. */
int qw_probe_task(const struct qw_profile*,struct qw_result*);
