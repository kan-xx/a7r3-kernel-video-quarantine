#include "bounded_stop_contract.h"
/* Finite orchestration only. No native adapter, MMIO address, release callback,
 * DMM callback, reset callback, scheduler, queue mutation or arbitrary call API.
 * A terminal state is never retried, and an acquired lease is never silently
 * released on an ambiguous failure. This is quarantine, NOT recovered service.
 */
static int finish(struct bb_tx *t,bb_u32 phase,int result) {
    t->phase=phase;t->result=result;return result;
}
int bb_attempt(struct bb_tx *t,const struct bb_ops *o,void *ctx,bb_u32 max_polls) {
    if(!t)return BB_BAD_INPUT;
    if(t->phase!=BB_NEW)return BB_REENTRY;
    if(!o||!o->try_acquire||!o->request_zero||!o->pause||!o->read_status||
       max_polls==0||max_polls>64)
        return finish(t,BB_REJECTED,BB_BAD_INPUT);
    t->polls=0;t->last_status=0xffffffffU;t->lease_held=0;t->request_attempted=0;
    t->phase=BB_ACQUIRING;
    if(o->try_acquire(ctx)!=0)
        return finish(t,BB_REJECTED,BB_ACQUIRE_FAILED);
    t->lease_held=1;t->request_attempted=1;t->phase=BB_STOP_REQUESTED;
    if(o->request_zero(ctx)!=0)
        return finish(t,BB_QUARANTINED,BB_REQUEST_FAILED);
    if(o->pause(ctx,10)!=0)
        return finish(t,BB_QUARANTINED,BB_PAUSE_FAILED);
    while(t->polls<max_polls) {
        if(o->read_status(ctx,&t->last_status)!=0)
            return finish(t,BB_QUARANTINED,BB_READ_FAILED);
        t->polls++;
        if(t->last_status==0)
            return finish(t,BB_FENCED,BB_FENCE_ONLY);
        if(t->polls==max_polls)break;
        if(o->pause(ctx,1000)!=0)
            return finish(t,BB_QUARANTINED,BB_PAUSE_FAILED);
    }
    return finish(t,BB_QUARANTINED,BB_TIMEOUT);
}
