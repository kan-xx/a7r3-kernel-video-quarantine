#ifndef STOCK_RECORD_GUARD_POLICY_H
#define STOCK_RECORD_GUARD_POLICY_H
#include <stdint.h>
enum { RG_PRE=0,RG_STARTING=1,RG_RUNNING=2,RG_STOPPING=3,RG_DONE=4,RG_FAILED=5 };
enum { RG_NONE=0,RG_START=1,RG_STOP=2,RG_FINISH=3 };
enum { RG_SUCCESS=0,RG_IDENTITY=1,RG_OBSERVE=2,RG_BASELINE=3,RG_START_KEY=4,RG_START_TIMEOUT=5,RG_GENERATION=6,RG_EARLY_IDLE=7,RG_STOP_KEY=8,RG_STOP_TIMEOUT=9,RG_KEY_STUCK=10,RG_LOG=11,RG_CANCELLED=12 };
/* qualified: 0 invalid, 1 coherent, 2 transient double-read/mode transition. */
struct rg_sample { uint32_t qualified,epoch_ok,state[3],generation_same; };
struct rg_policy { uint32_t phase,error,start_claim,stop_claim,seen_running,idles;uint64_t start_ms,stop_ms,duration_ms,uncertain_ms; };
/* status: 0 no key active/finished successfully, 1 pending, -1 failed.
 * Each returned action is claimed before any effect; there is no reset API.
 * Generation_same is only the observed object's configuration lineage under
 * an exclusive operator contract, not an invented hardware generation ID. */
int rg_tick(struct rg_policy*,const struct rg_sample*,uint64_t,int);
#endif
