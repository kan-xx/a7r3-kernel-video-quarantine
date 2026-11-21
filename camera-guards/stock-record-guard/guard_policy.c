#include "guard_policy.h"
static int fail(struct rg_policy*p,unsigned e){p->phase=RG_FAILED;if(!p->error)p->error=e;return RG_FINISH;}
int rg_tick(struct rg_policy*p,const struct rg_sample*s,uint64_t now,int key){
 if(p->phase==RG_DONE||p->phase==RG_FAILED)return RG_FINISH;
 if(!s->epoch_ok)return fail(p,RG_IDENTITY);
 if(!s->qualified||s->qualified>2)return fail(p,RG_OBSERVE);
 if(s->qualified==2){
  p->idles=0;
  if(!p->uncertain_ms)p->uncertain_ms=now?now:1;
  if(now<p->uncertain_ms||now-p->uncertain_ms>=2000)return fail(p,RG_OBSERVE);
  if(p->phase==RG_STARTING&&(now<p->start_ms||now-p->start_ms>=8000))return fail(p,RG_START_TIMEOUT);
  if(p->phase==RG_STOPPING&&(now<p->stop_ms||now-p->stop_ms>=10000))return fail(p,RG_STOP_TIMEOUT);
  return RG_NONE;
 }
 p->uncertain_ms=0;
 unsigned idle=!s->state[0]&&!s->state[1]&&!s->state[2],run=s->state[0]==6&&!s->state[1]&&!s->state[2];
 if(p->phase==RG_PRE){
  if(p->start_claim||!idle||!s->generation_same||p->duration_ms<1000||p->duration_ms>30000)return fail(p,RG_BASELINE);
  if(++p->idles<2)return RG_NONE;p->idles=0;p->start_claim=1;p->start_ms=now;p->phase=RG_STARTING;return RG_START;
 }
 if(now<p->start_ms)return fail(p,RG_OBSERVE);
 if(p->phase==RG_STARTING){
  if(key<0)return fail(p,RG_START_KEY);
  if(!s->generation_same)return fail(p,RG_GENERATION);
  if(key>0){if(now-p->start_ms>=10000)return fail(p,RG_KEY_STUCK);return RG_NONE;}
  if(run){p->seen_running=1;p->phase=RG_RUNNING;}
  else if(now-p->start_ms>=8000)return fail(p,RG_START_TIMEOUT);
  else return RG_NONE;
 }
 if(p->phase==RG_RUNNING){
  if(!s->generation_same)return fail(p,RG_GENERATION);
  if(idle)return fail(p,RG_EARLY_IDLE);
  if(!run)return fail(p,RG_GENERATION);
  if(now-p->start_ms<p->duration_ms)return RG_NONE;
  if(p->stop_claim||!p->seen_running||key)return fail(p,RG_STOP_KEY);
  p->stop_claim=1;p->stop_ms=now;p->phase=RG_STOPPING;return RG_STOP;
 }
 if(p->phase==RG_STOPPING){
  if(key<0)return fail(p,RG_STOP_KEY);
  /* A coherent identity/configuration mismatch is terminal even before idle.
   * Legitimate mode transitions are qualified==2 and handled above. */
  if(!s->generation_same)return fail(p,RG_GENERATION);
  if(now<p->stop_ms)return fail(p,RG_OBSERVE);
  if(now-p->stop_ms>=10000)return fail(p,key>0?RG_KEY_STUCK:RG_STOP_TIMEOUT);
  /* A successful STOP tap is not a stopped-recorder proof. Two independent
   * later idle samples plus completed key-up are required. */
  if(idle&&!key){if(!s->generation_same)return fail(p,RG_GENERATION);if(++p->idles==2){p->phase=RG_DONE;return RG_FINISH;}}
  else p->idles=0;
 }
 return RG_NONE;
}
