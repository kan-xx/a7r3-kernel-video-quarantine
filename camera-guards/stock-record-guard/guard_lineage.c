#include "guard_lineage.h"
/* C_Imager SetMode 637a59e4 writes requested at +10c (637a5a10).
 * Separate Apply 637a5dac normally commits previous=applied (637a5f80),
 * then applied=requested (637a5f8a). Repeated Apply updates only history.
 * These are not three simultaneous sensor modes or hardware completion. */
static int equal(const uint32_t *m,unsigned r,unsigned a,unsigned p){return m[0]==r&&m[1]==a&&m[2]==p;}
static int history(unsigned p){return p==1||p==48||p==76;}
static int baseline_ok(const uint32_t*m){return (m[0]==1||m[0]==76)&&m[0]==m[1]&&history(m[2]);}
int rg_baseline_restored(const uint32_t*base,const uint32_t*now){
 return baseline_ok(base)&&now[0]==base[0]&&now[1]==base[1]&&history(now[2]);
}
/* Enumerate the states produced by the three actual stores, including a
 * repeated Apply at each node. Polling may skip any number of these states;
 * the fixed phase deadline still bounds completion. This is stock-only:
 * path 1 -> 48 -> 76 entering capture, 76 -> 48 -> baseline leaving it.
 * A zeroed applied/history is deliberately excluded: presence of Stop() in
 * the image does not establish it is part of this qualified recording path. */
static int on_path(const uint32_t*now,const unsigned*path,unsigned length,unsigned previous){
 unsigned current=path[0],old=previous;
 if(equal(now,current,current,old)||equal(now,current,current,current))return 1;
 for(unsigned i=1;i<length;i++){
  unsigned next=path[i];
  if(equal(now,next,current,old)||equal(now,next,current,current)||
     equal(now,next,next,current)||equal(now,next,next,next))return 1;
  old=current;current=next;
 }
 return 0;
}
int rg_modes(unsigned phase,const uint32_t*base,const uint32_t*now,const uint32_t*state){
 if(!baseline_ok(base)||!history(now[2])||state[1]||state[2])return 0;
 if(phase==RG_PRE)return rg_baseline_restored(base,now);
 if(phase==RG_STARTING){
  const unsigned path[]={base[0],48,76};
  if(state[0]>6||!on_path(now,path,3,base[2]))return 0;
  /* Requested+applied 76, not previous==76, is the current mode condition.
   * The policy separately demands encoder state6 and completed key-up. */
  if(now[0]==76&&now[1]==76)return 1;
  if(state[0]==6||now[0]!=now[1])return 2;
  return 1; /* Original coherent standby/preparation; never run proof. */
 }
 if(phase==RG_RUNNING)return now[0]==76&&now[1]==76;
 if(phase==RG_STOPPING){
  const unsigned path[]={76,48,base[0]};
  if(state[0]>8||!(on_path(now,path,3,48)||on_path(now,path,3,76)||
                  on_path(now,path,3,base[2])))return 0;
  if(now[0]!=now[1])return 2;
  if(!state[0]&&!rg_baseline_restored(base,now))return 2;
  return 1;
 }
 return 0;
}
