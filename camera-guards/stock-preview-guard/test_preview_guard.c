#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "preview_policy.h"
#include "dial_owner.h"
static unsigned assertions;
#define CHECK(x) do{assertions++;if(!(x)){fprintf(stderr,"failed line %u: %s\n",__LINE__,#x);exit(1);}}while(0)
static unsigned allocs,sends,frees,retired,events,fail_alloc,fail_send,fail_event,bad_id,bad_dynamic,fail_retire;
static uint32_t buffers[2][5];
static int dynamic(uint32_t op,uint32_t module,uintptr_t arg){
 if(op==0x29){CHECK(module==0x172);*(uint32_t*)arg=bad_id?7:0x172e001;return bad_dynamic?-1:0;}
 CHECK(op==0x49&&module==0&&arg==0x172e001);retired++;return fail_retire?-1:0;
}
static int allocate(uint32_t dest,void**out,uint32_t n,uint32_t wait){
 CHECK(dest==0x7a0020&&n==16&&wait==1);allocs++;
 if(allocs==fail_alloc)return -1;*out=&buffers[allocs-1][1];return 0;
}
static int send(uint32_t dest,void*msg){
 uint32_t*m=msg;sends++;CHECK(dest==0x7a0020&&m[-1]==0x172e001&&m[0]==0x7025&&!m[1]&&m[2]==(sends==1?10:6)&&m[3]==0x116);
 return sends==fail_send?-1:0;
}
static int release(uint32_t dest,void*msg){CHECK(dest==0x7a0020&&msg);frees++;return 0;}
static int event(uint32_t kind,const uint32_t*v,uint32_t n){(void)kind;CHECK(v&&n==8);events++;return events==fail_event?-1:0;}
static const struct po_api api={dynamic,allocate,send,release,event};
static void reset(void){allocs=sends=frees=retired=events=fail_alloc=fail_send=fail_event=bad_id=bad_dynamic=fail_retire=0;memset(buffers,0,sizeof buffers);}
static struct pg_observation photo(void){
 struct pg_observation s={.identity_ok=1,.config_ok=1,.complete=1,.ui=PG_UI_PHOTO,
 .mode={1,1,1},.encoder={0,0,0},.seq_done=2,.seq_target=2,.seq_applied=2,
 .key=0x7025,.dial=6,.exinfo=0x116,.backup={5,5}};return s;
}
static struct pg_observation movie(void){
 struct pg_observation s=photo();s.ui=PG_UI_MOVIE4;s.mode[0]=s.mode[1]=s.mode[2]=76;
 s.encoder[0]=3;s.seq_done=s.seq_target=s.seq_applied=8;s.dial=10;s.backup[0]=s.backup[1]=19;return s;
}
static struct pg_policy entered(void){
 struct pg_policy p={.duration_ms=1000};struct pg_observation s=photo();
 CHECK(pg_tick(&p,&s,100,0,0,1)==PG_NONE);CHECK(pg_tick(&p,&s,299,0,0,1)==PG_NONE);
 CHECK(pg_tick(&p,&s,300,0,0,1)==PG_ENTER);CHECK(p.enter_claim==1);return p;
}
static struct pg_policy preview(void){
 struct pg_policy p=entered();struct pg_observation s=movie();
 CHECK(pg_tick(&p,&s,500,1,0,1)==PG_NONE);CHECK(!p.seen_movie);
 CHECK(pg_tick(&p,&s,600,0,0,1)==PG_NONE);CHECK(pg_tick(&p,&s,800,0,0,1)==PG_NONE);
 CHECK(p.phase==PG_PREVIEW&&p.seen_movie);return p;
}
int main(void){
 struct po_owner o={0};reset();CHECK(!po_open(&o,&api));CHECK(allocs==2&&!retired&&!sends);
 CHECK(!po_command(&o,&api,PO_ENTER));CHECK(sends==1&&!retired&&!frees);
 CHECK(!po_command(&o,&api,PO_RETURN));CHECK(sends==2&&!retired&&!frees);
 CHECK(!po_command(&o,&api,PO_RETIRE));CHECK(retired==1&&o.phase==PO_RETIRED&&!frees);
 CHECK(po_command(&o,&api,PO_RETURN)<0&&sends==2&&retired==1);
 reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));CHECK(!po_lost(&o,&api));CHECK(frees==2&&retired==1&&!sends);
 reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));CHECK(!po_command(&o,&api,PO_ENTER));CHECK(po_lost(&o,&api)<0);CHECK(o.phase==PO_HOLD&&sends==1&&!retired&&!frees);
 CHECK(po_command(&o,&api,PO_RETURN)<0&&sends==1&&!retired);
 reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));CHECK(po_command(&o,&api,PO_RETIRE)<0);CHECK(!sends&&!retired);
 for(unsigned fail=1;fail<=2;fail++){
  reset();memset(&o,0,sizeof o);fail_alloc=fail;CHECK(po_open(&o,&api)<0);CHECK(!sends&&retired==1&&frees==fail-1);
 }
 for(unsigned fail=1;fail<=2;fail++){
  reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));fail_send=fail;
  int a=po_command(&o,&api,PO_ENTER);if(fail==2){CHECK(!a);CHECK(po_command(&o,&api,PO_RETURN)<0);}else CHECK(a<0);
  CHECK(o.phase==PO_HOLD&&sends==fail&&!retired&&!frees);CHECK(po_command(&o,&api,PO_RETURN)<0&&sends==fail);
 }
 reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));fail_event=events+1;
 CHECK(po_command(&o,&api,PO_ENTER)<0);CHECK(o.enter_claim&&!sends&&!retired);CHECK(po_lost(&o,&api)<0&&!retired);
 reset();memset(&o,0,sizeof o);bad_id=1;CHECK(po_open(&o,&api)<0&&!allocs&&!sends&&!retired);
 reset();memset(&o,0,sizeof o);bad_dynamic=1;CHECK(po_open(&o,&api)<0&&!allocs&&!sends&&!retired);
 reset();memset(&o,0,sizeof o);CHECK(!po_open(&o,&api));CHECK(!po_command(&o,&api,PO_ENTER));CHECK(!po_command(&o,&api,PO_RETURN));fail_retire=1;
 CHECK(po_command(&o,&api,PO_RETIRE)<0);CHECK(po_command(&o,&api,PO_RETIRE)<0&&retired==1);

 struct pg_observation ph=photo(),mv=movie();CHECK(pg_photo(&ph)&&!pg_movie(&ph));CHECK(pg_movie(&mv)&&!pg_photo(&mv));
 struct pg_policy p=preview();CHECK(pg_tick(&p,&mv,1799,0,0,1)==PG_NONE);
 CHECK(pg_tick(&p,&mv,1800,0,0,1)==PG_RETURN&&p.return_claim==1);
 CHECK(pg_tick(&p,&ph,2000,1,0,1)==PG_NONE);CHECK(pg_tick(&p,&ph,2200,0,0,1)==PG_NONE);
 CHECK(pg_tick(&p,&ph,2400,0,0,1)==PG_RETIRE);CHECK(p.phase==PG_RETIRING);
 CHECK(pg_tick(&p,&ph,2500,1,0,1)==PG_NONE&&p.phase==PG_RETIRING);
 CHECK(pg_tick(&p,&ph,2600,0,0,1)==PG_NONE&&p.phase==PG_DONE);
 CHECK(pg_tick(&p,&mv,2700,0,0,1)==PG_NONE&&p.phase==PG_DONE);
 p=entered();CHECK(pg_tick(&p,&ph,10300,0,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim&&!p.retire_claim); /* GUI rejection is not cancellation proof */
 p=entered();CHECK(pg_tick(&p,&mv,10300,1,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 p=preview();CHECK(pg_tick(&p,&mv,900,0,1,1)==PG_RETURN); /* cancel needs actual movie */
 p=preview();struct pg_observation transient=mv;transient.complete=0;
 CHECK(pg_tick(&p,&transient,900,0,1,1)==PG_NONE&&!p.return_claim);
 CHECK(pg_tick(&p,&transient,3800,0,1,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 p=preview();CHECK(pg_tick(&p,&mv,1800,0,0,1)==PG_RETURN);
 CHECK(pg_tick(&p,&mv,11800,0,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.retire_claim); /* no fake return */
 for(unsigned field=0;field<18;field++){
  p=preview();struct pg_observation wrong=mv;
  switch(field){case 0:wrong.identity_ok=0;break;case 1:wrong.config_ok=0;break;
   case 2:wrong.ui=PG_UI_UNSUPPORTED;break;case 3:wrong.mode[0]=48;break;
   case 4:wrong.mode[1]=48;break;case 5:wrong.mode[2]=48;break;
   case 6:wrong.encoder[0]=6;break;case 7:wrong.encoder[0]=0;break;
   case 8:wrong.encoder[1]=3;break;case 9:wrong.seq_done=2;break;
   case 10:wrong.seq_target=2;break;case 11:wrong.seq_applied=2;break;
   case 12:wrong.seq_queued=1;break;case 13:wrong.seq_flags=1;break;
   case 14:wrong.backup[0]=5;break;case 15:wrong.backup[1]=5;break;
   case 16:wrong.dial=6;break;default:wrong.exinfo=0;}
  CHECK(pg_tick(&p,&wrong,1800,0,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 }
 p=preview();CHECK(pg_tick(&p,&mv,1800,0,0,0)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 p=preview();CHECK(pg_tick(&p,&mv,799,0,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 p=preview();CHECK(pg_tick(&p,&mv,1800,-1,0,1)==PG_NONE&&p.phase==PG_HOLD&&!p.return_claim);
 printf("{\"assertions\":%u,\"failures\":0,\"scope\":\"portable policy and OSAL ownership callback fixtures, no hardware\"}\n",assertions);
 return 0;
}
