#include "guard_policy.h"
#include <assert.h>
#include <stdio.h>
static unsigned checks;
#define CK(x) do{checks++;assert(x);}while(0)
static struct rg_sample idle={1,1,{0,0,0},1},run={1,1,{6,0,0},1};
static struct rg_policy started(void){struct rg_policy p={.duration_ms=20000};CK(rg_tick(&p,&idle,100,0)==RG_NONE);CK(rg_tick(&p,&idle,300,0)==RG_START);CK(p.start_claim==1&&p.stop_claim==0);return p;}
int main(void){
 struct rg_policy p=started();CK(rg_tick(&p,&run,500,1)==RG_NONE&&p.phase==RG_STARTING);CK(rg_tick(&p,&run,1500,0)==RG_NONE&&p.phase==RG_RUNNING);CK(rg_tick(&p,&run,20299,0)==RG_NONE);CK(rg_tick(&p,&run,20300,0)==RG_STOP&&p.stop_claim==1);CK(rg_tick(&p,&run,20400,1)==RG_NONE);CK(rg_tick(&p,&idle,20500,0)==RG_NONE);CK(rg_tick(&p,&idle,20700,0)==RG_FINISH&&p.phase==RG_DONE);for(unsigned i=0;i<10;i++)CK(rg_tick(&p,&run,21000+i,0)==RG_FINISH&&p.stop_claim==1);
 for(unsigned mode=0;mode<10;mode++){p=started();struct rg_sample s=run;int key=0;uint64_t now=1500;
  if(mode==0)s.epoch_ok=0;if(mode==1)s.qualified=0;if(mode==2)s.generation_same=0;if(mode==3)key=-1;if(mode==4){key=1;now=10300;}if(mode==5){s=idle;now=8300;}if(mode==6)now=200;
  if(mode>=7){CK(rg_tick(&p,&run,1500,0)==RG_NONE);now=20300;if(mode==7)s=idle;if(mode==8)s.state[0]=5;if(mode==9)s.state[1]=6;}
  CK(rg_tick(&p,&s,now,key)==RG_FINISH&&p.phase==RG_FAILED&&p.stop_claim==0);for(unsigned i=0;i<4;i++)CK(rg_tick(&p,&run,22000+i,0)==RG_FINISH&&p.stop_claim==0);
 }
 p=started();CK(rg_tick(&p,&run,1500,0)==RG_NONE);CK(rg_tick(&p,&run,20300,0)==RG_STOP);CK(rg_tick(&p,&run,30300,0)==RG_FINISH&&p.error==RG_STOP_TIMEOUT&&p.stop_claim==1);
 p=started();CK(rg_tick(&p,&run,1500,0)==RG_NONE);CK(rg_tick(&p,&run,20300,0)==RG_STOP);CK(rg_tick(&p,&idle,20500,-1)==RG_FINISH&&p.error==RG_STOP_KEY);
 for(unsigned d=0;d<2;d++){p=(struct rg_policy){.duration_ms=d?30001:999};CK(rg_tick(&p,&idle,0,0)==RG_FINISH&&p.error==RG_BASELINE&&!p.start_claim);}
 printf("policy checks=%u passed\n",checks);return 0;
}
