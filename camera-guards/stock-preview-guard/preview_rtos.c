#include "production_reader.h"
#include <string.h>
static uint32_t word(const void*p,unsigned o){uint32_t x;memcpy(&x,(const char*)p+o,4);return x;}
int pr_rtos_read(pu_read read,void*ctx,struct pr_rtos*s){
 unsigned char ctrl[0x118],param[16],movie[0x34],head[20],q[36],flags[3];uint32_t v,p;
 memset(s,0,sizeof*s);
 if(read(ctx,0x641fe610,&s->ctrl,4)||read(ctx,s->ctrl,ctrl,sizeof ctrl)||word(ctrl,0)!=0x64692730)return 1;
 if(read(ctx,s->ctrl+0x270,&s->param,4)||read(ctx,s->param,param,sizeof param)||word(param,0)!=0x64692848||word(param,4)!=46||word(param,8)!=0x63e11168)return 2;
 for(unsigned i=0;i<3;i++)s->mode[i]=word(ctrl,0x10c+4*i);
 if(read(ctx,0x645f7ff0,movie,sizeof movie)||read(ctx,0x6402f4e0,s->overrides,16)||read(ctx,0x643375f4,q,36)||read(ctx,0x6465d482,flags,3))return 3;
 for(unsigned i=0;i<4;i++)s->format[i]=word(movie,(unsigned[]){0x20,0x24,0x2c,0x30}[i]);
 s->seq[0]=word(q,0);s->seq[1]=word(q,4);s->seq[2]=word(q,28);s->seq[3]=word(q,32);
 s->flags=flags[0]|((uint32_t)flags[1]<<8)|((uint32_t)flags[2]<<16);
 const uint32_t root=0x64139e18;const unsigned offset[3]={0x2f8,0xf148,0x1df98};
 if(read(ctx,root,&v,4)||v!=0x646960e8)return 4;
 for(unsigned i=0;i<3;i++){
  uint32_t core=root+offset[i]+0x18;
  if(read(ctx,core,head,20)||word(head,0)!=root+0x2c8+0x10*i||word(head,16)!=0x64695ac0||
     read(ctx,word(head,0),&v,4)||v!=i||read(ctx,word(head,4),&p,4)||read(ctx,p,head,8)||word(head,0)!=core)return 5;
  s->stateptr[i]=p;s->state[i]=word(head,4);
 }
 if(read(ctx,0x641fe610,&v,4)||v!=s->ctrl)return 6;
 return 0;
}
