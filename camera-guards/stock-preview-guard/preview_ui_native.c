#include "preview_ui_native.h"
#include "preview_policy.h"
#include <string.h>
static const unsigned char config_row[48]={
 0x4b,0x45,0x59,0x21,1,0,0,0,0x25,0x70,0,0,0,0,0,0,
 0x64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0x40,0,0,0,0x25,0,0x41,0,0,0,0,0,0,0,0,0};
struct reader{pu_read read;void*ctx;unsigned count;};
static int read_at(struct reader*r,uint32_t addr,void*data,uint32_t n){
 if(addr<4096||(addr&3)||!n||n>1024||addr>UINT32_MAX-n||++r->count>16)return -1;
 return r->read(r->ctx,addr,data,n);
}
static int view_at(struct reader*r,uint32_t pointer,uint32_t id,uint32_t manager,struct pu_view*out){
 uint32_t w[10];if(read_at(r,pointer,w,sizeof w))return -1;
 *out=(struct pu_view){pointer,w[6],w[0],w[1],w[5],w[8],w[9]};
 return w[6]==id&&w[9]==manager?0:-1;
}
static int root(uint32_t id){return id==0x34||id==0x92||id==0x93||id==0x94||id==0x95||id==0x96;}
int pu_snapshot_read(pu_read read,void*ctx,uint32_t obj,uint32_t view,struct pu_snapshot*s){
 struct reader r={read,ctx,0};uint32_t h[10],m[28],a[256],b[256];unsigned char row[48];
 memset(s,0,sizeof*s);
 if(!read||obj>UINT32_MAX-0x12d4ee8||view>UINT32_MAX-0x8c8d18)return -1;
 if(read_at(&r,obj+0x12d4ee8,&s->input,4)||read_at(&r,s->input,h,sizeof h)||h[0]!=obj+0x12058a0)return -2;
 s->config=h[6];s->input_count=h[7];s->cache=h[9];
 if(s->input_count!=599||s->config>UINT32_MAX-39*48||s->cache>UINT32_MAX-39*40)return -3;
 if(read_at(&r,s->config+39*48,row,sizeof row)||memcmp(row,config_row,sizeof row)||
    read_at(&r,s->cache+39*40,s->cache_words,sizeof s->cache_words))return -4;
 if(read_at(&r,obj+0x12d4c04,&s->manager,4)||read_at(&r,s->manager,m,sizeof m))return -5;
 s->slots=m[0];s->bank[0]=m[8];s->bank[1]=m[9];s->control=m[23];
 if(!s->slots||s->slots>64||read_at(&r,s->bank[0],a,s->slots*16)||
    read_at(&r,s->bank[1],b,s->slots*16)||memcmp(a,b,s->slots*16))return -6;
 unsigned primaries=0,roots95=0;
 for(unsigned i=0;i<s->slots;i++){
  uint32_t pointer=a[i*4+1],id=a[i*4+2];if(!pointer)continue;
  s->active[s->active_count][0]=i;s->active[s->active_count][1]=pointer;s->active[s->active_count++][2]=id;s->highest=id;
  if(id==0xb9||id==0x72){
   if(++primaries!=1||view_at(&r,pointer,id,s->manager,&s->primary))return -7;
  }else if(!root(id))s->other_views++;
  if(id==0x95){if(++roots95!=1||view_at(&r,pointer,id,s->manager,&s->root95))return -8;}
 }
 if(primaries!=1||roots95!=1)return -9;
 const struct pu_view*p=&s->primary,*t=&s->root95;
 s->kind=PG_UI_UNSUPPORTED;
 if(!s->other_views&&s->highest==p->id&&s->control==p->id&&!p->event){
  if(p->id==0xb9&&p->vptr==view+0x8605b8&&!p->state&&p->trigger==view+0x19a905)s->kind=PG_UI_PHOTO;
  if(p->id==0x72&&p->vptr==view+0x8c8d18&&p->state==4&&p->trigger==view+0x5d14b9&&
     t->vptr==view+0x865450&&t->state==2&&!t->event&&t->trigger==view+0x27576d)s->kind=PG_UI_MOVIE4;
 }
 s->read_count=r.count;return 0;
}
int pu_same(const struct pu_snapshot*a,const struct pu_snapshot*b){
 /* All fields are deterministic semantic identities. Unused slots are zero;
  * raw manager counters and unused object fields are deliberately absent. */
 return !memcmp(a,b,sizeof*a);
}
