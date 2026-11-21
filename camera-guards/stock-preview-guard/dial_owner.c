#include "dial_owner.h"
#define DEST 0x007a0020u
static int valid(uint32_t id){return (id>>16)==0x172&&(id&0x8000)&&
 (id&0x7fff)>=0x6000&&(id&0x7fff)<0x7000;}
static int record(const struct po_api*a,uint32_t kind,const struct po_owner*p,int rc){
 uint32_t v[8]={p->phase,p->id,p->enter_claim,p->return_claim,
  p->retire_claim,p->send_count,(uint32_t)rc,0};
 return a->event(kind,v,8);
}
static int hold(struct po_owner*p,const struct po_api*a,int rc){
 p->phase=PO_HOLD;(void)record(a,9,p,rc);return -1;
}
static int release_unused(struct po_owner*p,const struct po_api*a){
 int bad=0;
 for(unsigned i=0;i<2;i++)if(p->messages[i]){
  if(a->release(DEST,p->messages[i]))bad=1;
  p->messages[i]=0; /* even an uncertain free is not retryable */
 }
 return bad?-1:0;
}
static int retire(struct po_owner*p,const struct po_api*a){
 if(p->retire_claim)return hold(p,a,-30);
 p->retire_claim=1;
 if(record(a,5,p,0))return hold(p,a,-31);
 int rc=a->dynamic(0x49,0,p->id);
 if(rc)return hold(p,a,rc);
 p->phase=PO_RETIRED;
 if(record(a,6,p,0))return -1;
 return 0;
}
int po_open(struct po_owner*p,const struct po_api*a){
 if(p->phase!=PO_NEW||p->id||p->enter_claim||p->return_claim||
    p->retire_claim||p->send_count||p->messages[0]||p->messages[1])return -1;
 struct {uint32_t before,id,after;} own={0x13579bdf,0,0x2468ace0};
 int rc=a->dynamic(0x29,0x172,(uintptr_t)&own.id);
 p->id=own.id;
 if(rc)return hold(p,a,rc);
 if(own.before!=0x13579bdf||own.after!=0x2468ace0||!valid(own.id))return hold(p,a,-10);
 for(unsigned i=0;i<2;i++){
  rc=a->allocate(DEST,(void**)&p->messages[i],16,1);
  if(rc||!p->messages[i]||((uintptr_t)p->messages[i]&3)){
   /* Error allocation output is not assumed to be owned. */
   p->messages[i]=0;
   if(release_unused(p,a))return hold(p,a,-11);
   if(retire(p,a))return -1;
   return -1;
  }
  uint32_t*m=p->messages[i];m[0]=0x7025;m[1]=0;m[2]=i?6:10;m[3]=0x116;m[-1]=p->id;
 }
 p->phase=PO_READY;
 if(record(a,1,p,0)){
  if(release_unused(p,a))return hold(p,a,-12);
  (void)retire(p,a);return -1;
 }
 return 0;
}
int po_command(struct po_owner*p,const struct po_api*a,uint32_t command){
 if(command==PO_CANCEL_UNUSED){
  if(p->phase!=PO_READY||p->enter_claim||p->return_claim)return hold(p,a,-20);
  if(release_unused(p,a))return hold(p,a,-21);
  return retire(p,a);
 }
 if(command==PO_RETIRE){
  if(p->phase!=PO_RETURNED||!p->enter_claim||!p->return_claim||p->send_count!=2)return hold(p,a,-22);
  if(p->messages[0]||p->messages[1])return hold(p,a,-23);
  return retire(p,a);
 }
 unsigned index;
 if(command==PO_ENTER&&p->phase==PO_READY&&!p->enter_claim)index=0;
 else if(command==PO_RETURN&&p->phase==PO_ENTERED&&p->enter_claim&&!p->return_claim)index=1;
 else return hold(p,a,-24);
 uint32_t*m=p->messages[index];
 if(!m)return hold(p,a,-25);
 if(index)p->return_claim=1;else p->enter_claim=1;
 if(record(a,index?3:2,p,0))return hold(p,a,-26);
 /* Claim is already durable. The argument is consumed even on send error. */
 p->messages[index]=0;p->send_count++;
 int rc=a->send(DEST,m);
 if(rc)return hold(p,a,rc);
 p->phase=index?PO_RETURNED:PO_ENTERED;
 if(record(a,4,p,0))return hold(p,a,-27);
 return 0;
}
int po_lost(struct po_owner*p,const struct po_api*a){
 if(p->phase==PO_RETIRED)return 0;
 if(p->phase==PO_READY&&!p->enter_claim&&!p->return_claim)
  return po_command(p,a,PO_CANCEL_UNUSED);
 return hold(p,a,-40);
}
