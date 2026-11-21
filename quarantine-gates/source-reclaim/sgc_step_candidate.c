/* Offline candidate; no installer/module entry.
 * One recovery-owned controller calls <=16 steps. Native lock is attempted
 * once per step; each masked capture section has <=64 hardware-status reads.
 * Stop failure never restarts, releases a job, returns a buffer or fakes IRQ.
 * Success means the native SGC idle condition only, NOT full pipeline drain.
 * Required external lease excludes source reconfiguration and owns both PIG
 * halves and H5/H8; the read-only identity package does not create that lease.
 */
typedef unsigned int u32;typedef unsigned char u8;
enum {NEW=0,WINDOW=1,FINAL=2,IDLE=3,FAILED=4};
enum {DONE=0,WAIT_LOCK=1,WAIT_WINDOW=10,WAIT_FINAL=11,ERR_CAPTURE=0x1001,ERR_WINDOW=0x1002,ERR_FINAL=0x1003,ERR_BUDGET=0x1004,ERR_IDENTITY=0x1005};
struct sr_sgc_profile {u32 object,trylock,unlock;};
struct sr_sgc_context {u32 phase,steps,window_attempts,final_attempts,error,side_effects,enable_zero_written,native_idle_observed;};
static u32 rd(u32 a){return *(volatile u32*)a;}
static void wr(u32 a,u32 v){*(volatile u32*)a=v;}
static int identity(const struct sr_sgc_profile*p){return p->object==0x640cff78u&&rd(0x641f0558)==p->object&&rd(p->object)==0x64690f30u&&rd(p->object+4)==0xf3120000u&&rd(p->object+0x4c)==0x638d49adu&&rd(0x641fe610)==0x641fe1c0u&&rd(0x641fe1c0)==0x64692730u&&rd(0x635c6240)==p->trylock&&rd(0x635c6244)==p->unlock;}
static u32 fail(struct sr_sgc_context*c,u32 e){c->phase=FAILED;c->error=e;return e;}
u32 sr_sgc_step(const struct sr_sgc_profile*p,struct sr_sgc_context*c){
 u32 o=p->object,n,packed,lo,hi,status,window,callback_result;
 if(c->phase==FAILED)return c->error;
 if(c->phase==IDLE)return DONE;
 if(c->phase>FINAL||c->steps>=16)return fail(c,ERR_BUDGET);
 c->steps++;
 if(!identity(p)||p->trylock<0x5f000000u||p->trylock>=0x60000000u||p->unlock<0x5f000000u||p->unlock>=0x60000000u||(c->phase==FINAL&&rd(o+0x20)!=5))return fail(c,ERR_IDENTITY);
 if(c->phase!=FINAL){
  if(((int(*)(u32))p->trylock)(0x13)!=0)return c->steps>=16?fail(c,ERR_BUDGET):WAIT_LOCK;
  if(!identity(p)||(c->phase==NEW?rd(o+0x20)>1:rd(o+0x20)!=5)){
   ((void(*)(u32))p->unlock)(0x13);return fail(c,ERR_IDENTITY);
  }
  if(c->phase==NEW){
   wr(o+0x20,5);*(volatile u8*)(o+0x48)=0;wr(o+0x34,1);wr(o+0x38,1);wr(o+0x30,0);
   wr(0xf3120248,0x3ffe3ffe);wr(0xf3120210,0);c->side_effects=1;c->phase=WINDOW;
  }
  c->window_attempts++;
  wr(0xf3120038,0x100);wr(0xf3000038,0x100);wr(0xf3100038,0x100);
  status=rd(0xf312003c)&3;window=rd(0xf3120210)&1;
  wr(0xf3120214,1);
  for(n=0;n<64;n++)if(!(rd(0xf3120214)&1))break;
  if(n==64){((void(*)(u32))p->unlock)(0x13);return fail(c,ERR_CAPTURE);}
  packed=rd(0xf3120218);lo=packed&0x3fff;hi=(packed>>16)&0x3fff;
  if(lo==0x3fff)window^=1;else window=lo>4&&lo<rd(o+0x38)-2;
  callback_result=((u32(*)(u32,u32))0x638d49adu)(rd(o+0x38),lo);
  if(callback_result||!window){
   ((void(*)(u32))p->unlock)(0x13);
   if(c->window_attempts>=8||c->steps>=16)return fail(c,ERR_WINDOW);
   return WAIT_WINDOW;
  }
  wr(0xf3120200,0);c->enable_zero_written=1;
  ((void(*)(u32))p->unlock)(0x13);
  wr(o+0x44,status);wr(o+0x3c,hi);wr(o+0x40,lo);c->phase=FINAL;
 }
 c->final_attempts++;
 for(n=0;n<64;n++)if(!(rd(0xf3120210)&0x10000))break;
 if(n==64){if(c->final_attempts>=8||c->steps>=16)return fail(c,ERR_FINAL);return WAIT_FINAL;}
 c->native_idle_observed=1;c->phase=IDLE;return DONE;
}
