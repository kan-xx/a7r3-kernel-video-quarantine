/* Offline-tested core. No publication authority on its own.
 * Caller must have separately bound these ORIGINAL imports in this boot.
 * One lock attempt only; no original functor/business invocation while held.
 */
typedef unsigned int u32;
#define TABLE ((volatile u32 *)0x641f6ba0u)
#define COUNT (*(volatile u32 *)0x641f6d20u)
#define TAIL (*(volatile u32 *)0x646c409cu)
#define ORIG 0x63cb3e05u
enum { PT_OK=0, PT_BUSY=1, PT_BOUNDS=2, PT_IDENTITY=3, PT_FOREIGN=4 };
struct table_result {
 u32 result,count,tail,own_before,own_after,changed,stage_mask,foreign;
};
static int qualified_row(volatile u32 *r) {
 if (r[2] || r[4] || r[5]!=0x641f1258u) return 0;
 if (r[0]==0x44000000u && r[3]==0x63cb4f4fu) return 1;
 if (r[0]==0x48000000u && r[3]==0x63cb492du) return 2;
 return 0;
}
__attribute__((noinline,used)) void pig_table_step(u32 gateway,u32 install,
 struct table_result *out) {
 u32 i,stage,a=16,b=16,duplicate=0;volatile u32 *r;
 out->result=PT_BUSY;out->count=out->tail=0;
 out->own_before=out->own_after=out->changed=out->stage_mask=out->foreign=0;
 if (((int(*)(u32))0x5f4e40d8u)(0x13)!=0) return;
 out->count=COUNT;out->tail=TAIL;
 if (out->count>out->tail || out->tail>16) {out->result=PT_BOUNDS;goto done;}
 /* Fixed storage is 16 rows. The inactive interval [count,tail) may retain
  * unregister/memmove copies. Clear own words there too, under the same lock.
  * Scanning these words does not interpret/follow any stale member pointers. */
 for(i=0;i<16;i++) {
  r=TABLE+6*i;if(r[1]==gateway)out->own_before++;
  if(i>=out->count)continue;
  stage=qualified_row(r);if(!stage)continue;
  if(out->stage_mask&stage)duplicate=1;
  out->stage_mask|=stage;if(stage==1)a=i;else b=i;
  if(r[1]!=ORIG && r[1]!=gateway)out->foreign++;
 }
 if(install) {
  /* Preflight every condition before either word is changed. */
  if(out->stage_mask!=3 || out->own_before || out->foreign || duplicate) {
   out->result=out->foreign?PT_FOREIGN:PT_IDENTITY;goto done;
  }
  TABLE[6*a+1]=gateway;TABLE[6*b+1]=gateway;
  out->changed=out->own_after=2;out->result=PT_OK;
 } else {
  /* Do not require the originally installed rows still exist or occupy their
   * old positions. Never overwrite a third party's function pointer. */
  for(i=0;i<16;i++)if(TABLE[6*i+1]==gateway) {
   TABLE[6*i+1]=ORIG;out->changed++;
  }
  for(i=0;i<16;i++)if(TABLE[6*i+1]==gateway)out->own_after++;
  out->result=out->foreign?PT_FOREIGN:duplicate?PT_IDENTITY:PT_OK;
 }
done:
 __asm__ volatile("dmb sy":::"memory");
 ((void(*)(u32))0x5f4e4108u)(0x13);
}
