/* Read-only cached-RAM snapshot for the stock-only timing restoration trial.
 * The caller supplies epoch/file-bound pread and an original settled-mode
 * receipt. Two equal snapshots detect changes, not atomicity or sensor FPS.
 * SGC+4 is recorded/checked as a value and never used as a read address.
 */
#include "baseline_snapshot.h"
#include "baseline_expected.h"
#include <string.h>
_Static_assert(sizeof(struct br_snapshot)==1192,"binary snapshot ABI");
static uint32_t word(const void*p,unsigned o){uint32_t n;memcpy(&n,(const char*)p+o,4);return n;}
static int ram(uint32_t p,unsigned n){return n&&p>=0x62e68000&&p<0x648c6000&&n<=0x648c6000-p;}
static int rd(br_read_fn f,void*c,uint32_t a,void*p,unsigned n){return !ram(a,n)||f(c,a,p,n)?-1:0;}
int br_check_anchors(br_read_fn f,void*c){
 unsigned char b[64];
 for(unsigned i=0;i<sizeof br_anchors/sizeof br_anchors[0];i++)
  if(rd(f,c,br_anchors[i].va,b,br_anchors[i].n)||memcmp(b,br_anchors[i].data,br_anchors[i].n))return -1;
 return 0;
}
int br_capture(br_read_fn f,void*c,struct br_snapshot*s){
 uint32_t p,v,after[3];unsigned char obj_after[80];unsigned offset=0;
 memset(s,0,sizeof*s);s->magic=0x31535242;
#define FAIL(n) do{s->error=(n);return -1;}while(0)
 if(rd(f,c,0x641fe610,&s->ctrl,4)||!ram(s->ctrl,0x274))FAIL(1);
 if(rd(f,c,s->ctrl,&v,4)||v!=0x64692730||rd(f,c,s->ctrl+0x10c,s->mode,12))FAIL(2);
 if(rd(f,c,0x641fe430,&s->param,4)||s->param!=0x641fe570||rd(f,c,s->ctrl+0x270,&p,4)||p!=s->param)FAIL(3);
 if(rd(f,c,s->param,s->param_object,80)||word(s->param_object,0)!=0x64692848||word(s->param_object,4)!=46||word(s->param_object,8)!=0x63e11168)FAIL(4);
 for(unsigned i=0;i<6;i++){
  if(word(s->param_object,br_rows[i].ptr_offset)!=br_rows[i].base)FAIL(5);
  if(rd(f,c,br_rows[i].base+33*br_rows[i].n,s->rows+offset,br_rows[i].n))FAIL(6);
  offset+=br_rows[i].n;
 }
 if(offset!=sizeof s->rows)FAIL(7);
 if(rd(f,c,0x64324568,s->drv[0],324)||rd(f,c,0x640e6eb8,s->drv[1],324))FAIL(8);
 if(rd(f,c,0x641f0558,&s->sgc,4)||s->sgc!=0x640cff78||rd(f,c,s->sgc,s->sgc_object,96)||word(s->sgc_object,4)!=0xf3120000)FAIL(9);
 if(rd(f,c,0x646d9428,s->reservation,12)||rd(f,c,0x6402f4e0,s->overrides,16))FAIL(10);
 if(rd(f,c,0x641fe430,&p,4)||p!=s->param||rd(f,c,s->param,obj_after,80)||memcmp(obj_after,s->param_object,80))FAIL(11);
 if(rd(f,c,0x641fe610,&p,4)||p!=s->ctrl||rd(f,c,s->ctrl+0x10c,after,12)||memcmp(after,s->mode,12))FAIL(12);
 if(rd(f,c,s->ctrl+0x270,&p,4)||p!=s->param||rd(f,c,0x641f0558,&p,4)||p!=s->sgc)FAIL(13);
 return 0;
#undef FAIL
}
static int valid(const struct br_snapshot*s){return s&&s->magic==0x31535242&&!s->error;}
static int mode(const struct br_snapshot*s,unsigned m){return valid(s)&&s->mode[0]==m&&s->mode[1]==m&&s->mode[2]==m;}
static int timing_same(const struct br_snapshot*a,const struct br_snapshot*b){
 return word(a->sgc_object,0x34)==word(b->sgc_object,0x34)&&word(a->sgc_object,0x38)==word(b->sgc_object,0x38)&&a->sgc_object[0x48]==b->sgc_object[0x48];
}
int br_config_same(const struct br_snapshot*a,const struct br_snapshot*b){
 return valid(a)&&valid(b)&&a->ctrl==b->ctrl&&a->param==b->param&&a->sgc==b->sgc&&
  !memcmp(a->mode,b->mode,12)&&!memcmp(a->param_object,b->param_object,80)&&!memcmp(a->rows,b->rows,308)&&
  !memcmp(a->drv,b->drv,sizeof a->drv)&&!memcmp(a->overrides,b->overrides,16)&&timing_same(a,b);
}
static int stock_rows(const struct br_snapshot*s){return !memcmp(s->rows,br_expected_rows,sizeof br_expected_rows);}
int br_check_photo_initial(const struct br_snapshot*a,const struct br_snapshot*b){
 return mode(a,1)&&mode(b,1)&&br_config_same(a,b)&&stock_rows(a)&&
  word(a->drv[0],0x30)==1&&word(a->drv[1],0x30)==1;
}
int br_check_movie_baseline(const struct br_snapshot*a,const struct br_snapshot*b){
 return mode(a,76)&&mode(b,76)&&br_config_same(a,b)&&stock_rows(a)&&
  !memcmp(a->drv[0],br_expected_drv,324)&&!memcmp(a->drv[1],br_expected_drv,324)&&
  word(a->sgc_object,0x34)==769&&word(a->sgc_object,0x38)==1869&&a->sgc_object[0x48]==0;
}
int br_check_photo_restored(const struct br_snapshot*initial,const struct br_snapshot*a,const struct br_snapshot*b){
 return mode(initial,1)&&mode(a,1)&&mode(b,1)&&br_config_same(a,b)&&stock_rows(a)&&
  !memcmp(initial->param_object,a->param_object,80)&&!memcmp(initial->rows,a->rows,308)&&
  !memcmp(initial->drv,a->drv,sizeof a->drv)&&timing_same(initial,a);
}
