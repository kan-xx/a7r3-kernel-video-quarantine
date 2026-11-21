#include "baseline_lease.h"
#include <string.h>
static const unsigned char payload[7]={2,3,0x4e,7,1,0xbb,0x0a};
static int allff(const unsigned char*p,unsigned n){for(unsigned i=0;i<n;i++)if(p[i]!=255)return 0;return 1;}
int bl_kind(const unsigned char b[16]){
 if(!allff(b+8,8))return BL_OTHER;
 if(allff(b,8))return BL_FF;
 if(memcmp(b,payload,7))return BL_OTHER;
 return b[7]==255?BL_RETAINED:b[7]==33?BL_ENABLED:BL_OTHER;
}
static int fail(struct bl_state*s,unsigned e){s->phase=BL_BROKEN;if(!s->error)s->error=e;return -1;}
static int readnow(struct bl_state*s,const struct bl_io*io){
 if(io->read16(io->ctx,s->after)){s->read_error=1;return fail(s,BL_READ);}return 0;
}
static int writeonce(struct bl_state*s,const struct bl_io*io,unsigned op){
 s->last_op=op;s->writes++;s->write_result=INT32_MIN;s->write_errno=0;
 int rc=io->write_fixed(io->ctx,op,&s->write_result,&s->write_errno);
 /* A failed write is NOT evidence of unchanged memory. The actual kernel's
  * copy_from_user may clear a destination byte on EFAULT. Always read back. */
 int rr=readnow(s,io);
 if(rc||s->write_result!=(op==BL_INIT7?7:1)||s->write_errno)return fail(s,BL_WRITE);
 if(rr)return -1;
 if(io->fence(io->ctx))return fail(s,BL_FENCE);
 return 0;
}
int bl_prepare(struct bl_state*s,const struct bl_io*io){
 if(s->phase!=BL_NEW||s->init_attempt||s->publish_attempt||s->retire_attempt)return fail(s,BL_ORDER);
 if(io->qualify(io->ctx))return fail(s,BL_IDENTITY);
 if(readnow(s,io))return -1;
 memcpy(s->before,s->after,16);s->initial_kind=(uint32_t)bl_kind(s->after);
 if(s->initial_kind!=BL_FF&&s->initial_kind!=BL_RETAINED)return fail(s,BL_CONTENT);
 if(s->initial_kind==BL_FF){
  s->init_attempt=1;
  if(writeonce(s,io,BL_INIT7))return -1;
 }
 if(bl_kind(s->after)!=BL_RETAINED)return fail(s,BL_CONTENT);
 s->phase=BL_PREPARED;return 0;
}
int bl_publish(struct bl_state*s,const struct bl_io*io){
 if(s->phase!=BL_PREPARED||s->publish_attempt||s->retire_attempt)return fail(s,BL_ORDER);
 if(io->qualify(io->ctx))return fail(s,BL_IDENTITY);
 if(readnow(s,io))return -1;
 if(bl_kind(s->after)!=BL_RETAINED)return fail(s,BL_CONTENT);
 /* Complete data stores before publishing the selector. This is a writer-side
  * fence, not an assertion that an unmeasured reader CPU uses acquire loads. */
 if(io->fence(io->ctx))return fail(s,BL_FENCE);
 s->publish_attempt=1;
 if(writeonce(s,io,BL_ENABLE1))return -1;
 if(bl_kind(s->after)!=BL_ENABLED)return fail(s,BL_CONTENT);
 s->phase=BL_ACTIVE;return 0;
}
int bl_retire(struct bl_state*s,const struct bl_io*io){
 if(s->retire_attempt)return fail(s,BL_ORDER);
 if(!s->init_attempt&&!s->publish_attempt&&s->phase==BL_NEW)return 0;
 if(io->qualify(io->ctx))return fail(s,BL_IDENTITY);
 if(readnow(s,io))return -1;
 int kind=bl_kind(s->after);
 if(kind==BL_RETAINED){s->phase=BL_RETIRED;return s->error?-1:0;}
 /* Initial partial-copy failure while disabled is not rewritten, nor mistaken
  * for a valid retained baseline. It remains BROKEN with actual bytes logged. */
 if(!s->publish_attempt)return fail(s,BL_CONTENT);
 /* Exact payload and second slot must remain owned. Index0 is accepted ONLY
  * after our publish attempt failed: native copy_from_user's observed EFAULT
  * behavior can zero the one destination byte. Retire it once toFF, do not
  * leave a newly created index0 override active for another sensor mode. */
 int own_zero=s->last_op==BL_ENABLE1&&s->write_result<0&&s->write_errno==14&&s->after[7]==0&&
              !memcmp(s->after,payload,7)&&allff(s->after+8,8);
 if(kind!=BL_ENABLED&&!own_zero)return fail(s,BL_CONTENT);
 if(io->fence(io->ctx))return fail(s,BL_FENCE);
 s->retire_attempt=1;
 if(writeonce(s,io,BL_DISABLE1))return -1;
 if(bl_kind(s->after)!=BL_RETAINED)return fail(s,BL_CONTENT);
 s->phase=BL_RETIRED;return s->error?-1:0;
}
int bl_expected(const struct bl_state*s,const unsigned char b[16]){
 int k=bl_kind(b);
 if(s->phase==BL_NEW)return k==BL_FF||k==BL_RETAINED;
 if(s->phase==BL_PREPARED||s->phase==BL_RETIRED)return k==BL_RETAINED;
 return s->phase==BL_ACTIVE&&k==BL_ENABLED;
}
