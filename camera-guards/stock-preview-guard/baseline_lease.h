#ifndef BASELINE_IMMUTABLE_LEASE_H
#define BASELINE_IMMUTABLE_LEASE_H
#include <stdint.h>
enum { BL_FF=1,BL_RETAINED=2,BL_ENABLED=3,BL_OTHER=4 };
enum { BL_NEW=0,BL_PREPARED,BL_ACTIVE,BL_RETIRED,BL_BROKEN };
enum { BL_INIT7=1,BL_ENABLE1,BL_DISABLE1 };
enum { BL_OK=0,BL_ORDER,BL_IDENTITY,BL_READ,BL_CONTENT,BL_WRITE,BL_FENCE };
struct bl_io {
 void *ctx;
 int (*qualify)(void*);
 int (*read16)(void*,unsigned char[16]);
 /* Fixed op only; no caller-provided address, value or pointer is exposed. */
 int (*write_fixed)(void*,unsigned op,int32_t *raw_result,int32_t *raw_errno);
 int (*fence)(void*);
};
struct bl_state {
 uint32_t phase,error,initial_kind,init_attempt,publish_attempt,retire_attempt;
 int32_t write_result,write_errno;
 uint32_t writes,last_op,read_error;
 unsigned char before[16],after[16];
};
int bl_kind(const unsigned char[16]);
int bl_prepare(struct bl_state*,const struct bl_io*);
int bl_publish(struct bl_state*,const struct bl_io*);
int bl_retire(struct bl_state*,const struct bl_io*);
/* Content expected by this exact phase. Reader recognizing three named forms
 * never grants a transaction alone; supervisor must additionally check this. */
int bl_expected(const struct bl_state*,const unsigned char[16]);
#endif
