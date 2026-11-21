#ifndef PREVIEW_PRODUCTION_READER_H
#define PREVIEW_PRODUCTION_READER_H
#include "preview_policy.h"
#include "preview_ui_native.h"
#include "baseline_snapshot.h"
struct pr_rtos {uint32_t ctrl,param,mode[3],format[4],seq[4],flags,stateptr[3],state[3];unsigned char overrides[16];};
struct pr_result {uint32_t magic,sequence,error,reserved;struct pg_observation observation;struct pr_rtos rtos;struct pu_snapshot ui;uint32_t backup_reply[16];uint64_t request_sent_ms;struct br_snapshot baseline;};
int pr_open(const char*,unsigned,uint64_t);
int pr_sample(struct pr_result*,uint32_t,int,int);
int pr_rtos_read(pu_read,void*,struct pr_rtos*);
#endif
