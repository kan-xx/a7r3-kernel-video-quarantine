#ifndef BASELINE_FIXED_WRITER_H
#define BASELINE_FIXED_WRITER_H
#include "baseline_lease.h"
/* Runs full existing pr_open identity qualification, locks the fixed source
 * page, binds original write_mem300B, then opens only the cached character
 * device. No write occurs here. Must precede any native-source allocation. */
int pr_baseline_open(const char*,unsigned,uint64_t,struct bl_io*);
#endif
