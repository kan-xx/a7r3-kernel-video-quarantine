#ifndef STOCK_RECORD_GUARD_LINEAGE_H
#define STOCK_RECORD_GUARD_LINEAGE_H
#include "guard_policy.h"
/* 1 allowed coherent mode, 2 bounded transition wait, 0 disallowed.
 * These are observed stock sensor IDs, not guessed sensor capabilities. */
int rg_modes(unsigned,const uint32_t[3],const uint32_t[3],const uint32_t[3]);
int rg_baseline_restored(const uint32_t*base,const uint32_t*now);
#endif
