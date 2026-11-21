#ifndef STOCK_PREVIEW_UI_NATIVE_H
#define STOCK_PREVIEW_UI_NATIVE_H
#include <stdint.h>
/* Transport must qualify readable maps, PID/start/boot and exact full module
 * hashes; this decoder deliberately has no transport or object calls. */
typedef int(*pu_read)(void*,uint32_t,void*,uint32_t);
struct pu_view {uint32_t pointer,id,vptr,state,event,trigger,manager;};
struct pu_snapshot {
 uint32_t input,config,cache,input_count,cache_words[10];
 uint32_t manager,slots,bank[2],control,active_count,active[64][3],highest;
 struct pu_view primary,root95;
 uint32_t other_views,kind,read_count;
};
int pu_snapshot_read(pu_read,void*,uint32_t,uint32_t,struct pu_snapshot*);
int pu_same(const struct pu_snapshot*,const struct pu_snapshot*);
#endif
