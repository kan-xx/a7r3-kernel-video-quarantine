#ifndef STOCK_BASELINE_SNAPSHOT_H
#define STOCK_BASELINE_SNAPSHOT_H
#include <stdint.h>
typedef int (*br_read_fn)(void*,uint32_t,void*,uint32_t);
struct br_snapshot {
 uint32_t magic,error,mode[3],ctrl,param,sgc;
 unsigned char param_object[80],rows[308],drv[2][324],sgc_object[96],reservation[12],overrides[16];
};
int br_check_anchors(br_read_fn,void*);
int br_capture(br_read_fn,void*,struct br_snapshot*);
int br_config_same(const struct br_snapshot*,const struct br_snapshot*);
int br_check_photo_initial(const struct br_snapshot*,const struct br_snapshot*);
int br_check_movie_baseline(const struct br_snapshot*,const struct br_snapshot*);
int br_check_photo_restored(const struct br_snapshot*,const struct br_snapshot*,const struct br_snapshot*);
#endif
