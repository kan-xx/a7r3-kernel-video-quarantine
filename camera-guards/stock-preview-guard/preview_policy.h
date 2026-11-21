#ifndef STOCK_PREVIEW_POLICY_H
#define STOCK_PREVIEW_POLICY_H
#include <stdint.h>
enum { PG_PRE=0, PG_ENTERING, PG_PREVIEW, PG_RETURNING, PG_RETIRING, PG_DONE, PG_HOLD };
enum { PG_NONE=0, PG_ENTER=1, PG_RETURN=2, PG_RETIRE=3 };
enum { PG_OK=0, PG_IDENTITY=1, PG_CONFIG, PG_OBSERVE, PG_BASELINE,
       PG_ENTER_IO, PG_ENTER_TIMEOUT, PG_RETURN_IO, PG_RETURN_TIMEOUT,
       PG_RETIRE_IO, PG_CLOCK, PG_JOURNAL, PG_CANCELLED, PG_UNEXPECTED };
enum { PG_UI_TRANSIENT=0, PG_UI_PHOTO=1, PG_UI_MOVIE4=2, PG_UI_UNSUPPORTED=3 };
/* Complete denotes a fully qualified, internally stable acquisition. A
 * transient observation cannot authorize an action or a terminal result.
 * Identity/config checks must still run when complete is false. */
struct pg_observation {
 uint32_t identity_ok,config_ok,complete,ui;
 uint32_t mode[3],encoder[3],seq_done,seq_target,seq_applied,seq_queued;
 uint32_t seq_flags,key,subkey,dial,exinfo,backup[2];
};
struct pg_policy {
 uint32_t phase,error,enter_claim,return_claim,retire_claim,seen_movie,stable;
 uint32_t duration_ms;
 uint64_t last_ms,enter_ms,preview_ms,return_ms,stable_ms;
};
/* Worker result: 0 completed successfully, 1 pending, -1 ambiguous/failure.
 * Cancellation is cooperative; it never creates a missing movie-ready proof.
 * Returned actions are consumed exactly once and must be durably journaled
 * BEFORE a private worker command is sent. No recovery/reset API exists. */
int pg_tick(struct pg_policy*,const struct pg_observation*,uint64_t,int,int,int);
int pg_photo(const struct pg_observation*);
int pg_movie(const struct pg_observation*);
#endif
