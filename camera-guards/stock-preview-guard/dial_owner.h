#ifndef STOCK_PREVIEW_DIAL_OWNER_H
#define STOCK_PREVIEW_DIAL_OWNER_H
#include <stdint.h>
enum { PO_NEW=0, PO_READY, PO_ENTERED, PO_RETURNED, PO_RETIRED, PO_HOLD };
enum { PO_ENTER=1, PO_RETURN=2, PO_RETIRE=3, PO_CANCEL_UNUSED=4 };
/* All ABI calls are the frozen native_dial_event.c operations, exposed for
 * deterministic offline fault tests. Event writes must be durable before
 * returning 0. No submitted message is ever freed or resubmitted. */
struct po_api {
 int (*dynamic)(uint32_t,uint32_t,uintptr_t);
 int (*allocate)(uint32_t,void**,uint32_t,uint32_t);
 int (*send)(uint32_t,void*);
 int (*release)(uint32_t,void*);
 int (*event)(uint32_t,const uint32_t*,uint32_t);
};
struct po_owner {
 uint32_t phase,id,enter_claim,return_claim,retire_claim,send_count;
 uint32_t *messages[2];
};
int po_open(struct po_owner*,const struct po_api*);
int po_command(struct po_owner*,const struct po_api*,uint32_t);
/* EOF/controller failure: release only a source that never submitted. A
 * claimed/submitted transaction keeps source ownership and requires an
 * explicit future qualified recovery decision, never a guessed second event. */
int po_lost(struct po_owner*,const struct po_api*);
#endif
