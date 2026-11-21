/* LOCAL CANDIDATE, NOT A DEVICE ADAPTER. All four callbacks require independent
 * boundedness, object lifetime, execution-domain and hardware qualification.
 * Native osal_wai_sem_tmo(0) and native delay RPC do NOT meet that contract yet.
 */
typedef unsigned int bb_u32;
struct bb_ops {
    int (*try_acquire)(void *);
    int (*request_zero)(void *);
    int (*pause)(void *,bb_u32 native_argument);
    int (*read_status)(void *,bb_u32 *);
};
struct bb_tx {
    bb_u32 phase;
    int result;
    bb_u32 polls;
    bb_u32 last_status;
    bb_u32 lease_held;
    bb_u32 request_attempted;
};
enum { BB_NEW=0,BB_ACQUIRING=1,BB_STOP_REQUESTED=2,
       BB_FENCED=3,BB_QUARANTINED=4,BB_REJECTED=5 };
/* Result 1 is RESERVED for a future separately proved complete cleanup gate.
 * This implementation NEVER returns 1, even when the bus status reaches zero.
 */
enum { BB_FENCE_ONLY=2,BB_BAD_INPUT=-1,BB_ACQUIRE_FAILED=-2,
       BB_REQUEST_FAILED=-3,BB_PAUSE_FAILED=-4,BB_TIMEOUT=-5,
       BB_READ_FAILED=-6,BB_REENTRY=-7 };
int bb_attempt(struct bb_tx *,const struct bb_ops *,void *,bb_u32 max_polls);
