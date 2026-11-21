/* OFFLINE CANDIDATE ONLY. Not a module and no install/entry publication exists.
 * Before invoking: qualify/pin current kernel+osal code, descriptor and memory;
 * close new-command admission; qualify recovery task, owner, bus mapping/clock.
 * Neither a matching pointer nor these checks establish those prerequisites.
 * All writes below are exercised ONLY against emulator RAM by this branch.
 */
typedef unsigned int u32;
extern int bb_sem_try_task_publish(void *existing_qualified_bsem,u32 *lease_held);
struct br_binding { u32 owner,sem_object,max_polls,expected_lpj; };
struct br_result { u32 phase; int result; u32 polls,status,lease_held,requested; };
enum { BR_NEW=0,BR_ACQUIRING=1,BR_STOP_REQUESTED=2,BR_FENCED=3,BR_QUARANTINED=4,BR_REJECTED=5 };
enum { BR_FENCE_ONLY=2,BR_BAD_BINDING=-1,BR_ACQUIRE_FAILED=-2,BR_CHANGED_BINDING=-3,BR_TIMEOUT=-5,BR_REENTRY=-7 };
#define VCD_BASE_GLOBAL ((volatile u32 *)0x6466d490U)
#define LPJ ((volatile u32 *)0x604b74e8U)
#define STATUS ((volatile u32 *)0xf4001000U)
#define REQUEST ((volatile u32 *)0xf4001004U)
static void barrier(void) { __asm__ volatile("dmb sy":::"memory"); }
static void delay_us(u32 n) { ((void (*)(u32))0x6025799cU)(n); }
static int end(struct br_result *r,u32 phase,int value) {r->phase=phase;r->result=value;return value;}
int br_native_fence_only(u32 owner_plus8,const struct br_binding *b,struct br_result *r) {
    if(!r)return BR_BAD_BINDING;
    if(r->phase!=BR_NEW)return BR_REENTRY;
    if(!b || b->owner<0x635c6000U || b->owner>0x648c5ff4U || (b->owner&3) ||
       owner_plus8!=b->owner+8 || b->sem_object<0x60100000U ||
       b->sem_object>0x787ffff0U || (b->sem_object&3) ||
       !b->max_polls || b->max_polls>64 || !b->expected_lpj || b->expected_lpj>0x1ffffffU)
        return end(r,BR_REJECTED,BR_BAD_BINDING);
    if(*VCD_BASE_GLOBAL!=0xf4000000U || *LPJ!=b->expected_lpj)
        return end(r,BR_REJECTED,BR_BAD_BINDING);
    r->polls=0;r->status=0xffffffffU;r->lease_held=0;r->requested=0;r->phase=BR_ACQUIRING;
    if(bb_sem_try_task_publish((void*)b->sem_object,&r->lease_held)!=0)
        return end(r,BR_REJECTED,BR_ACQUIRE_FAILED);
    r->lease_held=1;
    if(*VCD_BASE_GLOBAL!=0xf4000000U || *LPJ!=b->expected_lpj)
        return end(r,BR_QUARANTINED,BR_CHANGED_BINDING);
    r->phase=BR_STOP_REQUESTED;r->requested=1;
    *REQUEST=0;barrier();delay_us(10);
    while(r->polls<b->max_polls) {
        r->status=*STATUS;r->polls++;
        if(!r->status)return end(r,BR_FENCED,BR_FENCE_ONLY);
        if(r->polls==b->max_polls)break;
        delay_us(1000);
    }
    return end(r,BR_QUARANTINED,BR_TIMEOUT);
}
/* No path returns cleanup permission1, releases the retained semaphore,
 * invokes reset/free, acknowledges stop/remove, or reports recorder recovery.
 */
