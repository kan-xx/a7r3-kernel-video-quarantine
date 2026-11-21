/* Host ASan/UBSan test for quarantine-gates/vcd-bus-fence/bounded_stop_contract.c */
#include "../quarantine-gates/vcd-bus-fence/bounded_stop_contract.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct mock_bus {
    int acquire_rc;
    int req_rc;
    int pause10_rc;
    int pause1000_rc;
    int read_rc;
    unsigned read_calls;
    unsigned pause10_calls;
    unsigned pause1000_calls;
    bb_u32 statuses[64];
    unsigned status_count;
};

static unsigned checks;
#define CK(x) do { checks++; assert(x); } while (0)

static int m_acquire(void *p) { return ((struct mock_bus *)p)->acquire_rc; }
static int m_request(void *p) { return ((struct mock_bus *)p)->req_rc; }
static int m_pause(void *p, bb_u32 us) {
    struct mock_bus *m = p;
    if (us == 10) { m->pause10_calls++; return m->pause10_rc; }
    CK(us == 1000);
    m->pause1000_calls++;
    return m->pause1000_rc;
}
static int m_read(void *p, bb_u32 *out) {
    struct mock_bus *m = p;
    if (m->read_rc) return m->read_rc;
    unsigned idx = m->read_calls < m->status_count ? m->read_calls : m->status_count - 1;
    m->read_calls++;
    *out = m->statuses[idx];
    return 0;
}

static const struct bb_ops ops = { m_acquire, m_request, m_pause, m_read };

int main(void) {
    struct bb_tx tx;
    struct mock_bus m;

    /* 1. Null / bounds / bad ops fail closed without acquiring lease */
    CK(bb_attempt(0, &ops, &m, 4) == BB_BAD_INPUT);
    for (bb_u32 bad_max = 0; bad_max <= 65; bad_max += 65) {
        memset(&tx, 0, sizeof tx);
        memset(&m, 0, sizeof m);
        CK(bb_attempt(&tx, &ops, &m, bad_max) == BB_BAD_INPUT);
        CK(tx.phase == BB_REJECTED && !tx.lease_held && !tx.request_attempted);
        /* Terminal state must never allow reentry */
        CK(bb_attempt(&tx, &ops, &m, 4) == BB_REENTRY);
    }

    /* 2. Semaphore contention rejects before writing stop register */
    memset(&tx, 0, sizeof tx);
    memset(&m, 0, sizeof m);
    m.acquire_rc = -1;
    CK(bb_attempt(&tx, &ops, &m, 4) == BB_ACQUIRE_FAILED);
    CK(tx.phase == BB_REJECTED && !tx.lease_held && !tx.request_attempted);
    CK(bb_attempt(&tx, &ops, &m, 4) == BB_REENTRY);

    /* 3. Immediate zero status -> BB_FENCE_ONLY (2, NEVER 1!), lease retained */
    memset(&tx, 0, sizeof tx);
    memset(&m, 0, sizeof m);
    m.statuses[0] = 0;
    m.status_count = 1;
    int rc = bb_attempt(&tx, &ops, &m, 4);
    CK(rc == BB_FENCE_ONLY && rc != 1);
    CK(tx.phase == BB_FENCED && tx.polls == 1 && tx.last_status == 0);
    CK(tx.lease_held == 1 && tx.request_attempted == 1);
    CK(m.pause10_calls == 1 && m.pause1000_calls == 0);
    CK(bb_attempt(&tx, &ops, &m, 4) == BB_REENTRY);

    /* 4. Multi-poll drain -> BB_FENCE_ONLY on 4th poll */
    memset(&tx, 0, sizeof tx);
    memset(&m, 0, sizeof m);
    m.statuses[0] = 0x170;
    m.statuses[1] = 0x90;
    m.statuses[2] = 0x10;
    m.statuses[3] = 0;
    m.status_count = 4;
    CK(bb_attempt(&tx, &ops, &m, 4) == BB_FENCE_ONLY);
    CK(tx.polls == 4 && m.pause10_calls == 1 && m.pause1000_calls == 3 && tx.lease_held == 1);

    /* 5. Timeout / stuck bus (0x170) -> BB_QUARANTINED, lease MUST stay held */
    memset(&tx, 0, sizeof tx);
    memset(&m, 0, sizeof m);
    m.statuses[0] = 0x170;
    m.status_count = 1;
    CK(bb_attempt(&tx, &ops, &m, 64) == BB_TIMEOUT);
    CK(tx.phase == BB_QUARANTINED && tx.polls == 64 && tx.last_status == 0x170);
    CK(tx.lease_held == 1 && m.pause1000_calls == 63);

    /* 6. Request / initial-pause / read / inter-poll-pause errors quarantine with lease held */
    for (unsigned mode = 0; mode < 4; mode++) {
        memset(&tx, 0, sizeof tx);
        memset(&m, 0, sizeof m);
        m.statuses[0] = 0x170;
        m.status_count = 1;
        if (mode == 0) m.req_rc = -1;
        if (mode == 1) m.pause10_rc = -1;
        if (mode == 2) m.read_rc = -1;
        if (mode == 3) m.pause1000_rc = -1;
        int want = mode == 0 ? BB_REQUEST_FAILED : mode == 2 ? BB_READ_FAILED : BB_PAUSE_FAILED;
        CK(bb_attempt(&tx, &ops, &m, 3) == want);
        CK(tx.phase == BB_QUARANTINED && tx.lease_held == 1);
    }

    printf("BOUNDED_STOP_CONTRACT checks=%u passed=1\n", checks);
    return 0;
}
