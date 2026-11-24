/* bytes = 0 validates user-compiled helper ELFs via bounded ARM32 ELF32
 * executable header + root 0700 stat invariance; set non-zero bytes + sha
 * to pin a specific build. */
struct worker_identity {const char*path;unsigned bytes;unsigned char sha[32];};
static const struct worker_identity worker_identities[]={
{"./preview-owner-worker.elf",0,{0}},
{"./preview-backup-worker.elf",0,{0}},
};
