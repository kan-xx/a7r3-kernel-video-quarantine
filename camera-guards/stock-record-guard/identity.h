/* Set key_bytes = 0 to validate user-compiled local-rec-key.elf via bounded
 * ARM32 ELF32 executable header + root 0700 stat invariance; set non-zero
 * key_bytes + key_hash to pin a specific build. Stock FW 3.10 files below
 * always retain exact SHA-256 verification. */
static const unsigned char key_hash[32]={0};
static const unsigned key_bytes=0;
struct identity_entry {const char *path;unsigned bytes;unsigned char sha[32];};
static const struct identity_entry identities[]={
{"/usr/bin/im.elf",21868,{134,103,41,235,11,193,230,245,171,160,77,139,248,228,84,145,152,90,254,137,160,120,204,177,6,161,206,36,118,134,82,37}},
{"/usr/lib/libosal_uipc.so",26692,{182,222,211,90,221,149,130,65,59,64,28,244,219,120,236,44,154,32,27,99,46,120,194,115,29,107,187,55,146,73,179,235}},
{"/lib/libc-2.11.2.so",984276,{188,235,92,251,119,105,181,75,249,201,209,120,184,165,244,87,149,49,192,246,14,103,60,188,174,135,42,140,122,53,8,251}},
{"/lib/libdl-2.11.2.so",13968,{236,134,163,67,140,247,223,25,81,190,48,35,179,221,201,13,91,99,96,250,72,230,13,32,204,139,73,122,99,69,239,53}},
{"/lib/ld-2.11.2.so",101720,{124,33,92,238,108,65,117,7,157,105,203,20,51,198,190,144,24,158,121,63,110,68,240,104,237,106,201,118,33,221,122,44}},
};
