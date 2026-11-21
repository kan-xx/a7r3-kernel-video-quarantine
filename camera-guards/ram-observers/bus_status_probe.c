/* One-word, read-only active-recording baseline. Never requests STOP or RESET.
 * The original wait loop polls this same word with LDR. A zero value without
 * a preceding qualified stop request DOES NOT prove a fence or DMA idle.
 * Linux cannot guarantee a timeout if an unclocked peripheral stalls a read.
 */
#define main input_sampler_unused_main
#include "input_sampler_v3.c"
#undef main
#include <sys/mman.h>
#include "bus_status_anchors.h"

static int active(const struct sample *s) {
    static const uint32_t format[4]={4,2,0,6};
    if(s->mode[0]!=76||s->mode[1]!=76||
       (s->mode[2]!=48&&s->mode[2]!=76)||
       memcmp(s->format,format,sizeof format)||
       s->encoder[0].state_raw!=6||s->encoder[1].state_raw||s->encoder[2].state_raw||
       s->input.pig_vtable!=0x64690890u)return 0;
    for(unsigned i=0;i<sizeof s->override;i++)if(s->override[i]!=255)return 0;
    return 1;
}

int main(int argc,char **argv) {
    int result=0;uint32_t base=0;unsigned char code[184];
    struct sample before,after;
#ifdef HOST_FIXTURE
    if(argc!=3)return 2;
    memory_fd=open(argv[1],O_RDONLY|O_CLOEXEC);
#else
    (void)argv;if(argc!=1)return 2;
    char cmd[2048],version[8];
    if(textfile("/proc/cmdline",cmd,sizeof cmd)<0||!strstr(cmd,"memrsv=0x1A5E000@0x02E68000")||!strstr(cmd,"mem=1G@0"))return 3;
    if(textfile("/setting/updater/dat4",version,sizeof version)!=2||version[0]!=0x10||version[1]!=3)return 4;
    memory_fd=open("/dev/mem",O_RDONLY|O_CLOEXEC);
#endif
    if(memory_fd<0)return 6;
    for(unsigned i=0;i<sizeof anchors/sizeof anchors[0];i++)
        if(phys(anchors[i].va,code,anchors[i].n)||memcmp(code,anchors[i].data,anchors[i].n)){result=8;goto done;}
    for(unsigned i=0;i<sizeof bus_anchors/sizeof bus_anchors[0];i++)
        if(phys(bus_anchors[i].va,code,bus_anchors[i].n)||memcmp(code,bus_anchors[i].data,bus_anchors[i].n)){result=9;goto done;}
    if(phys(0x6466d490u,&base,4)||base!=0xf4000000u){result=10;goto done;}
    if(snapshot(&before)||!active(&before)){result=11;goto done;}
#ifdef HOST_FIXTURE
    int mmio_fd=open(argv[2],O_RDONLY|O_CLOEXEC);off_t offset=0;
#else
    int mmio_fd=open("/dev/mem",O_RDONLY|O_CLOEXEC);off_t offset=0xf4001000u;
#endif
    if(mmio_fd<0){result=12;goto done;}
    void *mapped=mmap(0,4096,PROT_READ,MAP_SHARED,mmio_fd,offset);
    close(mmio_fd);
    if(mapped==MAP_FAILED){result=13;goto done;}
    /* Recheck immediately before the single aligned volatile 32-bit load. */
    if(snapshot(&before)||!active(&before)){result=14;munmap(mapped,4096);goto done;}
    uint64_t t0=ns();
    uint32_t value=*(volatile const uint32_t *)mapped;
    uint64_t t1=ns();
    if(munmap(mapped,4096)){result=15;goto done;}
    if(snapshot(&after)||!active(&after)||before.ctrl!=after.ctrl||before.param!=after.param){result=16;goto done;}
    printf("{\"address\":\"0xf4001000\",\"value\":%u,\"loads\":1,\"start_ns\":%llu,\"end_ns\":%llu,\"native_stock_4k25_active_before_after\":true,\"hardware_write\":false,\"stop_requested\":false,\"fence_proved\":false,\"dma_idle_proved\":false}\n",value,(unsigned long long)t0,(unsigned long long)t1);
done:
    if(close(memory_fd)&&!result)result=17;
    return result;
}
