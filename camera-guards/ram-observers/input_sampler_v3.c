/* Read-only CamCore metadata/PQD-statistics and configuration sampler.
 * Reuses qualified reserved-RAM reader and encoder object chain.
 * No camera calls, IRQ hooks, memory/cache writes, or MMIO reads.
 * Metadata/statistics observations do NOT prove independent sensor frames. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include "observer_anchors_v2.h"
#define PA_BEGIN 0x02e68000u
#define PA_END 0x048c6000u
static int memory_fd=-1;
static volatile sig_atomic_t stopped;
static void stop(int x) {(void)x;stopped=1;}
static int phys(uint32_t va,void *out,unsigned n) {
    if(va<0x60000000u)return -1;
    uint32_t pa=va-0x60000000u;
    if(!n||n>8192||pa<PA_BEGIN||pa>=PA_END||n>PA_END-pa)return -1;
#ifdef HOST_FIXTURE
    off_t offset=(off_t)(pa-PA_BEGIN);
#else
    off_t offset=(off_t)pa;
#endif
    /* One exact bounded request: short/error reads fail closed, no retry loop. */
    ssize_t got=pread(memory_fd,out,n,offset);
    return got==(ssize_t)n?0:-1;
}
static uint32_t w(const void *b,unsigned o){uint32_t v;memcpy(&v,(const char*)b+o,4);return v;}
#ifndef HOST_FIXTURE
static int textfile(const char *p,char *b,size_t n){int f=open(p,O_RDONLY|O_CLOEXEC);if(f<0)return -1;ssize_t z=read(f,b,n-1);close(f);if(z<0)return -1;b[z]=0;return (int)z;}
#endif
static void hex(const unsigned char *p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static uint64_t ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return(uint64_t)t.tv_sec*1000000000u+(unsigned)t.tv_nsec;}
#ifdef INCLUDE_ENCODER
#include "encoder_snapshot.h"
#define POLL_MS 50
#define OBSERVER_ABI 5
#define MAX_SECONDS 20
#else
#define POLL_MS 50
#define OBSERVER_ABI 1
#define MAX_SECONDS 20
#endif

struct input_sample {
    unsigned char producer[12], latched[12], stats[12];
    uint32_t pipeline[3], pig_vtable, stats_root, callback[3];
    uint16_t completed_kind, calls;
};
static unsigned h(const void *b,unsigned o){uint16_t v;memcpy(&v,(const char*)b+o,2);return v;}
static int input_snapshot(struct input_sample *s){
    memset(s,0,sizeof *s);
    if(phys(0x641f0598u,&s->pig_vtable,4)||(s->pig_vtable!=0x64690710u&&s->pig_vtable!=0x64690890u))return 30;
    if(phys(0x647316a4u,&s->stats_root,4)||s->stats_root!=0x64189cd0u)return 31;
    if(phys(0x64352e5cu,s->producer,12)||phys(0x64352df0u,s->latched,12)||
       phys(0x64628502u,&s->completed_kind,2)||phys(0x643538e8u,s->pipeline,12)||
       phys(0x6418afe4u,s->stats,12)||phys(0x6418b296u,&s->calls,2)||
       phys(0x641f0618u,s->callback,12))return 32;
    /* Pipeline pointers are reported, never followed. Callback pointers are never called. */
    return 0;
}
static void input_print(const struct input_sample *s){
    printf("{\"pig0_vtable\":%u,\"pig0_type\":\"%s\",\"producer\":\"",s->pig_vtable,s->pig_vtable==0x64690890u?"SplitEEController":"EEController");hex(s->producer,12);printf("\",\"latched\":\"");hex(s->latched,12);
    printf("\",\"producer_sequence_candidate\":%u,\"latched_sequence_candidate\":%u,\"completed_kind\":%u,\"stats\":\"",w(s->producer,4),w(s->latched,4),s->completed_kind);hex(s->stats,12);
    printf("\",\"ydet_success_count_u16\":%u,\"ydet_total_calls_u16\":%u,\"pipeline_roots\":[%u,%u,%u],\"callbacks\":[%u,%u,%u]}",h(s->stats,8),s->calls,s->pipeline[0],s->pipeline[1],s->pipeline[2],s->callback[0],s->callback[1],s->callback[2]);
}

struct sample {
    struct input_sample input;
    uint32_t ctrl,param,mode[3],sync[2],format[4];
    int32_t index;
    unsigned char override[16],cs[48],cc[120],ec[52];
#ifdef INCLUDE_ENCODER
    struct encoder_sample encoder[3];
#endif
};
static int snapshot(struct sample *s){
    unsigned char obj[80],ctrl[0x118],movie[0x34];uint32_t v,ids[46];
    memset(s,0,sizeof *s);s->index=-1;
    if(phys(0x641fe610,&s->ctrl,4)||phys(s->ctrl,ctrl,sizeof ctrl)||w(ctrl,0)!=0x64692730)return 10;
    if(phys(s->ctrl+0x270,&s->param,4)||phys(s->param,obj,sizeof obj)||w(obj,0)!=0x64692848||w(obj,4)!=46||w(obj,8)!=0x63e11168)return 11;
    for(unsigned i=0;i<3;i++)s->mode[i]=w(ctrl,0x10c+i*4);
    if(phys(0x63e11168,ids,sizeof ids)||phys(0x6402f4e0,s->override,16)||phys(0x64354034,s->sync,8)||phys(0x645f7ff0,movie,sizeof movie))return 12;
    for(unsigned i=0;i<4;i++)s->format[i]=w(movie,(unsigned[]){0x20,0x24,0x2c,0x30}[i]);
    for(unsigned i=0;i<46;i++)if(ids[i]==s->mode[0])s->index=(int)i;
    if(s->index>=0){unsigned i=(unsigned)s->index;
        if(phys(w(obj,0x10)+48*i,s->cs,48)||phys(w(obj,0x14)+120*i,s->cc,120)||phys(w(obj,0x18)+52*i,s->ec,52))return 13;
    }
    if(phys(0x641fe610,&v,4)||v!=s->ctrl)return 14;
#ifdef INCLUDE_ENCODER
    for(unsigned i=0;i<3;i++){int rc=encoder_snapshot(&s->encoder[i],i);if(rc)return rc;}
#endif
    return input_snapshot(&s->input);
}
int main(int argc,char **argv){
    char *end;long seconds;int fd;char boot[80]="HOST_FIXTURE";
#ifdef HOST_FIXTURE
    if(argc!=3)return 2;seconds=strtol(argv[2],&end,10);fd=open(argv[1],O_RDONLY);
#else
    if(argc!=2)return 2;seconds=strtol(argv[1],&end,10);
    char cmd[2048],version[8];
    if(textfile("/proc/cmdline",cmd,sizeof cmd)<0||!strstr(cmd,"memrsv=0x1A5E000@0x02E68000")||!strstr(cmd,"mem=1G@0"))return 3;
    if(textfile("/setting/updater/dat4",version,sizeof version)!=2||version[0]!=0x10||version[1]!=3)return 4;
    if(textfile("/proc/sys/kernel/random/boot_id",boot,sizeof boot)<36)return 5;
    for(unsigned i=0;boot[i];i++)if(!strchr("0123456789abcdef-\n",boot[i]))return 5;
    boot[strcspn(boot,"\n")]=0;
    fd=open("/dev/mem",O_RDONLY|O_CLOEXEC);
#endif
    if(*end||seconds<1||seconds>MAX_SECONDS){if(fd>=0)close(fd);return 2;}
    if(fd<0)return 6;
    memory_fd=fd;
    unsigned char anchor[184];int result=0;
    for(unsigned i=0;i<sizeof anchors/sizeof anchors[0];i++)if(phys(anchors[i].va,anchor,anchors[i].n)||memcmp(anchor,anchors[i].data,anchors[i].n)){result=8;goto done;}
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,stop);
    uint64_t start=ns();if(!start){result=9;goto done;}
    printf("{\"type\":\"header\",\"abi\":%d,\"boot_id\":\"%s\",\"seconds\":%ld,\"period_ms\":%d,\"read_method\":\"dev_mem_pread_kernel_linear_mapping\",\"new_mapping_created\":false,\"frame_events_measured\":false,\"memory_writes\":false,\"mmio_read\":false,\"cache_operations\":false,\"cpu_cache_consistency_proved\":false,\"independent_sensor_frames_proved\":false}\n",OBSERVER_ABI,boot,seconds,POLL_MS);
    for(unsigned count=0;count<(unsigned)seconds*(1000/POLL_MS)&&!stopped;count++){
        if(ns()-start>=(uint64_t)seconds*1000000000u)break;
        uint64_t t0=ns();struct sample a,b;int x=snapshot(&a),y=snapshot(&b);uint64_t t1=ns();
        if(x||y){fprintf(stderr,"snapshot identity/read failure: %d/%d, PIG0 vptr %08x/%08x\n",x,y,a.input.pig_vtable,b.input.pig_vtable);result=x?x:y;break;}
        int stable=!memcmp(&a,&b,sizeof a);
        printf("{\"type\":\"sample\",\"elapsed_ns\":%llu,\"stable\":%s,\"modes\":[%u,%u,%u],\"index\":%d,\"sync\":[%u,%u],\"format\":[%u,%u,%u,%u],\"overrides\":\"",(unsigned long long)(ns()-start),stable?"true":"false",a.mode[0],a.mode[1],a.mode[2],a.index,a.sync[0],a.sync[1],a.format[0],a.format[1],a.format[2],a.format[3]);
        hex(a.override,16);printf("\",\"cs\":\"");hex(a.cs,48);printf("\",\"cc\":\"");hex(a.cc,120);printf("\",\"ec\":\"");hex(a.ec,52);printf("\"");
#ifdef INCLUDE_ENCODER
        printf(",\"encoders\":[");for(unsigned i=0;i<3;i++){if(i)printf(",");encoder_print(&a.encoder[i]);}printf("]");
#endif
        printf(",\"monotonic_start_ns\":%llu,\"monotonic_end_ns\":%llu,\"metadata_double_read_equal\":%s,\"stats_double_read_equal\":%s,\"input_a\":",(unsigned long long)t0,(unsigned long long)t1,
            !memcmp(a.input.producer,b.input.producer,12)&&!memcmp(a.input.latched,b.input.latched,12)?"true":"false",
            !memcmp(a.input.stats,b.input.stats,12)&&a.input.calls==b.input.calls?"true":"false");
        input_print(&a.input);printf(",\"input_b\":");input_print(&b.input);puts("}");
        if(fflush(stdout)||ferror(stdout)){result=15;break;}
        struct timespec delay={0,POLL_MS*1000000};nanosleep(&delay,0);
    }
    printf("{\"type\":\"end\",\"result\":%d,\"signal_stop\":%s}\n",result,stopped?"true":"false");
done:
    if(close(memory_fd)&&!result)result=16;memory_fd=-1;
    return result;
}
