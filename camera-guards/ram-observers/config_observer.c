/* Read-only RTOS configuration sampler. No hooks, camera calls or memory writes.
 * 50 ms polling observes configuration, NOT individual sensor frame events. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "observer_anchors.h"
#define PA_BEGIN 0x02e68000u
#define PA_END 0x048c6000u
static const volatile unsigned char *memory;
static volatile sig_atomic_t stopped;
static void stop(int x) {(void)x;stopped=1;}
static int phys(uint32_t va,void *out,unsigned n) {
    if(va<0x60000000u)return -1;
    uint32_t pa=va-0x60000000u;
    if(!n||n>8192||pa<PA_BEGIN||pa>=PA_END||n>PA_END-pa)return -1;
    unsigned char *d=out;for(unsigned i=0;i<n;i++)d[i]=memory[pa-PA_BEGIN+i];return 0;
}
static uint32_t w(const void *b,unsigned o){uint32_t v;memcpy(&v,(const char*)b+o,4);return v;}
#ifndef HOST_FIXTURE
static int textfile(const char *p,char *b,size_t n){int f=open(p,O_RDONLY|O_CLOEXEC);if(f<0)return -1;ssize_t z=read(f,b,n-1);close(f);if(z<0)return -1;b[z]=0;return (int)z;}
#endif
static void hex(const unsigned char *p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static uint64_t ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return(uint64_t)t.tv_sec*1000000000u+(unsigned)t.tv_nsec;}
#ifdef INCLUDE_ENCODER
#include "encoder_snapshot.h"
#define POLL_MS 200
#define OBSERVER_ABI 2
#define MAX_SECONDS 30
#else
#define POLL_MS 50
#define OBSERVER_ABI 1
#define MAX_SECONDS 120
#endif
struct sample {
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
    return 0;
}
int main(int argc,char **argv){
    char *end;long seconds;int fd;char boot[80]="HOST_FIXTURE";
#ifdef HOST_FIXTURE
    if(argc!=3)return 2;seconds=strtol(argv[2],&end,10);fd=open(argv[1],O_RDONLY);
    off_t offset=0;
#else
    if(argc!=2)return 2;seconds=strtol(argv[1],&end,10);
    char cmd[2048],version[8];
    if(textfile("/proc/cmdline",cmd,sizeof cmd)<0||!strstr(cmd,"memrsv=0x1A5E000@0x02E68000")||!strstr(cmd,"mem=1G@0"))return 3;
    if(textfile("/setting/updater/dat4",version,sizeof version)!=2||version[0]!=0x10||version[1]!=3)return 4;
    if(textfile("/proc/sys/kernel/random/boot_id",boot,sizeof boot)<36)return 5;
    for(unsigned i=0;boot[i];i++)if(!strchr("0123456789abcdef-\n",boot[i]))return 5;
    boot[strcspn(boot,"\n")]=0;
    fd=open("/dev/mem",O_RDONLY|O_SYNC|O_CLOEXEC);off_t offset=PA_BEGIN;
#endif
    if(*end||seconds<1||seconds>MAX_SECONDS){if(fd>=0)close(fd);return 2;}
    if(fd<0)return 6;
    void *mapped=mmap(0,PA_END-PA_BEGIN,PROT_READ,MAP_SHARED,fd,offset);
    close(fd);if(mapped==MAP_FAILED)return 7;memory=mapped;
    unsigned char anchor[184];int result=0;
    for(unsigned i=0;i<sizeof anchors/sizeof anchors[0];i++)if(phys(anchors[i].va,anchor,anchors[i].n)||memcmp(anchor,anchors[i].data,anchors[i].n)){result=8;goto done;}
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,stop);
    uint64_t start=ns();if(!start){result=9;goto done;}
    printf("{\"type\":\"header\",\"abi\":%d,\"boot_id\":\"%s\",\"seconds\":%ld,\"period_ms\":%d,\"frame_events_measured\":false,\"memory_writes\":false}\n",OBSERVER_ABI,boot,seconds,POLL_MS);
    for(unsigned count=0;count<(unsigned)seconds*(1000/POLL_MS)&&!stopped;count++){
        if(ns()-start>=(uint64_t)seconds*1000000000u)break;
        struct sample a,b;int x=snapshot(&a),y=snapshot(&b);
        if(x||y){fprintf(stderr,"snapshot identity/read failure: %d/%d\n",x,y);result=x?x:y;break;}
        int stable=!memcmp(&a,&b,sizeof a);
        printf("{\"type\":\"sample\",\"elapsed_ns\":%llu,\"stable\":%s,\"modes\":[%u,%u,%u],\"index\":%d,\"sync\":[%u,%u],\"format\":[%u,%u,%u,%u],\"overrides\":\"",(unsigned long long)(ns()-start),stable?"true":"false",a.mode[0],a.mode[1],a.mode[2],a.index,a.sync[0],a.sync[1],a.format[0],a.format[1],a.format[2],a.format[3]);
        hex(a.override,16);printf("\",\"cs\":\"");hex(a.cs,48);printf("\",\"cc\":\"");hex(a.cc,120);printf("\",\"ec\":\"");hex(a.ec,52);printf("\"");
#ifdef INCLUDE_ENCODER
        printf(",\"encoders\":[");for(unsigned i=0;i<3;i++){if(i)printf(",");encoder_print(&a.encoder[i]);}printf("]");
#endif
        puts("}");
        if(fflush(stdout)||ferror(stdout)){result=15;break;}
        struct timespec delay={0,POLL_MS*1000000};nanosleep(&delay,0);
    }
    printf("{\"type\":\"end\",\"result\":%d,\"signal_stop\":%s}\n",result,stopped?"true":"false");
done:
    if(munmap(mapped,PA_END-PA_BEGIN)&&!result)result=16;
    return result;
}
