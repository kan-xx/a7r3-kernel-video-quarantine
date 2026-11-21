/* Temporary, bounded, read-only DDR1 trace sampler. No camera commands,
 * MMIO, target memory writes, cache operations, or persistent installation.
 * DMM lifetime checks qualify evidence but do not pin the allocation.
 * Kernel and firmware bytes must be independently qualified by the operator. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include "vcd_trace_anchors.h"
#define TRACE_VA 0x806647c8u
#define TRACE_LEN 0x2458u
#define START_VA 0x80667a24u
#define START_LEN 0x1e8u
#define MAX_SECONDS 20
#define PERIOD_NS 50000000
struct unit { uint32_t v[10]; };
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped=1; }
static int textfile(const char *path,char *b,size_t n) {
 int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0)return -1;
 size_t got=0; while(got<n-1){ssize_t z=read(fd,b+got,n-1-got);if(z<0){close(fd);return -1;}if(!z)break;got+=(size_t)z;}
 close(fd);b[got]=0;return (int)got;
}
static int parse_units(char *b,struct unit *out) {
 unsigned found=0;char *save=0;
 for(char *line=strtok_r(b,"\n",&save);line;line=strtok_r(0,"\n",&save)) {
  struct unit u; int n=sscanf(line,"%x %x %x %x %x %x %x %x %x %x",&u.v[0],&u.v[1],&u.v[2],&u.v[3],&u.v[4],&u.v[5],&u.v[6],&u.v[7],&u.v[8],&u.v[9]);
  if(n==10 && u.v[1]==0x36b){*out=u;found++;}
 }
 if(found!=1)return found? -1:0;
 if(out->v[2]!=2||out->v[3]!=1||out->v[4]!=1||!out->v[6])return 0;
 uint64_t lo=out->v[8],hi=lo+out->v[9];
 if(lo<0x80000000u||hi>0x90000000u||out->v[9]<0x680000u||(lo&4095))return -1;
 return 1;
}
static int owner_matches(char *b,const struct unit *u) {
 char *save=0;unsigned count=0;
 for(char *line=strtok_r(b,"\n",&save);line;line=strtok_r(0,"\n",&save)) {
  unsigned handle,type,owner,serial;unsigned long long ts;
  if(sscanf(line,"%x %llx %x %x %x",&handle,&ts,&type,&owner,&serial)==5 && handle==u->v[0] && type==0x36b && owner==0x006800f3 && serial==1)count++;
 }
 return count==1;
}
static int current_unit(struct unit *u) {
 char b[32768];int n=textfile("/proc/udm/dmm_units",b,sizeof b);if(n<0||n==(int)sizeof(b)-1)return -1;
 int rc=parse_units(b,u);if(rc!=1)return rc;
 n=textfile("/proc/udm/dmm_units2",b,sizeof b);if(n<0||n==(int)sizeof(b)-1)return -1;
 return owner_matches(b,u)?1:0;
}
static int identity(const char *boot,unsigned pid,unsigned long long start) {
 char b[4096],path[64];if(textfile("/proc/sys/kernel/random/boot_id",b,sizeof b)<0)return 0;
 b[strcspn(b,"\n")]=0;if(strcmp(b,boot))return 0;
 snprintf(path,sizeof path,"/proc/%u/stat",pid);if(textfile(path,b,sizeof b)<0)return 0;
 char *p=strrchr(b,')');if(!p||strncmp(b+strcspn(b,"("),"(im.elf) ",9))return 0;
 char *save=0,*token=strtok_r(p+2," ",&save);for(unsigned i=0;i<19&&token;i++)token=strtok_r(0," ",&save);
 char *end=0;unsigned long long observed=token?strtoull(token,&end,10):0;
 return token&&!*end&&observed==start;
}
static uint64_t ns(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return(uint64_t)t.tv_sec*1000000000u+(unsigned)t.tv_nsec; }
static void copyvolatile(unsigned char *to,const volatile unsigned char *from,unsigned n){for(unsigned i=0;i<n;i++)to[i]=from[i];}
static uint32_t word(const unsigned char *p){uint32_t v;memcpy(&v,p,4);return v;}
static int qualify(const volatile unsigned char *mem,const struct unit *u) {
 unsigned char b[64];
 for(unsigned i=0;i<sizeof(vcd_anchors)/sizeof(vcd_anchors[0]);i++){
  copyvolatile(b,mem+vcd_anchors[i].va-0x80000000u,vcd_anchors[i].n);
  if(memcmp(b,vcd_anchors[i].data,vcd_anchors[i].n))return 0;
 }
 copyvolatile(b,mem+0x660000,4);return word(b)==u->v[8];
}
/* Fixed little-endian ABI: ARM target is little endian. Host decoder rejects
 * partial frames and preserves both cursor observations to flag ring races. */
struct file_header {char magic[8],boot[40];uint32_t pid;uint32_t seconds;uint64_t start_ticks,started_ns;};
struct frame_header {uint32_t magic,bytes;uint64_t elapsed_ns;uint32_t unit[10];unsigned char before[16],after[16];uint32_t start_stable,reserved;};
_Static_assert(sizeof(struct file_header)==72,"file ABI");
_Static_assert(sizeof(struct frame_header)==96,"frame ABI");
#ifndef HOST_TEST
int main(int argc,char **argv) {
 if(argc!=5)return 2;
 char *end=0;unsigned long pid=strtoul(argv[2],&end,10);if(*end||!pid||pid>65535)return 2;
 unsigned long long ticks=strtoull(argv[3],&end,10);if(*end||!ticks)return 2;
 unsigned long seconds=strtoul(argv[4],&end,10);if(*end||seconds<1||seconds>MAX_SECONDS||strlen(argv[1])!=36)return 2;
 if(!identity(argv[1],(unsigned)pid,ticks))return 3;
 char b[32768];if(textfile("/proc/iomem",b,sizeof b)<0||!strstr(b,"80000000-8fffffff : System RAM"))return 4;
 if(textfile("/setting/updater/dat4",b,sizeof b)!=2||(unsigned char)b[0]!=0x10||b[1]!=3)return 4;
 int fd=open("/dev/mem",O_RDONLY|O_SYNC|O_CLOEXEC);if(fd<0)return 5;
 /* tmpfs is only 1 MiB on the measured camera. Reserve room for the native
  * key result, pipeline observer and other residents; never fill the volume. */
 struct statvfs space;
 if(fstatvfs(fileno(stdout),&space)){close(fd);return 11;}
 uint64_t available=(uint64_t)space.f_bavail*space.f_frsize;
 const uint64_t reserve=192*1024,one=sizeof(struct frame_header)+TRACE_LEN+START_LEN;
 if(available<reserve+sizeof(struct file_header)+one){close(fd);return 12;}
 unsigned max_frames=(unsigned)((available-reserve-sizeof(struct file_header))/one);
 if(max_frames>40)max_frames=40;
 signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,stop);
 uint64_t begin=ns();if(!begin){close(fd);return 6;}
 struct file_header h={.magic="VCDLOG2",.pid=(unsigned)pid,.seconds=(unsigned)seconds,.start_ticks=ticks,.started_ns=begin};memcpy(h.boot,argv[1],36);
 if(fwrite(&h,1,sizeof h,stdout)!=sizeof h){close(fd);return 7;}
 void *mapping=MAP_FAILED;struct unit mapped={0};int result=0;unsigned frames=0,unqualified=0,changed=0;
 for(unsigned i=0;i<seconds*20&&!stopped&&frames<max_frames&&ns()-begin<seconds*1000000000ull;i++) {
  struct unit now={0},after={0};int rc=current_unit(&now);
  if(rc<0){result=8;break;}
  if(mapping!=MAP_FAILED && (rc!=1||memcmp(&now,&mapped,sizeof now))) {munmap(mapping,mapped.v[9]);mapping=MAP_FAILED;changed++;}
  if(i%20==0&&!identity(argv[1],(unsigned)pid,ticks)){result=9;break;}
  if(rc==1) {
   if(mapping==MAP_FAILED){mapping=mmap(0,now.v[9],PROT_READ,MAP_SHARED,fd,(off_t)now.v[8]);if(mapping==MAP_FAILED){result=10;break;}mapped=now;}
   const volatile unsigned char *mem=mapping;
   if(qualify(mem,&now)){
    unsigned char payload[TRACE_LEN+START_LEN],start_copy[START_LEN];const volatile unsigned char *trace=mem+TRACE_VA-0x80000000u;
    struct frame_header f={.magic=0x32464356,.bytes=sizeof(f)+sizeof(payload),.elapsed_ns=ns()-begin};memcpy(f.unit,now.v,sizeof f.unit);
    copyvolatile(f.before,trace,8);copyvolatile(f.before+8,trace+0x22d0,8);
    copyvolatile(payload,trace,TRACE_LEN);
    copyvolatile(f.after,trace,8);copyvolatile(f.after+8,trace+0x22d0,8);
    copyvolatile(payload+TRACE_LEN,mem+START_VA-0x80000000u,START_LEN);
    copyvolatile(start_copy,mem+START_VA-0x80000000u,START_LEN);
    f.start_stable=!memcmp(start_copy,payload+TRACE_LEN,START_LEN);
    if(current_unit(&after)==1&&!memcmp(&now,&after,sizeof now)){
     if(fwrite(&f,1,sizeof f,stdout)!=sizeof f||fwrite(payload,1,sizeof payload,stdout)!=sizeof payload||fflush(stdout)){result=7;break;}frames++;
    }else changed++;
   }else unqualified++;
  }
  struct timespec delay={0,PERIOD_NS};nanosleep(&delay,0);
 }
 if(mapping!=MAP_FAILED)munmap(mapping,mapped.v[9]);close(fd);
 if(!identity(argv[1],(unsigned)pid,ticks)&&!result)result=9;
 fprintf(stderr,"result=%d frames=%u unqualified=%u changed=%u stopped=%d max_frames=%u available=%llu reserve=%llu\n",result,frames,unqualified,changed,(int)stopped,max_frames,(unsigned long long)available,(unsigned long long)reserve);
 return result;
}
#else
#include <assert.h>
int main(void){
 struct unit u;char good[]="1d63 0000036b 0002 01 01 00 07 0000c047 81000000 01400000\n";
 assert(parse_units(good,&u)==1&&u.v[8]==0x81000000);
 char owner[]="1d63 0000000012345678 0000036b 006800f3 0001\n";assert(owner_matches(owner,&u));
 char wrong_owner[]="1d63 0000000012345678 0000036b 006800f5 0001\n";assert(!owner_matches(wrong_owner,&u));
 char freed[]="1d63 0000036b 0002 00 00 00 07 0000c047 81000000 01400000\n";assert(parse_units(freed,&u)==0);
 char wrap[]="1d63 0000036b 0002 01 01 00 07 0000c047 fff00000 01400000\n";assert(parse_units(wrap,&u)==-1);
 char small[]="1d63 0000036b 0002 01 01 00 07 0000c047 81000000 00100000\n";assert(parse_units(small,&u)==-1);
 char dup[]="1d63 0000036b 0002 01 01 00 07 0000c047 81000000 01400000\n1d64 0000036b 0002 01 01 00 07 0000c047 83000000 01400000\n";assert(parse_units(dup,&u)==-1);
 char none[]="header\n";assert(parse_units(none,&u)==0);
 unsigned char *mem=calloc(1,0x680000);assert(mem);u.v[8]=0x81000000;
 for(unsigned i=0;i<sizeof(vcd_anchors)/sizeof(vcd_anchors[0]);i++)memcpy(mem+vcd_anchors[i].va-0x80000000u,vcd_anchors[i].data,vcd_anchors[i].n);
 memcpy(mem+0x660000,&u.v[8],4);assert(qualify(mem,&u));mem[0x4314]^=1;assert(!qualify(mem,&u));free(mem);
 puts("10 allocation/owner/anchor qualification checks passed; no hardware access");return 0;
}
#endif
