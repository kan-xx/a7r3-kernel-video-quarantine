/* Read-only manager/counter sampler, independently bounded and epoch-qualified.
 * Reuses the phase10 allocation/source-code qualification. It never issues
 * codec commands or changes counters, queues, firmware, or cache state. */
#define main phase10_reader_main
#include "vcd_trace_reader.c"
#undef main

static uint32_t mr_word(const volatile unsigned char *m,unsigned off){
 unsigned char b[4];copyvolatile(b,m+off,4);return word(b);
}
static uint16_t mr_half(const volatile unsigned char *m,unsigned off){
 unsigned char b[2];copyvolatile(b,m+off,2);return(uint16_t)b[0]|(uint16_t)b[1]<<8;
}
static int mr_validate(const volatile unsigned char *mem,unsigned size,uint32_t va){
 if(va<0x802e0000u||va-0x80000000u>size-0x756cu||(va&3))return 0;
 unsigned off=va-0x80000000u;
 const uint32_t signature[]={0x802ee400,0x802ee470,0x802ec8d8,0x802ec8f0};
 if(mr_word(mem,off)>3)return 0;
 for(unsigned i=0;i<4;i++)if(mr_word(mem,off+8+i*4)!=signature[i])return 0;
 for(unsigned i=0;i<16;i++){
  uint32_t cva=va+0x24+i*0x688;unsigned c=cva-0x80000000u;
  if(mr_word(mem,c)!=0x802ec87c||mr_word(mem,c+8)>4)return 0;
  for(unsigned j=0;j<2;j++){
   uint32_t p=mr_word(mem,c+0x60c+4*j);
   if(p<cva+0xc||p>cva+0x5cc||(p-cva-0xc)%64)return 0;
   p=mr_word(mem,c+0x620+4*j);if(p<cva+0x61c||p>cva+0x61d)return 0;
  }
 }
 return 1;
}
static uint32_t mr_find(const volatile unsigned char *mem,unsigned size){
 uint32_t found=0;unsigned count=0;
 /* Bounded to the already observed original data/heap segment. No signature
  * elsewhere is accepted, even when it lies in the wider DMM allocation. */
 if(size<0x680000)return 0;
 for(unsigned off=0x2e0000;off+0x756c<=0x660000;off+=4){
  if(mr_word(mem,off+8)!=0x802ee400)continue;
  if(mr_validate(mem,size,0x80000000u+off)){found=0x80000000u+off;count++;if(count>1)return 0;}
 }
 return count==1?found:0;
}
struct mr_sample{
 uint32_t manager_va,manager_state,channel_state,frame_count;
 uint32_t command_read,command_write,command_count_a,command_count_b;
 uint16_t done_mask;
 uint8_t task_count,pending,sequence,active,feature,reserved;
};
_Static_assert(sizeof(struct mr_sample)==40,"sample ABI");
static void mr_sample(const volatile unsigned char *mem,uint32_t va,struct mr_sample *s){
 unsigned m=va-0x80000000u,c=m+0x24;memset(s,0,sizeof *s);
 s->manager_va=va;s->manager_state=mr_word(mem,m);s->channel_state=mr_word(mem,c+8);
 s->frame_count=mr_word(mem,c+0x62c);s->done_mask=mr_half(mem,c+6);
 s->command_read=mr_word(mem,c+0x60c);s->command_write=mr_word(mem,c+0x610);
 s->command_count_a=mr_word(mem,c+0x614);s->command_count_b=mr_word(mem,c+0x618);
 s->task_count=mem[c+0x630];s->pending=mem[c+0x631];s->sequence=mem[c+0x632];
 s->active=mem[m+0x6a8];s->feature=mem[c+0x682];
}
struct mr_event {uint32_t magic,kind,bytes,stable;uint64_t elapsed_ns;};
_Static_assert(sizeof(struct mr_event)==24,"event ABI");
#ifndef HOST_TEST
static int mr_emit(unsigned kind,int stable,uint64_t begin,const void *data,unsigned n,uint64_t *written,uint64_t budget){
 struct mr_event e={.magic=0x3153524d,.kind=kind,.bytes=sizeof e+n,.stable=(unsigned)stable,.elapsed_ns=ns()-begin};
 if(*written+e.bytes>budget)return 2;
 if(fwrite(&e,1,sizeof e,stdout)!=sizeof e||fwrite(data,1,n,stdout)!=n||fflush(stdout))return 1;
 *written+=e.bytes;return 0;
}
int main(int argc,char **argv){
 if(argc!=5)return 2;char *end;unsigned long pid=strtoul(argv[2],&end,10);if(*end||!pid||pid>65535)return 2;
 unsigned long long ticks=strtoull(argv[3],&end,10);if(*end||!ticks)return 2;
 unsigned long seconds=strtoul(argv[4],&end,10);if(*end||seconds<1||seconds>20||strlen(argv[1])!=36)return 2;
 if(!identity(argv[1],(unsigned)pid,ticks))return 3;
 char b[32768];if(textfile("/proc/iomem",b,sizeof b)<0||!strstr(b,"80000000-8fffffff : System RAM"))return 4;
 if(textfile("/setting/updater/dat4",b,sizeof b)!=2||(unsigned char)b[0]!=0x10||b[1]!=3)return 4;
 struct statvfs fs;if(fstatvfs(fileno(stdout),&fs))return 5;
 uint64_t available=(uint64_t)fs.f_bavail*fs.f_frsize,reserve=192*1024;
 if(available<reserve+65536)return 6;
 uint64_t budget=available-reserve;if(budget>512*1024)budget=512*1024;
 int fd=open("/dev/mem",O_RDONLY|O_SYNC|O_CLOEXEC);if(fd<0)return 7;
 signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,stop);
 uint64_t begin=ns(),written=sizeof(struct file_header);if(!begin){close(fd);return 8;}
 struct file_header header={.magic="A7RMGR1",.pid=(unsigned)pid,.seconds=(unsigned)seconds,.start_ticks=ticks,.started_ns=begin};memcpy(header.boot,argv[1],36);
 if(fwrite(&header,1,sizeof header,stdout)!=sizeof header){close(fd);return 9;}
 void *map=MAP_FAILED;struct unit mapped={0};uint32_t manager=0;struct mr_sample previous={0};int have_previous=0,result=0,cap=0;unsigned records=0,unstable=0,loops=0;
 while(!stopped&&ns()-begin<seconds*1000000000ull&&loops++<seconds*500){
  struct unit unit={0},after={0};int rc=current_unit(&unit);
  if(rc<0){result=10;break;}
  if(map!=MAP_FAILED&&(rc!=1||memcmp(&unit,&mapped,sizeof unit))){
   int qualified=manager!=0;
   munmap(map,mapped.v[9]);map=MAP_FAILED;manager=0;have_previous=0;
   if(qualified){int out=mr_emit(3,0,begin,&mapped,sizeof mapped,&written,budget);if(out){cap=out==2;result=out==1?9:0;break;}}
  }
  if(loops%100==1&&!identity(argv[1],(unsigned)pid,ticks)){result=11;break;}
  if(rc==1){
   if(map==MAP_FAILED){map=mmap(0,unit.v[9],PROT_READ,MAP_SHARED,fd,(off_t)unit.v[8]);if(map==MAP_FAILED){result=12;break;}mapped=unit;}
   /* Discovery scans 3.5 MiB. Do not spin that scan at the sampling rate while
    * the original loader is still constructing its heap. */
   if(!manager&&(loops==1||loops%50==0)&&qualify(map,&unit)){
    manager=mr_find(map,unit.v[9]);
    if(manager){int out=mr_emit(1,1,begin,&unit,sizeof unit,&written,budget);if(out){cap=out==2;result=out==1?9:0;break;}}
   }
   if(manager){
    struct mr_sample a,second;mr_sample(map,manager,&a);mr_sample(map,manager,&second);
    int stable=!memcmp(&a,&second,sizeof a);if(!stable)unstable++;
    if(current_unit(&after)==1&&!memcmp(&unit,&after,sizeof unit)){
     if(!have_previous||memcmp(&a,&previous,sizeof a)){
      int out=mr_emit(2,stable,begin,&a,sizeof a,&written,budget);if(out){cap=out==2;result=out==1?9:0;break;}
      previous=a;have_previous=1;records++;
     }
    }
   }
  }
  struct timespec wait={0,2000000};nanosleep(&wait,0);
 }
 if(map!=MAP_FAILED)munmap(map,mapped.v[9]);close(fd);
 if(!identity(argv[1],(unsigned)pid,ticks)&&!result)result=11;
 fprintf(stderr,"result=%d records=%u unstable=%u loops=%u bytes=%llu budget=%llu capped=%d stopped=%d\n",result,records,unstable,loops,(unsigned long long)written,(unsigned long long)budget,cap,(int)stopped);
 return result;
}
#else
#include <assert.h>
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);unsigned char *mem=calloc(1,0x680000);assert(mem);
 assert(fread(mem+0x2e0000,1,0x380000,f)==0x380000);fclose(f);
 uint32_t va=mr_find(mem,0x680000);assert(va==0x803260e4);struct mr_sample s;mr_sample(mem,va,&s);
 assert(s.manager_state==2&&s.channel_state==3&&s.active==1&&s.sequence==0);
 unsigned off=va-0x80000000+0x24;mem[off]^=1;assert(!mr_validate(mem,0x680000,va));mem[off]^=1;
 uint32_t saved=mr_word(mem,off+0x60c),bad=0x90000000;memcpy(mem+off+0x60c,&bad,4);assert(!mr_validate(mem,0x680000,va));memcpy(mem+off+0x60c,&saved,4);
 assert(!mr_validate(mem,0x680000,0x90000000)&&!mr_validate(mem,0x680000,va+1));
 assert(mr_validate(mem,0x680000,va));free(mem);puts("manager scanner/counter decode and invalid pointer/vtable rejection passed on archived 4K25 RAM; hardware not executed");return 0;
}
#endif
