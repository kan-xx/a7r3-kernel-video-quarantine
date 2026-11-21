/* Standalone tmpfs supervisor. No hooks, firmware writes, raw memory writes,
 * codec reset/abort, or host-dependent STOP. Its children are never killed:
 * the original tap must get a chance to release the key. Kernel waits are
 * not promised to be interruptible or bounded. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include "guard_policy.h"
#include "guard_lineage.h"
#ifdef GUARD_FIXTURE
static uint64_t ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec;}
struct sample {uint32_t ctrl,param,mode[3],state[3],profile;};
#else
#define INCLUDE_ENCODER
#define main original_observer_main
#include "../ram-observers/config_observer.c"
#undef main
#include <sys/statfs.h>
#include "../ram-observers/sha256_local.h"
#include "identity.h"
#endif
static volatile sig_atomic_t cancel_requested;
static void cancel(int x){(void)x;cancel_requested=1;}
static unsigned sequence,log_bytes,log_failed;static int logfd=-1,owned_lock=-1,exit_fd=-1;static pid_t child;
static uint64_t begun;static char expected_boot[40];static unsigned expected_pid;static uint64_t expected_start;
static struct sample running;static unsigned have_running;
#ifndef GUARD_FIXTURE
static struct sample baseline;
#endif
#define JOURNAL_LIMIT (1024u*1024u)
#define SPACE_MARGIN (64u*1024u)
#define EXIT_PENDING 999
struct event {uint32_t magic,kind,bytes,sequence;uint64_t elapsed_ns;};
struct identity_record {char boot[40];uint32_t pid,duration_ms;uint64_t start_ticks,started_ns;};
struct sample_record {struct rg_policy policy;struct rg_sample gate;struct sample sampled;int32_t child_pid,child_status;};
struct final_record {struct rg_policy policy;int32_t child_pid,child_pending;uint32_t idle_verified,scope_flags;};
_Static_assert(sizeof(struct rg_policy)==56&&sizeof(struct identity_record)==64&&sizeof(struct final_record)==72,"journal ABI");
static int exactwrite(int fd,const void*p,size_t n){const unsigned char*b=p;while(n){ssize_t z=write(fd,b,n);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;b+=z;n-=z;}return 0;}
/* An observation is not a reservation. Check twice, then allocate every
 * journal byte before START. A later allocation failure still cannot send a
 * key, and the status page below already exists before this can happen. */
static int space_check(uint64_t *available){
 struct statvfs fs;*available=0;if(statvfs(".",&fs)||!fs.f_frsize||fs.f_bavail>UINT64_MAX/fs.f_frsize)return -1;
 *available=(uint64_t)fs.f_bavail*fs.f_frsize;
 return *available>=(uint64_t)JOURNAL_LIMIT+SPACE_MARGIN?0:-1;
}
static int exit_status_write(unsigned result){
 if(exit_fd<0)return -1;char text[32];memset(text,' ',sizeof text);
 int n=snprintf(text,sizeof text,"%010u\n",result);if(n!=11)return -1;text[n]=' ';
 if(pwrite(exit_fd,text,sizeof text,0)!=(ssize_t)sizeof text||fsync(exit_fd))return -1;return 0;
}
static int exit_status_reserve(void){
 exit_fd=open("exit-code",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(exit_fd<0)return -1;
 struct stat st;if(fstat(exit_fd,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=geteuid())return -1;
 /* Write actual data, not ftruncate/sparse reservation. The final fixed-size
  * overwrite cannot need a new tmpfs data page when the filesystem is full. */
 return exit_status_write(EXIT_PENDING);
}
static void detached_finish(unsigned result){
 int bad=exit_status_write(result);if(exit_fd>=0&&close(exit_fd))bad=1;_exit(bad?99:(int)result);
}
static int emit(unsigned kind,const void*p,unsigned n,int durable){
 struct event e={0x31475253,kind,sizeof e+n,++sequence,ns()-begun};
 if(log_failed||log_bytes+e.bytes>JOURNAL_LIMIT||exactwrite(logfd,&e,sizeof e)||exactwrite(logfd,p,n)||(durable&&fsync(logfd))){log_failed=1;return -1;}
 log_bytes+=e.bytes;return 0;
}
static int smallfile(const char*p,char*b,unsigned n){int f=open(p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return -1;int r=read(f,b,n-1),ok=close(f);if(r<0||ok)return -1;b[r]=0;return r;}
static int identity(void){
#ifdef GUARD_FIXTURE
 char b[8];return smallfile("epoch",b,sizeof b)==2&&!strcmp(b,"1\n");
#else
 char path[80],b[2048],boot[80];if(smallfile("/proc/sys/kernel/random/boot_id",boot,sizeof boot)!=37||boot[36]!='\n'||memcmp(boot,expected_boot,36))return 0;
 snprintf(path,sizeof path,"/proc/%u/exe",expected_pid);char exe[80];ssize_t exelen=readlink(path,exe,sizeof exe);if(exelen!=15||memcmp(exe,"/usr/bin/im.elf",15))return 0;
 snprintf(path,sizeof path,"/proc/%u/stat",expected_pid);if(smallfile(path,b,sizeof b)<1)return 0;
 char prefix[32];snprintf(prefix,sizeof prefix,"%u (im.elf) ",expected_pid);if(strncmp(b,prefix,strlen(prefix)))return 0;
 char*p=strrchr(b,')');if(!p||p[1]!=' '||!p[2]||p[3]!=' ')return 0;p+=4;
 uint64_t value=0;for(unsigned field=4;field<=22;field++){char*end;errno=0;unsigned long long v=strtoull(p,&end,10);if(errno||end==p||(*end!=' '&&*end!='\n'&&*end))return 0;if(field==4&&v!=1)return 0;if(field==22)value=v;p=*end?end+1:end;}
 return value==expected_start;
#endif
}
static int acquire_sample(struct sample*out,struct rg_sample*gate,unsigned phase){
 memset(gate,0,sizeof*gate);gate->epoch_ok=identity();if(!gate->epoch_ok)return -1;
#ifdef GUARD_FIXTURE
 char b[80];if(smallfile("states",b,sizeof b)<1)return -1;
 unsigned q,s0,s1,s2,gen;if(sscanf(b,"%u %u %u %u %u",&q,&s0,&s1,&s2,&gen)!=5)return -1;
 memset(out,0,sizeof*out);out->ctrl=0x1000;out->param=0x2000;out->mode[0]=out->mode[1]=76;out->state[0]=s0;out->state[1]=s1;out->state[2]=s2;out->profile=gen;
 (void)phase;gate->qualified=q;memcpy(gate->state,out->state,sizeof gate->state);gate->generation_same=gen==1;
#else
 struct sample b;int a_rc=snapshot(out),b_rc=snapshot(&b);if(a_rc||b_rc){if((!a_rc||a_rc==14)&&(!b_rc||b_rc==14))gate->qualified=2;return -1;}
 /* Ring pointers and counters legitimately move; stable identity/state/config
  * is required, not equality of unrelated asynchronous progress counters. */
 if(out->ctrl!=b.ctrl||out->param!=b.param||memcmp(out->mode,b.mode,sizeof out->mode)||memcmp(out->format,b.format,sizeof out->format)||memcmp(out->override,b.override,16)){gate->qualified=2;return -1;}
 for(unsigned i=0;i<3;i++){
  const struct encoder_sample*a=&out->encoder[i],*c=&b.encoder[i];
  if(a->parameter_va!=c->parameter_va||a->state_va!=c->state_va||a->state_raw!=c->state_raw||a->manager_selection!=c->manager_selection||a->profile_va!=c->profile_va||memcmp(a->request,c->request,sizeof a->request)||memcmp(a->profile,c->profile,sizeof a->profile)){gate->qualified=2;return -1;}
  gate->state[i]=a->state_raw;
 }
 if(!identity()){gate->epoch_ok=0;return -1;}gate->qualified=1;
 /* A recognized sensor transition must not hide a changed process-owned
  * object, format or override. Check these coherent invariants first. */
 gate->generation_same=!memcmp(out->override,baseline.override,16)&&out->ctrl==baseline.ctrl&&out->param==baseline.param&&!memcmp(out->format,baseline.format,sizeof out->format);
 if(!gate->generation_same)return 0;
 int mode_rc=rg_modes(phase,baseline.mode,out->mode,gate->state);if(!mode_rc){gate->generation_same=0;return 0;}if(mode_rc==2){gate->qualified=2;return -1;}
 if(have_running&&phase!=RG_STOPPING){
  for(unsigned i=0;i<3;i++){const struct encoder_sample*a=&out->encoder[i],*c=&running.encoder[i];
   if(a->parameter_va!=c->parameter_va||a->manager_selection!=c->manager_selection||a->profile_va!=c->profile_va||memcmp(a->request,c->request,sizeof a->request)||memcmp(a->profile,c->profile,sizeof a->profile))gate->generation_same=0;
  }
 }
 if(phase==RG_STOPPING&&!gate->state[0]&&!gate->state[1]&&!gate->state[2]&&!rg_baseline_restored(baseline.mode,out->mode))gate->generation_same=0;
#endif
 return gate->qualified?0:-1;
}
static int verify_key_receipt(int fd,int status){
 uint32_t data[32];struct stat s;if(fstat(fd,&s)||s.st_size!=128||pread(fd,data,sizeof data,0)!=sizeof data||!WIFEXITED(status)||WEXITSTATUS(status))return -1;
 uint32_t*a=data,*b=data+16;
 if(a[0]!=0x31504853||a[1]!=2||a[2]||a[9]!=3||a[13]!=2||a[3]!=b[3]||b[0]!=0x31504853||b[1]!=4||b[2]||b[4]||b[5]||b[8]||b[9]!=3||b[14]||b[15]!=2||a[10]!=0x13579bdf||a[11]!=0x2468ace0||b[10]!=a[10]||b[11]!=a[11])return -1;
 if((a[3]>>16)!=0x172||!(a[3]&0x8000)||(a[3]&0x7fff)<0x6000||(a[3]&0x7fff)>=0x7000)return -1;
 return 0;
}
static int key_fd=-1,key_result,reserved_key[2]={-1,-1};static unsigned key_called;
static int key_receipts_reserve(void){
 const char*names[2]={"start-key.bin","stop-key.bin"};uint32_t zeros[32]={0};
 for(unsigned i=0;i<2;i++){
  int fd=open(names[i],O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;reserved_key[i]=fd;
  struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||exactwrite(fd,zeros,sizeof zeros)||fsync(fd)||lseek(fd,0,SEEK_SET)!=0)return -1;
 }
 return 0;
}
static int key_poll(void){
 if(!child)return key_result;int status;pid_t p=waitpid(child,&status,WNOHANG);if(!p)return 1;
 if(p<0){if(errno==EINTR)return 1;key_result=-1;return -1;}
 int result=verify_key_receipt(key_fd,status);uint32_t receipt[35]={(uint32_t)child,(uint32_t)status,(uint32_t)result};
 if(pread(key_fd,receipt+3,128,0)!=128)memset(receipt+3,0,128);
 if(emit(4,receipt,sizeof receipt,1))result=-1;
 if(close(key_fd))result=-1;key_fd=-1;child=0;key_result=result;return result;
}
static int key_start(unsigned action){
 if(child||key_fd>=0||action!=key_called+1||action>2)return -1;
 key_fd=reserved_key[action-1];reserved_key[action-1]=-1;if(key_fd<0)return -1;
 struct stat s;uint32_t untouched[32];
 if(fstat(key_fd,&s)||s.st_uid!=geteuid()||s.st_nlink!=1||!S_ISREG(s.st_mode)||s.st_size!=128||pread(key_fd,untouched,sizeof untouched,0)!=(ssize_t)sizeof untouched||lseek(key_fd,0,SEEK_SET)!=0){close(key_fd);key_fd=-1;return -1;}
 for(unsigned i=0;i<32;i++)if(untouched[i]){close(key_fd);key_fd=-1;return -1;}
 key_called=action;key_result=1;
 child=fork();if(child<0){child=0;close(key_fd);key_fd=-1;return -1;}
 if(!child){
  /* Retain the singleton lock through exec. A stuck key helper must keep
   * future trials excluded even after this supervisor records uncertainty. */
  if(owned_lock<0||fcntl(owned_lock,F_SETFD,0))_exit(123);
  signal(SIGHUP,SIG_IGN);signal(SIGINT,SIG_IGN);signal(SIGTERM,SIG_IGN);int null=open("/dev/null",O_RDONLY);if(null<0||dup2(null,0)<0||dup2(key_fd,1)<0||dup2(key_fd,2)<0)_exit(124);
  if(null>2)close(null);if(key_fd>2)close(key_fd);
  char*const args[]={"local-rec-key.elf",0};char*const environment[]={"PATH=/usr/bin:/bin","LD_LIBRARY_PATH=/usr/lib:/lib",0};execve("./local-rec-key.elf",args,environment);_exit(125);
 }
 uint32_t record[2]={action,(uint32_t)child};if(emit(3,record,sizeof record,1))return -1;return 0;
}
#ifndef GUARD_FIXTURE
static int hash_file(const char*p,const unsigned char*expected,unsigned size){
 int fd=open(p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;struct stat a,b;int okay=!fstat(fd,&a)&&S_ISREG(a.st_mode)&&a.st_size==size;struct sha256 sh;sha_init(&sh);unsigned left=size;unsigned char buf[4096],digest[32];
 while(okay&&left){unsigned ask=left>sizeof buf?sizeof buf:left;ssize_t z=read(fd,buf,ask);if(z<=0||z>(ssize_t)ask){okay=0;break;}sha_add(&sh,buf,z);left-=z;}
 if(okay&&(read(fd,buf,1)!=0||fstat(fd,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mtime!=b.st_mtime))okay=0;sha_end(&sh,digest);if(close(fd))okay=0;return okay&&!memcmp(digest,expected,32);
}
static int production_open(void){
 struct stat cwd,key;struct statfs fs;if(geteuid()||stat(".",&cwd)||!S_ISDIR(cwd.st_mode)||cwd.st_uid||cwd.st_gid||(cwd.st_mode&0777)!=0700||statfs(".",&fs)||fs.f_type!=0x01021994)return -1;
 if(lstat("local-rec-key.elf",&key)||!S_ISREG(key.st_mode)||key.st_uid||key.st_gid||key.st_nlink!=1||(key.st_mode&0777)!=0700||!hash_file("local-rec-key.elf",key_hash,key_bytes))return -1;
 for(unsigned i=0;i<sizeof identities/sizeof identities[0];i++)if(!hash_file(identities[i].path,identities[i].sha,identities[i].bytes))return -1;
 if(!identity())return -1;
 char cmd[2048],version[8];if(smallfile("/proc/cmdline",cmd,sizeof cmd)<0||!strstr(cmd,"memrsv=0x1A5E000@0x02E68000")||!strstr(cmd,"mem=1G@0"))return -1;
 if(smallfile("/setting/updater/dat4",version,sizeof version)!=2||version[0]!=0x10||version[1]!=3)return -1;
 int fd=open("/dev/mem",O_RDONLY|O_SYNC|O_CLOEXEC);if(fd<0)return -1;void*map=mmap(0,PA_END-PA_BEGIN,PROT_READ,MAP_SHARED,fd,PA_BEGIN);int bad=close(fd);if(map==MAP_FAILED||bad)return -1;memory=map;
 unsigned char anchor[184];for(unsigned i=0;i<sizeof anchors/sizeof anchors[0];i++)if(phys(anchors[i].va,anchor,anchors[i].n)||memcmp(anchor,anchors[i].data,anchors[i].n))return -1;
 if(snapshot(&baseline))return -1;
 /* This version is stock only, with no sensor overrides. */
 for(unsigned i=0;i<16;i++)if(baseline.override[i]!=0xff)return -1;
 if(!rg_modes(RG_PRE,baseline.mode,baseline.mode,(uint32_t[]){0,0,0}))return -1;
 const uint32_t stock_format[4]={4,2,0,6};if(memcmp(baseline.format,stock_format,sizeof stock_format))return -1;
 return identity()?0:-1;
}
#endif
static int supervise(unsigned duration){
 begun=ns();if(!begun)return 90;
#ifdef GUARD_FIXTURE
 const char*lockpath="../fixture-record.lock";
#else
 const char*lockpath="/tmp_bt/a7r-stock-record-guard.lock";
#endif
 int lock=open(lockpath,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);struct stat lockst;
 if(lock<0||fstat(lock,&lockst)||!S_ISREG(lockst.st_mode)||lockst.st_nlink!=1||lockst.st_uid!=geteuid()||(lockst.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB))return 91;
 owned_lock=lock;
#ifndef GUARD_FIXTURE
 if(production_open())return 92;
#endif
 uint64_t available;if(space_check(&available))return 97;
 /* Both key result pages exist before the first action, so a full temporary
  * filesystem during recording cannot require allocating the STOP receipt. */
 if(key_receipts_reserve())return 98;
#ifdef GUARD_SPACE_RACE
 /* Guest-only coordinator of a real concurrent-allocation race. The guard's
  * statvfs/write/pwrite calls remain native Linux syscalls, never mocked. */
 extern void fixture_space_race(void);fixture_space_race();
#endif
 logfd=open("run.bin",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(logfd<0)return 93;
 unsigned char zero[4096]={0};for(unsigned i=0;i<JOURNAL_LIMIT/sizeof zero;i++)if(exactwrite(logfd,zero,sizeof zero))return 94;
 if(fsync(logfd)||lseek(logfd,0,SEEK_SET)!=0)return 94;
 struct identity_record header={.pid=expected_pid,.duration_ms=duration*1000,.start_ticks=expected_start,.started_ns=begun};memcpy(header.boot,expected_boot,40);
 if(emit(1,&header,sizeof header,1))return 94;
 signal(SIGTERM,cancel);signal(SIGINT,cancel);signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);
 struct rg_policy policy={.duration_ms=duration*1000};unsigned loops=0;
 while(policy.phase!=RG_DONE&&policy.phase!=RG_FAILED&&loops++<300){
  struct sample sample;struct rg_sample gate;memset(&sample,0,sizeof sample);acquire_sample(&sample,&gate,policy.phase);int key=key_poll();uint64_t now=ns();
  struct sample_record record={policy,gate,sample,child,key};if(emit(2,&record,sizeof record,0)){policy.phase=RG_FAILED;policy.error=RG_LOG;break;}
  /* Cancellation before START aborts; after START it requests the earliest
   * qualified STOP. It cannot manufacture state6 or skip pending key-up. */
  if(cancel_requested&&!policy.start_claim){policy.phase=RG_FAILED;policy.error=RG_CANCELLED;break;}
  if(cancel_requested&&policy.start_claim&&now/1000000>=policy.start_ms+1000)policy.duration_ms=1000;
  unsigned previous=policy.phase;int action=rg_tick(&policy,&gate,now/1000000,key);
  if(previous==RG_STARTING&&policy.seen_running&&!have_running){running=sample;have_running=1;}
  if(action==RG_START||action==RG_STOP){
   /* Recheck the epoch immediately before committing a one-use action. The
    * sampler is continuous; no other actor may press MOVIE/change mode. */
   if(!identity()){policy.phase=RG_FAILED;policy.error=RG_IDENTITY;break;}
   if(emit(5,&policy,sizeof policy,1)||key_start(action)){policy.phase=RG_FAILED;policy.error=RG_LOG;break;}
  }
  if(action==RG_FINISH)break;
  struct timespec wait={0,200000000};nanosleep(&wait,0);
 }
 if(policy.phase!=RG_DONE&&policy.phase!=RG_FAILED){policy.phase=RG_FAILED;policy.error=RG_STOP_TIMEOUT;}
 struct final_record final={policy,child,child!=0,policy.phase==RG_DONE,1};
 int failed=emit(6,&final,sizeof final,1)||ftruncate(logfd,log_bytes)||fsync(logfd);close(logfd);close(lock);
#ifndef GUARD_FIXTURE
 if(memory)munmap((void*)memory,PA_END-PA_BEGIN);
#endif
 return failed?95:policy.phase==RG_DONE?0:100+(int)policy.error;
}
int main(int argc,char**argv){
#ifdef GUARD_FIXTURE
 if(argc!=3||(strcmp(argv[1],"--launch")&&strcmp(argv[1],"--check")))return 2;unsigned duration=(unsigned)strtoul(argv[2],0,10);strcpy(expected_boot,"00000000-0000-0000-0000-000000000001");expected_pid=151;expected_start=100;
#else
 if(argc!=6||(strcmp(argv[1],"--launch")&&strcmp(argv[1],"--check"))||strlen(argv[2])!=36)return 2;char*end;
 for(unsigned i=0;i<36;i++)if((i==8||i==13||i==18||i==23)?argv[2][i]!='-':!strchr("0123456789abcdef",argv[2][i]))return 2;
 memcpy(expected_boot,argv[2],36);unsigned long p=strtoul(argv[3],&end,10);if(*end||p<2||p>65535)return 2;expected_pid=p;
 expected_start=strtoull(argv[4],&end,10);if(*end||!expected_start)return 2;unsigned long d=strtoul(argv[5],&end,10);if(*end||d<1||d>30)return 2;unsigned duration=d;
#endif
 if(duration<1||duration>30)return 2;
 uint64_t available;if(space_check(&available)){
  printf("STOCK_GUARD_SPACE qualified=0 available=%llu required=%u no_key=1\n",(unsigned long long)available,JOURNAL_LIMIT+SPACE_MARGIN);return 97;
 }
 if(!strcmp(argv[1],"--check")){
#ifndef GUARD_FIXTURE
  if(production_open())return 92;
#endif
  struct sample sample;struct rg_sample gate;int rc=acquire_sample(&sample,&gate,RG_PRE);
  unsigned okay=!rc&&gate.qualified==1&&gate.epoch_ok&&gate.generation_same&&!gate.state[0]&&!gate.state[1]&&!gate.state[2];
  printf("STOCK_GUARD_CHECK qualified=%u states=%u,%u,%u pid=%u start=%llu available=%llu required=%u\n",okay,gate.state[0],gate.state[1],gate.state[2],expected_pid,(unsigned long long)expected_start,(unsigned long long)available,JOURNAL_LIMIT+SPACE_MARGIN);
#ifndef GUARD_FIXTURE
  if(memory)munmap((void*)memory,PA_END-PA_BEGIN);
#endif
  return okay?0:96;
 }
 int claim=open("launch.claim",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(claim<0)return 8;
 struct identity_record launch={.pid=expected_pid,.duration_ms=duration*1000,.start_ticks=expected_start,.started_ns=ns()};memcpy(launch.boot,expected_boot,40);
 if(exactwrite(claim,&launch,sizeof launch)||fsync(claim)||close(claim))return 9;
 if(exit_status_reserve())return 98;
 /* Detached child owns all I/O before any MOVIE action. Host/session closure
  * does not close the journal or become a reason to send an extra toggle. */
 int ack[2];if(pipe(ack)){exit_status_write(3);close(exit_fd);return 3;}pid_t pid=fork();if(pid<0){exit_status_write(3);close(exit_fd);return 3;}
 if(pid){close(exit_fd);exit_fd=-1;close(ack[1]);char c=0;int n=read(ack[0],&c,1);close(ack[0]);printf("STOCK_GUARD pid=%d detached=%d\n",(int)pid,n==1&&c=='R');return n==1&&c=='R'?0:4;}
 close(ack[0]);if(setsid()<0)detached_finish(5);int null=open("/dev/null",O_RDWR);if(null<0)detached_finish(6);
 for(int fd=0;fd<3;fd++)if(dup2(null,fd)<0)detached_finish(6);if(null>2)close(null);signal(SIGHUP,SIG_IGN);
 if(write(ack[1],"R",1)!=1)detached_finish(7);close(ack[1]);int result=supervise(duration);detached_finish(result);
}
