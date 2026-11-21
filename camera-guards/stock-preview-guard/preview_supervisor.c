/* Detached stock-baseline supervisor. No REC, reset, USB, or persistent writes.
 * Timed-out native calls are not killed; source/lock survive in HOLD. */
#define _GNU_SOURCE
#include "production_reader.h"
#include "dial_owner.h"
#include "baseline_writer.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>
#ifndef PREVIEW_FIXTURE
#include <sys/statfs.h>
#include "../ram-observers/sha256_local.h"
#include "worker_identities.h"
#endif
#define JOURNAL_BYTES (512u*1024u)
#define MAX_TURNS 180u
static volatile sig_atomic_t cancel_requested;
static void cancel(int n){(void)n;cancel_requested=1;}
static unsigned clock_failed;static uint64_t last_clock;
static uint64_t ms(void){struct timespec t;
#ifdef PREVIEW_FIXTURE
 extern int fixture_clock(struct timespec*);int rc=fixture_clock(&t);
#else
 int rc=clock_gettime(CLOCK_MONOTONIC,&t);
#endif
 if(clock_failed||rc||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000){clock_failed=1;return 0;}
 uint64_t now=(uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;if(!now||(last_clock&&now<last_clock)){clock_failed=1;return 0;}last_clock=now;return now;
}
static int exact(int fd,void*p,unsigned n,int wr){unsigned char*b=p;while(n){ssize_t z=wr?write(fd,b,n):read(fd,b,n);if(z<0&&errno==EINTR)continue;if(z<=0||(unsigned)z>n)return -1;b+=z;n-=(unsigned)z;}return 0;}
static void pause_ms(unsigned n){struct timespec t={n/1000,(n%1000)*1000000};while(nanosleep(&t,&t)&&errno==EINTR){}}
static int statusfd=-1,journal=-1,lockfd=-1,ownerjournal=-1;static uint32_t logseq,logbytes,logbad;
struct loghead {uint32_t magic,kind,bytes,sequence;uint64_t milliseconds;};
/* Per turn: one observation + one policy. Outside this: ready + at most
 * three worker receipts + three claims + one final record. Probe is smaller.
 * This bounds bytes even if every loop emits its maximum sized records. */
#define MAX_LOG_BYTES (MAX_TURNS*(2u*sizeof(struct loghead)+sizeof(struct pr_result)+sizeof(struct pg_policy))+7u*(sizeof(struct loghead)+16u)+sizeof(struct loghead)+32u+12u*(sizeof(struct loghead)+sizeof(struct bl_state)+16u))
_Static_assert(MAX_LOG_BYTES<=JOURNAL_BYTES,"reserved journal fits every allowed event");
_Static_assert(MAX_LOG_BYTES==452448,"retained window bound and unchanged record ABI");
_Static_assert(sizeof(struct bl_state)==76,"lease journal ABI");
_Static_assert(sizeof(struct pr_result)==2384,"appended sensor snapshot ABI");
static int logrow(unsigned kind,const void*p,unsigned n){struct loghead h={0x314a5050,kind,sizeof h+n,++logseq,ms()};
#ifdef PREVIEW_FIXTURE
 extern void fixture_log_fault(unsigned,int);fixture_log_fault(kind,journal);
#endif
 if((clock_failed&&kind==5)||logbad||logbytes+h.bytes>JOURNAL_BYTES||exact(journal,&h,sizeof h,1)||exact(journal,(void*)p,n,1)||fsync(journal)){logbad=1;return -1;}logbytes+=h.bytes;return 0;}
static int status(unsigned code){char b[32];memset(b,' ',sizeof b);if(snprintf(b,sizeof b,"%010u\n",code)!=11)return -1;b[11]=' ';return pwrite(statusfd,b,sizeof b,0)==sizeof b&&!fsync(statusfd)?0:-1;}
static int reserve(const char*name,unsigned n){int f=open(name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(f<0)return -1;unsigned char b[4096]={0};for(unsigned i=0;i<n;i+=sizeof b)if(exact(f,b,n-i>sizeof b?sizeof b:n-i,1)){close(f);return -1;}if(fsync(f)||lseek(f,0,SEEK_SET)!=0){close(f);return -1;}return f;}
static int space(void){struct statvfs v;return statvfs(".",&v)||!v.f_frsize||v.f_bavail>UINT64_MAX/v.f_frsize||(uint64_t)v.f_bavail*v.f_frsize<JOURNAL_BYTES+65536?-1:0;}
struct peer {pid_t pid;int cmd,reply;unsigned used,want;uint64_t sent_ms;unsigned char data[sizeof(struct pr_result)];};
static int highdup(int fd){return fcntl(fd,F_DUPFD_CLOEXEC,20);}
static int close_others(unsigned first){
#if defined(__APPLE__) && defined(PREVIEW_FIXTURE)
 const char*path="/dev/fd";
#else
 const char*path="/proc/self/fd";
#endif
 DIR*d=opendir(path);if(!d)return -1;int own=dirfd(d);struct dirent*e;unsigned count=0;int bad=0;while((e=readdir(d))){if(++count>65536){bad=1;break;}char*end;unsigned long n=strtoul(e->d_name,&end,10);if(!*end&&n>=first&&n<=INT_MAX&&(int)n!=own)if(close((int)n)&&errno!=EBADF)bad=1;}if(closedir(d))bad=1;return bad?-1:0;}
static int launch_peer(struct peer*p,const char*path,char*const args[],int log){int q[2],r[2];if(pipe(q))return -1;if(pipe(r)){close(q[0]);close(q[1]);return -1;}
 p->pid=fork();if(p->pid<0){close(q[0]);close(q[1]);close(r[0]);close(r[1]);return -1;}
 if(!p->pid){
  int old[4]={q[0],r[1],lockfd,log},copy[4];for(unsigned i=0;i<4;i++){copy[i]=old[i]>=0?highdup(old[i]):-1;if(old[i]>=0&&copy[i]<0)_exit(120);}
  int null=open("/dev/null",O_RDWR);if(null<0)_exit(121);for(unsigned i=0;i<3;i++)if(dup2(null,i)<0)_exit(121);
  for(unsigned i=0;i<4;i++)if(copy[i]>=0&&dup2(copy[i],3+i)<0)_exit(122);
  if(close_others(7))_exit(124);
  if(log<0)close(6);
  signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);
  char*const environment[]={"PATH=/usr/bin:/bin","LD_LIBRARY_PATH=/usr/lib:/lib",0};execve(path,args,environment);_exit(123);
 }
 close(q[0]);close(r[1]);p->cmd=q[1];p->reply=r[0];p->used=0;
 if(fcntl(p->cmd,F_SETFD,FD_CLOEXEC)||fcntl(p->reply,F_SETFD,FD_CLOEXEC)||fcntl(p->reply,F_SETFL,O_NONBLOCK))return -1;return 0;
}
static int pollpeer(struct peer*p,unsigned n){if(n>sizeof p->data||p->used>n)return -1;while(p->used<n){ssize_t z=read(p->reply,p->data+p->used,n-p->used);if(z<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 1;if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p->used+=(unsigned)z;}return 0;}
static int command(struct peer*p,uint32_t magic,unsigned seq,unsigned action){uint32_t q[4]={magic,seq,action,0};if(p->used&&p->used!=p->want)return -1;
 uint64_t sent=ms();if(clock_failed)return -1;p->sent_ms=sent;p->used=0;int rc=exact(p->cmd,q,sizeof q,1);
#ifdef PREVIEW_FIXTURE
 extern void fixture_command_sent(uint32_t);if(!rc)fixture_command_sent(magic);
#endif
 return rc;
}
static int awaitpeer(struct peer*p,unsigned n,unsigned timeout){uint64_t begin=p->sent_ms?p->sent_ms:ms();if(clock_failed)return -1;int rc;while((rc=pollpeer(p,n))==1){uint64_t now=ms();if(clock_failed||now-begin>=timeout)return -1;pause_ms(10);}uint64_t completed=ms();if(clock_failed||completed-begin>=timeout)return -1;return rc;}
#ifdef PREVIEW_FIXTURE
extern int fixture_reader(void);
#else
static int fixed_file(const char*path,const unsigned char*want,unsigned bytes){int f=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return -1;struct stat a={0},b={0};int ok=!fstat(f,&a)&&S_ISREG(a.st_mode)&&a.st_size==bytes&&a.st_uid==0&&a.st_gid==0&&a.st_nlink==1&&(a.st_mode&0777)==0700;
 struct sha256 h;sha_init(&h);unsigned char block[4096],digest[32];unsigned left=bytes;while(ok&&left){unsigned ask=left>4096?4096:left;ssize_t n=read(f,block,ask);if(n<=0||(unsigned)n>ask){ok=0;break;}sha_add(&h,block,(unsigned)n);left-=(unsigned)n;}sha_end(&h,digest);
 if(read(f,block,1)!=0||fstat(f,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mtime!=b.st_mtime||memcmp(want,digest,32))ok=0;if(close(f))ok=0;return ok?0:-1;
}
static int reader_main(const char*boot,unsigned pid,uint64_t start){
 signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);signal(SIGINT,SIG_IGN);signal(SIGTERM,SIG_IGN);lockfd=5;
 struct pr_result result={.magic=0x31535050};if(pr_open(boot,pid,start))result.error=100;
 struct peer backup={.cmd=-1,.reply=-1};char*const args[]={"preview-backup-worker.elf",0};
 if(!result.error&&launch_peer(&backup,"./preview-backup-worker.elf",args,-1))result.error=101;
 if(exact(4,&result,sizeof result,1)||result.error)return 101;
 for(unsigned seq=1;;seq++){
  uint32_t q[4];if(exact(3,q,sizeof q,0))break;if(q[0]!=0x31515050||q[1]!=seq||q[2]!=1||q[3])break;
  /* backup reply fd must be blocking: this isolated read worker may wait;
   * supervisor times out independently, without killing this native call. */
  if(fcntl(backup.reply,F_SETFL,0))break;
  (void)pr_sample(&result,seq,backup.cmd,backup.reply);
  if(exact(4,&result,sizeof result,1)||result.error)break;
 }
 close(backup.cmd);close(backup.reply);return 0;
}
#endif
static int selfcheck(void){struct stat st;if(stat(".",&st)||!S_ISDIR(st.st_mode)||(st.st_mode&0777)!=0700||st.st_uid!=geteuid()||space())return -1;
#ifndef PREVIEW_FIXTURE
 struct statfs fs;if(geteuid()||st.st_gid||statfs(".",&fs)||fs.f_type!=0x01021994)return -1;
 for(unsigned i=0;i<sizeof worker_identities/sizeof worker_identities[0];i++)if(fixed_file(worker_identities[i].path,worker_identities[i].sha,worker_identities[i].bytes))return -1;
#endif
 return 0;
}
static int baseline_log(unsigned action,unsigned intent,const struct bl_state*s){
 struct {uint32_t magic,action,intent,bytes;struct bl_state state;} row={0x314c424c,action,intent,sizeof *s,*s};
 return logrow(8,&row,sizeof row);
}
static int baseline_step(struct bl_state*s,const struct bl_io*io,unsigned action){
 int log_failed=baseline_log(action,1,s);
 /* Publication requires durable intent. Retirement is already-authorized
  * cleanup of this lease's selector, so a journal I/O error must not suppress
  * its single safe attempt. Logging failure still prevents overall success. */
 if(log_failed&&action!=3)return -1;
 int rc=action==1?bl_prepare(s,io):action==2?bl_publish(s,io):bl_retire(s,io);
 if(baseline_log(action,0,s)||log_failed)return -1;return rc;
}
static int supervise(const char*boot,const char*pidtext,const char*starttext,unsigned duration,int probe,int retained_round){
 struct peer reader={.cmd=-1,.reply=-1},owner={.cmd=-1,.reply=-1};struct pg_policy policy={.duration_ms=duration};struct pr_result sample;memset(&sample,0,sizeof sample);
 struct bl_state lease={0};struct bl_io lease_io={0};struct br_snapshot prior={0},initial={0};int lease_open=0;
 unsigned result=90,owner_seq=0,reader_seq=0;int owner_result=0,pending=0;uint64_t owner_when=0;uint32_t expected_phase=PO_READY;
#ifdef PREVIEW_FIXTURE
 const char*lockpath="../fixture-preview.lock";
#else
 const char*lockpath="/tmp_bt/a7r-stock-record-guard.lock";
#endif
 lockfd=open(lockpath,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);struct stat st;
 if(lockfd<0||fstat(lockfd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0777)!=0600||st.st_nlink!=1||flock(lockfd,LOCK_EX|LOCK_NB))return 91;
 statusfd=reserve("exit-code",32);if(statusfd<0)return 92;if(status(999))return 93;
#ifdef PREVIEW_SPACE_RACE
 extern void fixture_fill(void);fixture_fill();
#endif
 journal=reserve("run.bin",JOURNAL_BYTES);ownerjournal=reserve("owner.bin",4096);if(journal<0||ownerjournal<0){result=94;goto done;}
 if(!probe){
#ifdef PREVIEW_FIXTURE
 extern int fixture_baseline_open(struct bl_io*);if(fixture_baseline_open(&lease_io)){
#else
 if(pr_baseline_open(boot,(unsigned)strtoul(pidtext,0,10),strtoull(starttext,0,10),&lease_io)){
#endif
 result=132;goto done;}lease_open=1;
 }
 char*const rargs[]={"preview-guard.elf","--reader",(char*)boot,(char*)pidtext,(char*)starttext,0};
 if(launch_peer(&reader,"./preview-guard.elf",rargs,-1)){result=95;goto done;}
 reader.want=sizeof(struct pr_result);
 if(awaitpeer(&reader,reader.want,15000)){result=96;goto done;}
 memcpy(&sample,reader.data,sizeof sample);if(sample.magic!=0x31535050||sample.sequence||sample.error||sample.request_sent_ms){result=97;goto done;}
 if(probe){
  /* Diagnostic only: no owner process, dynamic source, or dial event exists. */
  for(unsigned i=0;i<2;i++){
   if(command(&reader,0x31515050,++reader_seq,1)||awaitpeer(&reader,sizeof sample,3000)){result=103;goto done;}
   memcpy(&sample,reader.data,sizeof sample);if(sample.request_sent_ms){result=130;goto done;}sample.request_sent_ms=reader.sent_ms;if(logrow(7,&sample,sizeof sample)){result=105;goto done;}
   if(sample.magic!=0x31535050||sample.sequence!=reader_seq||sample.reserved||sample.error||!pg_photo(&sample.observation)){result=130;goto done;}
   if(i&&!br_check_photo_initial(&prior,&sample.baseline)){result=133;goto done;}prior=sample.baseline;
   if(!i)pause_ms(200);
  }
  result=0;goto done;
 }
 char*const oargs[]={"preview-owner-worker.elf",0};if(launch_peer(&owner,"./preview-owner-worker.elf",oargs,ownerjournal)){result=98;goto done;}
 owner.want=16;if(awaitpeer(&owner,16,10000)){result=99;goto done;}
 uint32_t ready[4];memcpy(ready,owner.data,16);if(ready[0]!=0x31524750||ready[1]||ready[2]!=PO_READY||ready[3]){result=100;goto done;}
 if(logrow(1,ready,sizeof ready)){result=101;goto done;}
 for(unsigned turns=0;turns<MAX_TURNS;turns++){
  if(command(&reader,0x31515050,++reader_seq,1)){result=102;goto hold;}
  if(awaitpeer(&reader,sizeof sample,3000)){result=103;goto hold;}
  memcpy(&sample,reader.data,sizeof sample);
  if(sample.magic!=0x31535050||sample.sequence!=reader_seq||sample.reserved||sample.request_sent_ms){result=104;goto hold;}
  sample.request_sent_ms=reader.sent_ms;
  if(sample.error){(void)logrow(2,&sample,sizeof sample);result=104;goto hold;}
  if(!bl_expected(&lease,sample.rtos.overrides)||(!sample.baseline.error&&memcmp(sample.rtos.overrides,sample.baseline.overrides,16))||
     (retained_round&&bl_kind(sample.rtos.overrides)!=BL_RETAINED)){
   (void)logrow(2,&sample,sizeof sample);result=134;goto hold;
  }
  if(pending){int r=pollpeer(&owner,16);if(r<0){owner_result=-1;pending=0;}else if(!r){uint32_t answer[4];memcpy(answer,owner.data,16);owner_result=answer[0]==0x31524750&&answer[1]==owner_seq&&answer[2]==expected_phase&&!answer[3]?0:-1;pending=0;if(logrow(3,answer,16))owner_result=-1;}else if(ms()-owner_when>=10000){owner_result=-1;}}
  uint64_t now=ms();if(clock_failed){result=131;goto hold;}
  if(now-sample.request_sent_ms>=3000){result=103;goto hold;}
  int gate=1;
  if(policy.phase==PG_PRE&&policy.stable&&pg_photo(&sample.observation))gate=br_check_photo_initial(&prior,&sample.baseline);
  if(((policy.phase==PG_ENTERING&&policy.stable)||policy.phase==PG_PREVIEW)&&pg_movie(&sample.observation))gate=br_check_movie_baseline(&prior,&sample.baseline);
  if(((policy.phase==PG_RETURNING&&policy.stable)||policy.phase==PG_RETIRING)&&pg_photo(&sample.observation))gate=br_check_photo_restored(&initial,&prior,&sample.baseline);
  if(!gate){(void)logrow(2,&sample,sizeof sample);result=135;goto hold;}
  int action=pg_tick(&policy,&sample.observation,now,owner_result<0?-1:pending?1:owner_result,cancel_requested,!logbad);
  if(logrow(2,&sample,sizeof sample)||logrow(4,&policy,sizeof policy)){result=105;goto hold;}
  if(action){
   if(action==PG_ENTER){
    initial=sample.baseline;
    if(baseline_step(&lease,&lease_io,1)||(!retained_round&&baseline_step(&lease,&lease_io,2))){result=136;goto hold;}
   }
   if(action==PG_RETURN&&baseline_step(&lease,&lease_io,3)){result=137;goto hold;}
   if(ms()-sample.request_sent_ms>=3000||clock_failed){result=138;goto hold;}
   uint32_t claim[4]={action,owner_seq+1,policy.phase,0};if(logrow(5,claim,sizeof claim)){result=106;goto hold;}
   if(pending||owner_result||command(&owner,0x31434750,++owner_seq,(unsigned)action)){result=107;goto hold;}
   pending=1;owner_when=owner.sent_ms;expected_phase=action==PG_ENTER?PO_ENTERED:action==PG_RETURN?PO_RETURNED:PO_RETIRED;if(clock_failed){result=131;goto hold;}
  }
  if(policy.phase==PG_HOLD){result=110+policy.error;goto done;}
  if(policy.phase==PG_DONE){result=0;goto done;}
  prior=sample.baseline;
  pause_ms(250);
 }
 result=108;
hold:policy.phase=PG_HOLD;if(!policy.error)policy.error=PG_OBSERVE;
done:
 /* The payload is never cleared. Even HOLD can disable only this lease's
  * selector once; no native source event is inferred from a timeout. */
 if(lease_open&&lease.phase!=BL_NEW&&lease.phase!=BL_RETIRED&&!lease.retire_attempt){
  if(baseline_step(&lease,&lease_io,3)&&!result)result=139;
 }
 if(clock_failed){result=131;policy.phase=PG_HOLD;policy.error=PG_CLOCK;}
 {uint32_t end[8]={result,policy.phase,policy.error,policy.enter_claim,policy.return_claim,policy.retire_claim,(uint32_t)owner.pid,(uint32_t)reader.pid};if(journal>=0)(void)logrow(6,end,sizeof end);}
 if(reader.cmd>=0)close(reader.cmd);if(owner.cmd>=0)close(owner.cmd);
 /* On HOLD, worker EOF retains a claimed original source and inherited lock.
  * No wait/kill/replay. DONE additionally requires source retirement receipt. */
 if(statusfd>=0&&status(result))result=109;return(int)result;
}
static int valid_uuid(const char*s){if(strlen(s)!=36)return 0;for(unsigned i=0;i<36;i++)if(i==8||i==13||i==18||i==23){if(s[i]!='-')return 0;}else if(!strchr("0123456789abcdef",s[i]))return 0;return 1;}
int main(int argc,char**argv){
 if(argc==5&&!strcmp(argv[1],"--reader")){
#ifdef PREVIEW_FIXTURE
  return fixture_reader();
#else
  return reader_main(argv[2],(unsigned)strtoul(argv[3],0,10),strtoull(argv[4],0,10));
#endif
 }
 if(argc!=7||(strcmp(argv[1],"--check")&&strcmp(argv[1],"--launch")&&strcmp(argv[1],"--probe")&&strcmp(argv[1],"--launch-retained"))||!valid_uuid(argv[3]))return 80;
 char*end;unsigned long pid=strtoul(argv[4],&end,10);if(*end||pid<2||pid>INT_MAX)return 81;unsigned long long start=strtoull(argv[5],&end,10);if(*end||!start||argv[5][0]=='-')return 82;
 unsigned long duration=strtoul(argv[6],&end,10);if(*end||duration<1000||duration>45000||(strcmp(argv[1],"--launch-retained")&&duration!=1000))return 83;
 if(chdir(argv[2])||selfcheck())return 84;
 if(!strcmp(argv[1],"--check")){
#ifndef PREVIEW_FIXTURE
  if(pr_open(argv[3],(unsigned)pid,start))return 90;
#endif
  return 0;
 }
 int probe=!strcmp(argv[1],"--probe");int claim=open(probe?"probe.claim":"launch.claim",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(claim<0)return 85;char evidence[120];int n=snprintf(evidence,sizeof evidence,"%s %lu %llu %lu\n",argv[3],pid,start,duration);if(n<0||(unsigned)n>=sizeof evidence||exact(claim,evidence,(unsigned)n,1)||fsync(claim)||close(claim))return 86;
 pid_t child=fork();if(child<0)return 87;if(child){printf("PREVIEW_GUARD pid=%ld detached=1\n",(long)child);return 0;}
 if(setsid()<0)_exit(88);signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);signal(SIGINT,cancel);signal(SIGTERM,cancel);
 int null=open("/dev/null",O_RDWR);if(null<0)_exit(89);for(unsigned i=0;i<3;i++)if(dup2(null,i)<0)_exit(89);if(close_others(3))_exit(89);
 int rc=supervise(argv[3],argv[4],argv[5],(unsigned)duration,probe,!strcmp(argv[1],"--launch-retained"));_exit(rc);
}
