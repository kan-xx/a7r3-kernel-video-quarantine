/* All RTOS reads use pread(/dev/mem) -> qualified read_mem cached __va path.
 * No mmap, O_SYNC alias, cache maintenance, or MMIO is used. The fixed
 * baseline-only writer below uses the separately qualified cached write_mem. */
#define _GNU_SOURCE
#include "production_reader.h"
#include "baseline_lease.h"
#include "baseline_writer.h"
#include "baseline_kernel_anchor.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../ram-observers/observer_anchors.h"
#include "../ram-observers/sha256_local.h"
#include "reader_identities.h"
struct range{uint32_t a,z,offset;unsigned major,minor;uint64_t inode;char permission[5],path[180];};
static struct range ranges[2048];static unsigned nr,pid;static uint64_t start;static char boot[40];
static int memfd=-1,procfd=-1,io_failed;static uint32_t objbase,viewbase;static struct stat files[32];
static int text(const char*path,char*out,unsigned cap){int f=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return -1;unsigned n=0;int ok=1;while(n+1<cap){ssize_t z=read(f,out+n,cap-n-1);if(z<0&&errno==EINTR)continue;if(z<0){ok=0;break;}if(!z)break;n+=(unsigned)z;}char tail;if(read(f,&tail,1)!=0)ok=0;if(close(f))ok=0;if(!ok)return -1;out[n]=0;return(int)n;}
static int epoch(void){char b[2048],p[80],exe[64];if(text("/proc/sys/kernel/random/boot_id",b,sizeof b)!=37||memcmp(b,boot,36)||b[36]!='\n')return 0;
 snprintf(p,sizeof p,"/proc/%u/exe",pid);if(readlink(p,exe,sizeof exe)!=15||memcmp(exe,"/usr/bin/im.elf",15))return 0;
 snprintf(p,sizeof p,"/proc/%u/stat",pid);if(text(p,b,sizeof b)<1)return 0;char prefix[40];snprintf(prefix,sizeof prefix,"%u (im.elf) ",pid);if(strncmp(b,prefix,strlen(prefix)))return 0;
 char*q=strrchr(b,')');if(!q||q[1]!=' '||q[3]!=' ')return 0;q+=4;uint64_t got=0;
 for(unsigned i=4;i<=22;i++){char*end;errno=0;unsigned long long v=strtoull(q,&end,10);if(errno||end==q||(*end&&*end!=' '&&*end!='\n'))return 0;if(i==4&&v!=1)return 0;if(i==22)got=v;q=*end?end+1:end;}
 return got==start;
}
static int same_stat(const struct stat*a,const struct stat*b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtime==b->st_mtime&&a->st_ctime==b->st_ctime;}
static int file_identity(unsigned i,int full){const struct reader_identity*x=&reader_identities[i];struct stat st;int f=open(x->path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return -1;int ok=!fstat(f,&st)&&S_ISREG(st.st_mode)&&st.st_size==(off_t)x->bytes;
 if(ok&&!full)ok=same_stat(&st,&files[i]);
 if(ok&&full){unsigned char buf[4096],digest[32];struct sha256 h;sha_init(&h);unsigned left=x->bytes;while(ok&&left){unsigned ask=left>sizeof buf?sizeof buf:left;ssize_t n=read(f,buf,ask);if(n<=0||(unsigned)n>ask){ok=0;break;}sha_add(&h,buf,(unsigned)n);left-=(unsigned)n;}sha_end(&h,digest);struct stat after;if(read(f,buf,1)!=0||fstat(f,&after)||!same_stat(&st,&after)||memcmp(digest,x->sha,32))ok=0;}
 if(close(f))ok=0;if(ok&&full)files[i]=st;return ok?0:-1;
}
static int maps(void){char p[80];static char buf[262144];snprintf(p,sizeof p,"/proc/%u/maps",pid);if(text(p,buf,sizeof buf)<1)return -1;
 nr=0;uint32_t ob=0,vb=0;for(char*l=buf;l&&*l;){char*next=strchr(l,'\n');if(next)*next++=0;if(nr>=2048)return -1;
  struct range*r=&ranges[nr];memset(r,0,sizeof*r);unsigned long long ino;int at=0;
  if(sscanf(l,"%x-%x %4s %x %x:%x %llu %n",&r->a,&r->z,r->permission,&r->offset,&r->major,&r->minor,&ino,&at)!=7||r->a>=r->z||(nr&&r->a<ranges[nr-1].z)||strlen(l+at)>=sizeof r->path)return -1;
  r->inode=ino;strcpy(r->path,l+at);nr++;
  if(!strcmp(r->path,"/usr/lib/libObj.so")||!strcmp(r->path,"/usr/lib/viewUnified2.so")){
   unsigned i=!strcmp(r->path,"/usr/lib/libObj.so")?0:1;
   if(r->major!=major(files[i].st_dev)||r->minor!=minor(files[i].st_dev)||r->inode!=(uint64_t)files[i].st_ino)return -1;
   if(!r->offset&&!strcmp(r->permission,"r-xp")){uint32_t*v=i?&vb:&ob;if(*v)return -1;*v=r->a;}
  }
  l=next;
 }
 if(!ob||!vb||(objbase&&objbase!=ob)||(viewbase&&viewbase!=vb))return -1;objbase=ob;viewbase=vb;return 0;
}
static int aliases(void){for(unsigned i=0;i<sizeof reader_aliases/sizeof reader_aliases[0];i++){char b[128];ssize_t n=readlink(reader_aliases[i].path,b,sizeof b);unsigned wanted=(unsigned)strlen(reader_aliases[i].target);if(n!=(ssize_t)wanted||memcmp(b,reader_aliases[i].target,wanted))return -1;}return 0;}
static int qualified(void){if(!epoch()||aliases())return -1;for(unsigned i=0;i<sizeof reader_identities/sizeof reader_identities[0];i++)if(file_identity(i,0))return -1;return maps()||!epoch()?-1:0;}
static int process_read(void*ctx,uint32_t a,void*out,uint32_t n){(void)ctx;if(!n||n>8192||a>UINT32_MAX-n)goto bad;for(unsigned i=0;i<nr;i++)if(ranges[i].permission[0]=='r'&&a>=ranges[i].a&&a+n<=ranges[i].z){if(pread(procfd,out,n,(off_t)a)==(ssize_t)n)return 0;break;}bad:io_failed=1;return -1;}
static int ram_read(void*ctx,uint32_t a,void*out,uint32_t n){(void)ctx;if(!out||!n||n>8192||a<0x62e68000||a>=0x648c6000||n>0x648c6000-a||pread(memfd,out,n,(off_t)(a-0x60000000))!=(ssize_t)n){io_failed=1;return -1;}return 0;}
int pr_open(const char*b,unsigned p,uint64_t t){if(!b||strlen(b)!=36||p<2||!t)return -1;strcpy(boot,b);pid=p;start=t;
 if(sizeof reader_identities/sizeof reader_identities[0]>32||!epoch())return -1;
 for(unsigned i=0;i<sizeof reader_identities/sizeof reader_identities[0];i++)if(file_identity(i,1))return -1;
 char line[2048],v[8],path[80];if(text("/proc/cmdline",line,sizeof line)<1||!strstr(line,"memrsv=0x1A5E000@0x02E68000")||!strstr(line,"mem=1G@0")||text("/setting/updater/dat4",v,sizeof v)!=2||v[0]!=0x10||v[1]!=3)return -1;
 memfd=open("/dev/mem",O_RDONLY|O_CLOEXEC);snprintf(path,sizeof path,"/proc/%u/mem",pid);procfd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(memfd<0||procfd<0||qualified())return -1;
 unsigned char anchor[184];for(unsigned i=0;i<sizeof anchors/sizeof anchors[0];i++)if(ram_read(0,anchors[i].va,anchor,anchors[i].n)||memcmp(anchor,anchors[i].data,anchors[i].n))return -1;
 if(br_check_anchors(ram_read,0))return -1;
 return 0;
}
static int exact(int fd,void*p,unsigned n,int writing){unsigned char*b=p;while(n){ssize_t z=writing?write(fd,b,n):read(fd,b,n);if(z<0&&errno==EINTR)continue;if(z<=0||(unsigned)z>n)return -1;b+=z;n-=(unsigned)z;}return 0;}
int pr_sample(struct pr_result*out,uint32_t sequence,int backup_command,int backup_reply){
 memset(out,0,sizeof*out);out->magic=0x31535050;out->sequence=sequence;io_failed=0;
 struct pg_observation*s=&out->observation;struct pu_snapshot u[3];struct pr_rtos r[3];int urc[3];
 if(qualified()){out->error=1;return -1;}s->identity_ok=1;
 for(unsigned i=0;i<3;i++){
  if(qualified()){s->identity_ok=0;out->error=2;return -1;}
  if(pr_rtos_read(ram_read,0,&r[i])){out->error=3;s->identity_ok=0;return -1;}
  const uint32_t fmt[4]={4,2,0,6};s->config_ok=!memcmp(r[i].format,fmt,16);if(bl_kind(r[i].overrides)==BL_OTHER)s->config_ok=0;
  if(!s->config_ok){out->error=4;return -1;}
  urc[i]=pu_snapshot_read(process_read,0,objbase,viewbase,&u[i]);if(io_failed){out->error=5;s->identity_ok=0;return -1;}
  if(i==1){uint32_t q[4]={0x31514250,sequence,1,0};uint32_t*answer=out->backup_reply;if(exact(backup_command,q,sizeof q,1)||exact(backup_reply,answer,sizeof out->backup_reply,0)||answer[0]!=0x31524250||answer[1]!=sequence||answer[2]||answer[5]!=1||answer[6]!=1||answer[7]!=1||answer[8]!=1||answer[11]!=1||(answer[10]&0xffffff00)!=0xa5a5a500||(answer[13]&0xffffff00)!=0xa5a5a500||(answer[10]&255)!=answer[3]||(answer[13]&255)!=answer[4]||answer[3]>255||answer[4]>255){out->error=6;return -1;}s->backup[0]=answer[3];s->backup[1]=answer[4];}
  if(i<2){struct timespec ts={0,100000000};while(nanosleep(&ts,&ts)&&errno==EINTR){}}
 }
 if(qualified()){out->error=7;s->identity_ok=0;return -1;}
 out->rtos=r[2];out->ui=u[2];memcpy(s->mode,r[2].mode,12);memcpy(s->encoder,r[2].state,12);
 s->seq_done=r[2].seq[0];s->seq_target=r[2].seq[1];s->seq_applied=r[2].seq[2];s->seq_queued=r[2].seq[3];s->seq_flags=r[2].flags;
 s->key=u[2].cache_words[0];s->subkey=u[2].cache_words[1];s->dial=u[2].cache_words[2];s->exinfo=u[2].cache_words[3];s->ui=u[2].kind;
 s->complete=!urc[0]&&!urc[1]&&!urc[2]&&pu_same(&u[0],&u[1])&&pu_same(&u[1],&u[2])&&!memcmp(&r[0],&r[1],sizeof r[0])&&!memcmp(&r[1],&r[2],sizeof r[0]);
 if(br_capture(ram_read,0,&out->baseline))s->complete=0;
 if(qualified()){out->error=9;s->identity_ok=0;return -1;}
 return 0;
}

/* Baseline-only writer. This is a separate successor, never part of the
 * frozen stock guard. No mmap is used: pwrite invokes cached write_mem.
 * Data source is a fixed, locked, page-aligned read-only ELF object. */
static const unsigned char bl_source[4096] __attribute__((aligned(4096)))={
 [0]=2,[1]=3,[2]=0x4e,[3]=7,[4]=1,[5]=0xbb,[6]=10,[16]=33,[17]=255
};
static int bl_memfd=-1;
static int bl_qualified(void*unused){
 (void)unused;unsigned char code[300];struct stat st;
 if(qualified()||bl_memfd<0||fstat(bl_memfd,&st)||!S_ISCHR(st.st_mode)||major(st.st_rdev)!=1||minor(st.st_rdev)!=1||
    pread(memfd,code,300,(off_t)0x2959a8)!=300||memcmp(code,baseline_kernel_write_mem,300))return -1;
 return 0;
}
static int bl_read16(void*unused,unsigned char out[16]){(void)unused;return ram_read(0,0x6402f4e0,out,16);}
static int bl_barrier(void*unused){(void)unused;
#if defined(__arm__)
 __asm__ volatile("dsb sy" ::: "memory");
#else
 __sync_synchronize();
#endif
 return 0;
}
static int bl_write_fixed(void*unused,unsigned op,int32_t*raw,int32_t*error){
 (void)unused;unsigned n;off_t pa;const unsigned char*source;
 *raw=-1;*error=0;
 if(bl_qualified(0)){*error=ESTALE;return -1;}
 if(op==BL_INIT7){n=7;pa=0x402f4e0;source=bl_source;}
 else if(op==BL_ENABLE1){n=1;pa=0x402f4e7;source=bl_source+16;}
 else if(op==BL_DISABLE1){n=1;pa=0x402f4e7;source=bl_source+17;}
 else{*error=EINVAL;return -1;}
 errno=0;ssize_t result=pwrite(bl_memfd,source,n,pa);*error=errno;*raw=(int32_t)result;
 return result==(ssize_t)n&&!*error?0:-1;
}
int pr_baseline_open(const char*b,unsigned p,uint64_t t,struct bl_io*out){
 if(!out||bl_memfd>=0||pr_open(b,p,t)||mlock(bl_source,sizeof bl_source))return -1;
 bl_memfd=open("/dev/mem",O_RDWR|O_CLOEXEC);
 if(bl_qualified(0))return -1;
 *out=(struct bl_io){0,bl_qualified,bl_read16,bl_write_fixed,bl_barrier};return 0;
}
