#include "preview_policy.h"
static int exact3(const uint32_t*v,uint32_t n){return v[0]==n&&v[1]==n&&v[2]==n;}
static int common(const struct pg_observation*s,uint32_t seq,uint32_t dial,uint32_t b){
 return s->identity_ok==1&&s->config_ok==1&&s->complete==1&&
  s->seq_done==seq&&s->seq_target==seq&&s->seq_applied==seq&&
  !s->seq_queued&&!s->seq_flags&&s->key==0x7025&&!s->subkey&&
  s->dial==dial&&s->exinfo==0x116&&s->backup[0]==b&&s->backup[1]==b;
}
int pg_photo(const struct pg_observation*s){
 return common(s,2,6,5)&&s->ui==PG_UI_PHOTO&&exact3(s->mode,1)&&exact3(s->encoder,0);
}
int pg_movie(const struct pg_observation*s){
 return common(s,8,10,19)&&s->ui==PG_UI_MOVIE4&&exact3(s->mode,76)&&
  s->encoder[0]==3&&!s->encoder[1]&&!s->encoder[2];
}
static int hold(struct pg_policy*p,unsigned e){p->phase=PG_HOLD;if(!p->error)p->error=e;return PG_NONE;}
static int twice(struct pg_policy*p,uint64_t now){
 if(!p->stable){p->stable=1;p->stable_ms=now;return 0;}
 if(now-p->stable_ms<200)return 0;
 p->stable=2;return 1;
}
int pg_tick(struct pg_policy*p,const struct pg_observation*s,uint64_t now,int worker,int cancel,int journal_ok){
 if(p->phase==PG_DONE||p->phase==PG_HOLD)return PG_NONE;
 if(now<p->last_ms)return hold(p,PG_CLOCK);p->last_ms=now;
 if(!journal_ok)return hold(p,PG_JOURNAL);
 if(s->identity_ok!=1)return hold(p,PG_IDENTITY);
 if(s->config_ok!=1)return hold(p,PG_CONFIG);
 if(worker<0)return hold(p,p->phase==PG_RETURNING?PG_RETURN_IO:p->phase==PG_RETIRING?PG_RETIRE_IO:PG_ENTER_IO);
 if(p->duration_ms<1000||p->duration_ms>45000)return hold(p,PG_BASELINE);
 if(p->phase==PG_PRE){
  if(cancel)return hold(p,PG_CANCELLED);
  if(worker||!pg_photo(s)||p->enter_claim)return hold(p,PG_BASELINE);
  if(!twice(p,now))return PG_NONE;
  p->stable=0;p->enter_claim=1;p->enter_ms=now;p->phase=PG_ENTERING;return PG_ENTER;
 }
 if(p->phase==PG_ENTERING){
  if(now-p->enter_ms>=10000)return hold(p,PG_ENTER_TIMEOUT);
  if(worker||!pg_movie(s)){p->stable=0;return PG_NONE;}
  if(!twice(p,now))return PG_NONE;
  p->seen_movie=1;p->preview_ms=now;p->stable=0;p->phase=PG_PREVIEW;
 }
 if(p->phase==PG_PREVIEW){
  /* No return based solely on a deadline. Only the exact current original
   * movie-opened state authorizes the one native return position event. */
  if(worker)return hold(p,PG_UNEXPECTED);
  if(!pg_movie(s)){
   p->stable=0;
   if(s->complete||now-p->preview_ms>=p->duration_ms+2000)return hold(p,PG_OBSERVE);
   return PG_NONE;
  }
  if(!cancel&&now-p->preview_ms<p->duration_ms)return PG_NONE;
  if(!p->seen_movie||p->return_claim)return hold(p,PG_UNEXPECTED);
  p->return_claim=1;p->return_ms=now;p->stable=0;p->phase=PG_RETURNING;return PG_RETURN;
 }
 if(p->phase==PG_RETURNING){
  if(now-p->return_ms>=10000)return hold(p,PG_RETURN_TIMEOUT);
  if(worker||!pg_photo(s)){p->stable=0;return PG_NONE;}
  if(!twice(p,now))return PG_NONE;
  if(p->retire_claim)return hold(p,PG_UNEXPECTED);
  p->retire_claim=1;p->phase=PG_RETIRING;return PG_RETIRE;
 }
 if(p->phase==PG_RETIRING){
  if(!pg_photo(s))return hold(p,PG_OBSERVE);
  if(worker){if(now-p->return_ms>=12000)return hold(p,PG_RETIRE_IO);return PG_NONE;}
  p->phase=PG_DONE;
 }
 return PG_NONE;
}
