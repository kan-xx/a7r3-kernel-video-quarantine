"""Decode copied standalone guard journal. Does not contact a camera."""
import argparse,json,struct
from pathlib import Path
PHASES=['pre','starting','running','stopping','done','failed']
ERRORS=['success','identity','observe','baseline','start_key','start_timeout','generation','early_idle','stop_key','stop_timeout','key_stuck','log','cancelled']
def policy(b):
 assert len(b)>=56
 v=struct.unpack_from('<6I4Q',b)
 x=dict(zip('phase error start_claim stop_claim seen_running idles start_ms stop_ms duration_ms uncertain_ms'.split(),v));x['phase_name']=PHASES[v[0]]if v[0]<len(PHASES)else'unknown';x['error_name']=ERRORS[v[1]]if v[1]<len(ERRORS)else'unknown';return x

def decode(data,allow_live=False):
 at=0;sequence=0;rows=[];complete=False
 while at<len(data):
  if len(data)-at<24:
   if allow_live:break
   raise ValueError('Truncated event header')
  if not any(data[at:at+24]):
   if not allow_live and not complete:raise ValueError('Preallocated live journal has no terminal proof')
   break
  magic,kind,size,seq,elapsed=struct.unpack_from('<4IQ',data,at)
  assert magic==0x31475253 and 24<=size<=4096 and seq==sequence+1 and 1<=kind<=6
  if at+size>len(data):
   if allow_live:break
   raise ValueError('Truncated event body')
  b=data[at+24:at+size];row=dict(kind=kind,sequence=seq,elapsed_ns=elapsed)
  if kind==1:
   assert len(b)==64 and not rows
   boot,pid,duration,start,started=struct.unpack('<40sIIQQ',b);row.update(boot_id=boot.split(b'\0')[0].decode(),pid=pid,duration_ms=duration,start_ticks=start,started_ns=started)
  elif kind==2:
   assert len(b)>=80
   gate=struct.unpack_from('<6I',b,56);row.update(policy=policy(b),qualified=gate[0],epoch_ok=gate[1],states=list(gate[2:5]),generation_same=gate[5],sample_bytes=len(b)-88,modes=list(struct.unpack_from('<3I',b,88)))
  elif kind==3:
   assert len(b)==8;action,pid=struct.unpack('<II',b);row.update(action='start'if action==1 else'stop',child_pid=pid)
  elif kind==4:
   assert len(b)==140;pid,status,rc=struct.unpack_from('<IIi',b);row.update(child_pid=pid,wait_status=status,receipt_result=rc,receipt=struct.unpack_from('<32I',b,12))
  elif kind==5:row['policy']=policy(b)
  else:
   assert len(b)==72
   pid,pending,idle,scope=struct.unpack_from('<iiII',b,56);row.update(policy=policy(b),child_pid=pid,child_pending=pending,idle_verified=idle,scope_flags=scope);complete=True
  rows.append(row);at+=size;sequence=seq
  if complete:
   assert not any(data[at:]),'Bytes after final event'
   break
 assert rows and rows[0]['kind']==1
 actions=[x['action']for x in rows if x['kind']==3];assert actions in ([],['start'],['start','stop'])
 final=rows[-1]if complete else None
 success=bool(complete and final['policy']['phase']==4 and final['policy']['error']==0 and final['idle_verified']==1 and not final['child_pending']and actions==['start','stop'])
 return dict(header=rows[0],complete=complete,success=success,actions=actions,final=final,rows=rows,bytes_consumed=at,acceptance_requires_exit_code_zero=True,scope='Same boot/process and qualified observed configuration lineage. No hardware capture-generation counter, final file validation or actual frame-rate proof.')
def decode_run(data,exit_code,allow_live=False):
 # Explicit pre-action resource/setup failures cannot contain a legitimate
 # recorder action. A zero-only reserved/partial journal is retained evidence.
 if exit_code in (90,91,92,93,94,97,98) and not any(data):
  return dict(complete=True,success=False,actions=[],exit_code=exit_code,
              pre_action_failure=True,pending=False,zero_journal_bytes=len(data),
              scope='Known r2 setup/resource failure before START; no recording or recovery success asserted.')
 x=decode(data,allow_live)
 x['exit_code']=exit_code;x['pending']=exit_code==999
 x['success']=bool(x['success']and exit_code==0)
 x['acceptance_requires_exit_code_zero']=False
 return x

if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('journal',type=Path);a.add_argument('--allow-live',action='store_true');a.add_argument('--summary',action='store_true');a.add_argument('--exit-code',type=Path);args=a.parse_args()
 code=int(args.exit_code.read_text().strip())if args.exit_code is not None else None
 data=args.journal.read_bytes()if args.journal.exists()else b''
 x=decode_run(data,code,args.allow_live)if code is not None else decode(data,args.allow_live)
 if args.summary:x.pop('rows',None)
 print(json.dumps(x,indent=2))
