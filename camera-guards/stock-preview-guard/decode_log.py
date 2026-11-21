"""Decode bounded guard journal; never equate a successful probe with a transaction."""
from pathlib import Path
import json,struct,sys,hashlib
D=Path(__file__).resolve().parent
OBS_NAMES=['identity_ok','config_ok','complete','ui']+['mode'+str(i) for i in range(3)]+['encoder'+str(i) for i in range(3)]+['seq_done','seq_target','seq_applied','seq_queued','seq_flags','key','subkey','dial','exinfo','backup0','backup1']
def decode(path):
 b=Path(path).read_bytes();at=0;sequence=0;events=[];final=None;claims=[];probe=0;layout=json.loads((D/'layout.json').read_text())
 if len(b)>layout['reserved_bytes']:raise ValueError('journal too large')
 while at+24<=len(b) and b[at:at+4]!=bytes(4):
  magic,kind,n,seq,ms=struct.unpack_from('<4IQ',b,at)
  if magic!=0x314a5050 or seq!=sequence+1 or n<24 or at+n>len(b):raise ValueError('journal framing')
  sequence=seq;raw=b[at+24:at+n];event=dict(kind=kind,sequence=seq,ms=ms,bytes=n)
  if kind in [2,7]:
   if len(raw)!=layout['result']:raise ValueError('sample size')
   magic2,request,error,reserved=struct.unpack_from('<4I',raw)
   if magic2!=0x31535050 or reserved:raise ValueError('sample header')
   values=struct.unpack_from('<21I',raw,layout['result_observation_offset']);event.update(request=request,error=error,observation=dict(zip(OBS_NAMES,values)));probe+=kind==7
   reply=list(struct.unpack_from('<16I',raw,layout['result_backup_reply_offset']));event['backup_reply']=reply
   event['request_sent_ms']=struct.unpack_from('<Q',raw,layout['result_request_sent_ms_offset'])[0]
   event['request_age_at_log_ms']=ms-event['request_sent_ms'] if event['request_sent_ms'] else None
   event['sample_fresh_at_log']=bool(event['request_sent_ms'] and 0<=ms-event['request_sent_ms']<3000)
   event['backup_calls']=[dict(key=hex(key),size=reply[5+k],size_errno=reply[14+k],read_rc=struct.unpack('<i',struct.pack('<I',reply[8+3*k]))[0],read_errno=reply[9+3*k],canary=hex(reply[10+3*k]),value=reply[3+k],attempted=reply[0]==0x31524250 and reply[8+3*k]!=0x80000000)for k,key in enumerate([0x010708bf,0x01071a8e])]
   x=raw[layout['result_baseline_offset']:];v=struct.unpack_from('<8I',x)
   if len(x)!=1192:raise ValueError('baseline snapshot size')
   event['baseline']=dict(magic=hex(v[0]),error=v[1],mode=list(v[2:5]),ctrl=hex(v[5]),param=hex(v[6]),sgc=hex(v[7]),
    param_object_hex=x[32:112].hex(),rows_hex=x[112:420].hex(),rows_sha256=hashlib.sha256(x[112:420]).hexdigest(),
    drv_hex=[x[420:744].hex(),x[744:1068].hex()],drv_sha256=[hashlib.sha256(x[420:744]).hexdigest(),hashlib.sha256(x[744:1068]).hexdigest()],
    sgc_hex=x[1068:1164].hex(),sgc_Hminus1=struct.unpack_from('<I',x,1068+0x34)[0],sgc_Vminus1=struct.unpack_from('<I',x,1068+0x38)[0],sgc_field48=x[1068+0x48],
    reservation_hex=x[1164:1176].hex(),overrides_hex=x[1176:1192].hex())
  elif kind in [1,3,5]:
   if len(raw)!=16:raise ValueError('receipt/claim size')
   event['words']=list(struct.unpack('<4I',raw))
   if kind==5:claims.append(event['words'][0])
  elif kind==4:
   if len(raw)!=layout['policy']:raise ValueError('policy size')
   event['policy_words']=list(struct.unpack_from('<8I',raw));event['policy']=dict(zip(['phase','error','enter_claim','return_claim','retire_claim','seen_movie','stable','duration_ms','last_ms','enter_ms','preview_ms','return_ms','stable_ms'],struct.unpack('<8I5Q',raw)))
  elif kind==6:
   if len(raw)!=32:raise ValueError('final size')
   final=list(struct.unpack('<8I',raw));event['final']=final
  elif kind==8:
   if len(raw)!=92:raise ValueError('lease record size')
   magic,action,intent,size=struct.unpack_from('<4I',raw)
   if magic!=0x314c424c or action not in [1,2,3] or intent not in [0,1] or size!=76:raise ValueError('lease header')
   v=list(struct.unpack_from('<6I2i3I',raw,16));event.update(action=action,intent=bool(intent),lease=dict(zip(['phase','error','initial_kind','init_attempt','publish_attempt','retire_attempt','write_result','write_errno','writes','last_op','read_error'],v)))
   event['lease'].update(before_hex=raw[60:76].hex(),after_hex=raw[76:92].hex())
  else:raise ValueError('unknown record')
  events.append(event);at+=n
 if any(b[at:]):raise ValueError('nonzero trailing/incomplete journal')
 lease_done=[e['lease']for e in events if e['kind']==8 and not e['intent']]
 last_lease=lease_done[-1]if lease_done else None
 transaction_success=bool(final and final[:6]==[0,5,0,1,1,1] and claims==[1,2,3] and not probe and last_lease and last_lease['phase']==3 and not last_lease['error'] and last_lease['after_hex']=='02034e0701bb0affffffffffffffffff')
 probe_success=bool(final and final[:7]==[0,0,0,0,0,0,0] and probe==2 and not claims)
 return dict(transaction_success=transaction_success,baseline_rehearsal_success=bool(transaction_success and last_lease['publish_attempt']==1),retained_roundtrip_success=bool(transaction_success and not last_lease['publish_attempt'] and not last_lease['writes']),probe_success=probe_success,complete_final=final is not None,claims=claims,final=final,used_bytes=at,events=events,hardware_frame_rate_proven=False)
if __name__=='__main__':
 if len(sys.argv)!=2:raise SystemExit('usage: decode_log.py run.bin')
 print(json.dumps(decode(sys.argv[1]),indent=2))
