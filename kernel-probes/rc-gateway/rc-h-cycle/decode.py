"""Immutable H-cycle observer decoder; requires every reserved row committed."""
import struct,json,hashlib
HEADER_BYTES=64;CAP=64;EVENT_BYTES=416;STATE_BYTES=HEADER_BYTES+CAP*EVENT_BYTES
HEADER_FIELDS=['magic','version','capacity','event_bytes','phase','reserved','dropped','restore_activation','restore_complete','no_unload','activation_gateway','complete_gateway','ever_published','install_result','independent_exposure_proved','order_counter']
FIELDS=[('committed',1),('native_r4',1),('native_lr',1),('jiffies_before',1),('jiffies_after',1),('kind',1),('flags',1),('return_value',1),('generation',1),('entry_order',1),('return_order',1),('sp',1),('lr',1),('source_lr',1),('args',5),('sequence',1),('job',1),('controller',1),('epoch',2),('driver',2),('state',2),('arm',2),('queue_index',2),('current_index',2),('cflags',2),('input_status',1),('output_status',1),('status_valid',1),('status_value',1),('io_before',4),('io_after',4),('input_before',14),('input_after',14),('output_before',14),('output_after',14)]
assert sum(n for _,n in FIELDS)*4==EVENT_BYTES
def record(raw):
 assert len(raw)==EVENT_BYTES;v=struct.unpack('<104I',raw);o=0;r={}
 for k,n in FIELDS:r[k]=v[o]if n==1 else list(v[o:o+n]);o+=n
 return r
def decode(raw,strict=False):
 assert len(raw)==STATE_BYTES,'size';h=dict(zip(HEADER_FIELDS,struct.unpack_from('<16I',raw)))
 assert [h[k]for k in ('magic','version','capacity','event_bytes')]==[0x48594331,1,64,416],'schema'
 assert h['reserved']<=64 and h['no_unload']==1 and h['independent_exposure_proved']==0 and h['order_counter']<=128
 rs=[record(raw[64+i*416:64+(i+1)*416])for i in range(h['reserved'])]
 pending=[i for i,r in enumerate(rs)if r['committed']!=i+1]
 for i,r in enumerate(rs):
  if r['committed']:assert r['committed']==i+1,'commit';assert r['kind']in(1,2)and r['job']in(5,8),'route';assert r['generation']==(i+1 if r['kind']==1 else 0),'generation'
 if strict:assert not pending and h['phase']==2 and h['reserved']==64 and not h['dropped']and h['restore_activation']==h['restore_complete']==1 and h['ever_published']==3 and h['install_result']==3 and h['order_counter']==128,'not fully sealed/committed/restored'
 if strict:assert sorted(v for r in rs for v in (r['entry_order'],r['return_order']))==list(range(1,129)),'observer order stamps'
 return dict(header=h,records=rs,pending=pending,sha256=hashlib.sha256(raw).hexdigest(),independent_exposure=False,fps_computable=False)
