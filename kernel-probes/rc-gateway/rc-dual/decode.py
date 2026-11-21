"""Strict host decoder. Raw identity candidates only, never sensor completion/fps."""
from pathlib import Path
import struct,json
FIELDS=[('committed',1),('kind',1),('flags',1),('error',1),('args',8),('sp',1),('lr',1),('callers',4),('ec',1),('sequence',1),('job',1),('epoch',2),('driver',2),('state',2),('controller',1),('cflags',1),('input_status',1),('output_status',1),('status_valid',1),('status_value',1),('ec_mode',1),('controller_index',1),('controller_index_after',1),('tag_before',3),('tag_after',3),('unit_before',10),('unit_after',10),('input_pair',2),('output_list',9),('params',50),('input_desc',14),('output_desc',14),('tail',20)]
OFF={};n=0
for k,count in FIELDS:OFF[k]=n*4;n+=count
EVENT_BYTES=n*4;STATE_BYTES=64+64*EVENT_BYTES
HEAD=['magic','version','capacity','event_bytes','phase','reserved','dropped','restore_build','restore_complete','no_unload','build_gateway','complete_gateway','ever_published','install_result','upstream_complete_proved','timestamp_qualified']
def record(b):
 assert len(b)==EVENT_BYTES
 d={}
 for k,c in FIELDS:
  vals=list(struct.unpack_from('<'+str(c)+'I',b,OFF[k]));d[k]=vals[0]if c==1 else vals
 return d
def decode(b):
 assert len(b)==STATE_BYTES
 h=dict(zip(HEAD,struct.unpack_from('<16I',b)));assert(h['magic'],h['version'],h['capacity'],h['event_bytes'])==(0x52434432,2,64,EVENT_BYTES)
 assert h['reserved']<=64 and h['phase']in(0,1,2,3)and h['upstream_complete_proved']==h['timestamp_qualified']==0
 rs=[];pending=[]
 for i in range(h['reserved']):
  r=record(b[64+i*EVENT_BYTES:64+(i+1)*EVENT_BYTES])
  if r['committed']==0:pending.append(i);continue
  assert r['committed']==i+1
  assert r['kind']in(1,2);rs.append(r)
 return {'header':h,'records':rs,'pending_indices':pending,'sealed_is_drain':False,'event_order_is_hardware_time':False,'upstream_complete':False,'frame_countable':False,'fps_computable':False}
if __name__=='__main__':
 import sys
 p=Path(sys.argv[1]);print(json.dumps(decode(p.read_bytes()),indent=2))
