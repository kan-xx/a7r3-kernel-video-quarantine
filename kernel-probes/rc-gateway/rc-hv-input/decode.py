"""Strict host decoder. Raw identity candidates only, never sensor completion/fps."""
from pathlib import Path
import struct,json
FIELDS=[('committed',1),('native_r4',1),('native_lr',1),('jiffies_before',1),('jiffies_after',1),('kind',1),('flags',1),('error',1),('args',8),('sp',1),('lr',1),('callers',4),('ec',1),('sequence',1),('job',1),('epoch',2),('driver',2),('state',2),('controller',1),('cflags',1),('input_status',1),('output_status',1),('status_valid',1),('status_value',1),('ec_mode',1),('controller_index',1),('controller_index_after',1),('tag_before',3),('tag_after',3),('unit_before',10),('unit_after',10),('input_pair',2),('output_list',9),('params',50),('input_desc',14),('output_desc',14),('tail',20)]
FIELDS += [('ancestor_lr',1),('upstream_before',11),('upstream_after',11),('io_before',4),('io_after',4)]
ANCESTORS={0x63936fcb,0x6393700f,0x63937093,0x639370e9,0x639371bf,
 0x63938ad3,0x63938b15,0x63938b79,0x63938be9,0x63938c5b,
 0x6393a6f3,0x6393a733,0x6393a7ab,0x6393a7f9,0x6393a8b1}
OFF={};n=0
for k,count in FIELDS:OFF[k]=n*4;n+=count
EVENT_BYTES=n*4;STATE_BYTES=64+64*EVENT_BYTES
HEAD=['magic','version','capacity','event_bytes','phase','reserved','dropped','restore_build','restore_complete','no_unload','build_gateway','complete_gateway','ever_published','install_result','upstream_complete_proved','restore_h_complete']
def record(b):
 assert len(b)==EVENT_BYTES
 d={}
 for k,c in FIELDS:
  vals=list(struct.unpack_from('<'+str(c)+'I',b,OFF[k]));d[k]=vals[0]if c==1 else vals
 return d
def decode(b):
 assert len(b)==STATE_BYTES
 h=dict(zip(HEAD,struct.unpack_from('<16I',b)));assert(h['magic'],h['version'],h['capacity'],h['event_bytes'])==(0x52434432,5,64,EVENT_BYTES)
 assert h['reserved']<=64 and h['phase']in(0,1,2,3)and h['upstream_complete_proved']==0 and h['restore_h_complete']in(0,1,2,3)
 rs=[];pending=[]
 for i in range(h['reserved']):
  r=record(b[64+i*EVENT_BYTES:64+(i+1)*EVENT_BYTES])
  if r['committed']==0:pending.append(i);continue
  assert r['committed']==i+1
  assert r['kind']in(1,2)and r['native_lr']==r['lr']
  if r['flags']&512:assert r['kind']==1 and r['ancestor_lr']in ANCESTORS and r['callers'][3]==0x63d2d5cb
  if r['flags']&1024:assert r['flags']&512 and r['flags']&4
  if r['flags']&2048:assert r['flags']&1024 and r['upstream_before']==r['upstream_after']
  rs.append(r)
 return {'header':h,'records':rs,'pending_indices':pending,'sealed_is_drain':False,'event_order_is_hardware_time':False,'raw_jiffies_captured':True,'nominal_tick_hz':100,'fine_tick_cadence_and_irq_skew_qualified':False,'upstream_complete':False,'frame_countable':False,'fps_computable':False}
if __name__=='__main__':
 import sys
 p=Path(sys.argv[1]);print(json.dumps(decode(p.read_bytes()),indent=2))
