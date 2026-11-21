"""Pure host decoder for an exact .data.rcgate 1584-byte observation.
No device access; no snapshot is claimed to be atomic or a callback barrier.
"""
import struct,json,sys
from pathlib import Path
def decode(raw):
 if len(raw)!=1584:raise ValueError('Expected exact state extent, 1584 bytes')
 w=list(struct.unpack('<396I',raw));h=w[:12]
 if h[:4]!=[0x52434731,1,32,48]:raise ValueError('State identity/record ABI mismatch')
 if h[4]not in(0,1,2,3)or h[5]>32 or h[6]>1 or h[7]>3:raise ValueError('Invalid state counters')
 if h[8:10]!=[0x64696ed4,0x63d5f5e9]or h[11]!=1:raise ValueError('Target/residency mismatch')
 if h[10]and(h[10]&3 or not 0x5f000000<=h[10]<0x60000000):raise ValueError('Gateway outside qualified kernel-module VA range')
 events=[];pending=[]
 names=['committed','backend','interface','payload','status_pointer','jobid','entry_sp','entry_lr','caller_lr','native_error','status_valid','status_value']
 for i in range(32):
  r=w[12+i*12:24+i*12]
  if not r[0]:
   if i<h[5]:pending.append(i)
   continue
  if r[0]!=i+1 or i>=h[5]or r[10]not in(0,1):raise ValueError('Invalid committed record')
  event=dict(zip(names,r));event['index']=i;events.append(event)
 all_committed=not pending and len(events)==h[5]
 return dict(phase={0:'unpublished',1:'armed',2:'sealed',3:'refused'}[h[4]],reserved=h[5],contention_or_loss=bool(h[6]),restore_result={0:'not_attempted',1:'restored_or_already_original',2:'foreign_slot_preserved',3:'bounded_cas_attempts_exhausted'}[h[7]],gateway=hex(h[10]),records=events,pending_indices=pending,all_reserved_committed=all_committed,closed_record_set=h[4]==2 and all_committed,resident_until_kernel_discarded=True,atomic_snapshot=False,callback_drain_proven=False,hardware_frame_count_proven=False,fps_computable=False)
if __name__=='__main__':
 p=Path(sys.argv[1]);print(json.dumps(decode(p.read_bytes()),indent=2))
