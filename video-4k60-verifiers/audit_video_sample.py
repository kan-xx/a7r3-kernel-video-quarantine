"""Read-only video audit. Metadata/PTS passing never certifies sensor cadence.
Use a moving time target plus synchronized in-camera evidence for final acceptance.
"""
import argparse, hashlib, json, math, shutil, statistics, subprocess
from fractions import Fraction
from pathlib import Path

def audit(path, fps='60000/1001', width=3840, height=2160, seconds=6):
    path=Path(path).resolve(strict=True)
    assert path.is_file() and 0<seconds<=30
    target=float(Fraction(fps));assert 0<target<=240
    probe=shutil.which('ffprobe');ffmpeg=shutil.which('ffmpeg')
    if not probe or not ffmpeg:raise RuntimeError('ffprobe and ffmpeg are required')
    def run(args):
        return subprocess.run(args,capture_output=True,text=True,check=True,timeout=120).stdout
    before=path.stat()
    digest=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
    meta=json.loads(run([probe,'-v','error','-show_streams','-show_format','-of','json',str(path)]))
    videos=[s for s in meta['streams'] if s['codec_type']=='video'];assert len(videos)==1
    video=videos[0]
    frames=json.loads(run([probe,'-v','error','-select_streams','v:0','-read_intervals',f'%+{seconds}',
        '-show_entries','frame=best_effort_timestamp_time,pkt_duration_time','-of','json',str(path)]))['frames']
    pts=[float(x['best_effort_timestamp_time']) for x in frames if 'best_effort_timestamp_time' in x]
    # Restrict frame statistics to the same beginning-of-file time window.
    if pts:pts=[x for x in pts if x<pts[0]+seconds]
    delta=[b-a for a,b in zip(pts,pts[1:])]
    monotonic=bool(delta) and all(x>0 for x in delta)
    median=statistics.median(delta) if delta else None
    tick=float(Fraction(video['time_base']))
    # Matroska can quantize a 16.683 ms period to alternating 16/17 ms.
    tolerance=max(0.000005,tick+0.000001,0.002/target)
    cadence_ok=bool(median and abs(median-1/target)<=tolerance)
    irregular=sum(abs(x-1/target)>tolerance for x in delta)
    span=pts[-1]-pts[0] if len(pts)>1 else 0
    span_error=abs(span-len(delta)/target) if span else None
    hash_text=run([ffmpeg,'-hide_banner','-v','error','-xerror','-i',str(path),'-map','0:v:0',
        '-t',str(seconds),'-an','-fps_mode','passthrough','-f','framemd5','-'])
    hashes=[line.split(',')[-1].strip() for line in hash_text.splitlines() if line and not line.startswith('#')]
    repeats=sum(a==b for a,b in zip(hashes,hashes[1:]))
    def rate(s):
        try:return float(Fraction(s))
        except (ValueError,ZeroDivisionError):return None
    avg=rate(video.get('avg_frame_rate','0/0'))
    metadata_ok=avg is not None and abs(avg-target)<=target*0.001
    dimension_ok=video['width']==width and video['height']==height
    checks=dict(dimensions=dimension_ok,declared_average_rate=metadata_ok,monotonic_pts=monotonic,
        median_pts_period=cadence_ok,no_pts_gaps_or_rate_changes=bool(delta) and irregular==0,
        pts_span_matches_frame_count=span_error is not None and span_error<=max(tick*2,0.001/target),
        timestamp_resolution_sufficient=0<tick<1/target/4,
        decoding=True,decoded_frames_available=len(hashes)>1)
    after=path.stat();assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Input changed during audit'
    return dict(source=str(path),sha256=digest.hexdigest(),bytes=before.st_size,
        expected=dict(width=width,height=height,fps=fps),analyzed_first_seconds=seconds,
        video={k:video.get(k) for k in ['codec_name','profile','level','width','height','r_frame_rate','avg_frame_rate','time_base','duration','nb_frames','bit_rate']},
        pts_frames=len(pts),median_pts_period_seconds=median,observed_pts_fps=len(delta)/span if span>0 else None,
        timestamp_tick_seconds=tick,
        decoded_frames=len(hashes),adjacent_exact_repeats=repeats,exact_repeat_fraction=repeats/max(1,len(hashes)-1),
        checks=checks,file_timing_and_dimensions_pass=all(checks.values()),
        temporal_content_status='needs_review_exact_duplicates' if repeats else 'no_exact_duplicates_detected_independent_sensor_frames_unproven',
        full_camera_acceptance=False,
        limitation='Exact hashes do not detect all recompressed/interpolated duplicate frames. Static scenes may repeat legitimately. Sensor timing, moving target, encoder selection and recovery evidence are required independently.',
        ffprobe=meta,decoded_frame_hashes=hashes)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('video',type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--fps',default='60000/1001');p.add_argument('--width',type=int,default=3840);p.add_argument('--height',type=int,default=2160)
    p.add_argument('--seconds',type=float,default=6);a=p.parse_args()
    result=audit(a.video,a.fps,a.width,a.height,a.seconds)
    with a.output.open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:result[k] for k in ['file_timing_and_dimensions_pass','video','pts_frames','decoded_frames','adjacent_exact_repeats','full_camera_acceptance']},ensure_ascii=False))
