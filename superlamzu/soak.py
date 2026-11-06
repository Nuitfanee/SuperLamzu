"""Explicit read-only SLZ1 soak logging; not a report-rate measurement tool.

Keep dev node/query-gap grouping and rate comparisons. A disappearing USB
node or reset counters are observations, not proof of a firmware crash.
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import sys
import time

from . import cfg, protocol as P, target as T
from .runtime_link import RuntimeLink

SCHEMA='superlamzu-soak-1'
MONOTONIC=('ticks','slot_ends','samples','reads_started','tx_attempts')


def algorithms():
    return cfg._reference('ko1_soak')


def select_device(nodes,via,serial):
    pid=T.APP_PID if via=='wired' else 0x002E
    matching=[n for n in nodes if n.get('vendor_id')==T.VID and n.get('product_id')==pid
              and n.get('serial_number')==serial]
    if via=='receiver' and any(n.get('vendor_id')==T.VID and n.get('product_id')==T.APP_PID for n in nodes):
        raise ValueError('无线记录前请拔下Thorn本体数据线，保持接收器连接；有线报告不计入无线验收。')
    configs=[n for n in matching if n.get('interface_number')==2 and n.get('usage_page')==0xFFFF and n.get('usage')==0]
    mice=[n for n in matching if n.get('usage_page')==1 and n.get('usage')==2 and n.get('interface_number')==0]
    if len(configs)!=1 or len(mice)!=1:
        raise ValueError('需要指定序列号的唯一配置接口和鼠标报告接口；请检查连接。')
    return configs[0],mice[0]


def open_config(node):
    return cfg.hid.open_node(cfg.hid.Node(node['path'].decode('utf-8'),node['path'],
                                        node['vendor_id'],node['product_id'],
                                        iface=node['interface_number'],
                                        usage_page=node['usage_page'],usage=node['usage']))


def device_state(node,via):
    handle=open_config(node)
    try:
        link=RuntimeLink(handle)
        m=cfg.Mouse(link,0 if via=='wired' else 2)
        fw=m.fw();caps=m.capabilities()
        if fw!='0.0.1.16' or m.sensor_model()!=4:
            raise ValueError('Thorn V2固件或传感器身份不匹配')
        xy=m.current_dpi()[1]
        if xy[0]!=xy[1]:raise ValueError('当前记录要求X/Y CPI相同；请先选择等轴CPI。')
        state=dict(serial=node['serial_number'],via=via,mouse_fw=fw,features=caps,
                   polling=m.polling(),dpi_now=xy[0],profile=m.active_profile(),
                   receiver_fw=[cfg.Mouse(link,i).fw() for i in (0,1)] if via=='receiver' else None,
                   settings={})
        for bit,key,get in ((P.F_FPS,'fps',m.fps_status),(P.F_LOCK,'lock',m.lock_status),
                            (P.F_FPS_CUSTOM,'custom',m.fps_custom_status),
                            (P.F_SMOOTHING,'smoothing',m.smoothing_status),
                            (P.F_IDLE_TRACKING,'tracking',m.tracking_status),
                            (P.F_MOTION_PATH,'motion_path',m.motion_path)):
            if caps['flags']&bit:state['settings'][key]=get()
        return state
    finally:
        handle.close()


def reset_evidence(previous,current):
    if not previous or not current:return None
    a,b=previous.get('stats'),current.get('stats')
    if not a or not b or not a.get('counting_enabled') or not b.get('counting_enabled'):return None
    drops=[key for key in MONOTONIC if 1000<a['counters'][key]<0xF0000000
           and b['counters'][key]<a['counters'][key]//2]
    return dict(kind='counter_reset_candidate',counters=drops,
                meaning='multiple counters decreased; reboot or explicit counter clear') if len(drops)>=2 else None


def poll_once(node,via,flags):
    handle=open_config(node)
    try:
        m=cfg.Mouse(RuntimeLink(handle),0 if via=='wired' else 2)
        charging,battery=m.battery()
        return dict(battery_pct=battery,charging=bool(charging),profile=m.active_profile(),
                    stats=m.stats() if flags&P.F_STATS else None)
    finally:handle.close()


class Tracker:
    def __init__(self):
        alg=algorithms()
        self.nodes=alg.NodeTracker(True,0)
        self.link=alg.LinkTracker()
        self.previous=None

    @staticmethod
    def adapt(event):
        if event is None:return None
        event=dict(event)
        event['kind']={'receiver_reset':'usb_absence','link_drop':'query_gap'}[event['kind']]
        return event

    def sample(self,present,row,at):
        events=[self.adapt(self.nodes.tick(present,at)),self.adapt(self.link.tick(row is not None,at))]
        if row is not None:
            event=reset_evidence(self.previous,row)
            if event:events.append(dict(event,time=at))
            self.previous=row
        return [e for e in events if e is not None]

    def close(self,at):
        return [e for e in (self.adapt(self.nodes.close(at)),self.adapt(self.link.close(at))) if e is not None]


def run(path,state,*,seconds=300,interval=5,enumerate_nodes=None,poll=poll_once,
        clock=time.monotonic,sleep=time.sleep):
    if not math.isfinite(seconds) or seconds<0 or not math.isfinite(interval) or interval<1:
        raise ValueError('seconds须为非负有限值；interval至少1秒')
    if enumerate_nodes is None:
        import hid
        enumerate_nodes=lambda:hid.enumerate(T.VID)
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tracker=Tracker();start=clock();reason='duration';samples=0
    with path.open('x',encoding='utf-8') as file:
        def emit(record):
            file.write(json.dumps(record,ensure_ascii=False,allow_nan=False)+'\n');file.flush()
        emit(dict(type='header',schema=SCHEMA,started=time.strftime('%Y-%m-%dT%H:%M:%S'),
                  device=state,interval_s=interval,scope='periodic read-only configuration traffic; not report timing'))
        try:
            while seconds==0 or clock()-start<seconds:
                at=clock()-start;row=None;error=None;present=False
                try:
                    nodes=enumerate_nodes()
                    pid=T.APP_PID if state['via']=='wired' else 0x002E
                    present=any(n.get('vendor_id')==T.VID and n.get('product_id')==pid
                                and n.get('serial_number')==state['serial'] for n in nodes)
                    # A newly attached wire changes the physical path: end wireless soak.
                    if state['via']=='receiver' and any(n.get('vendor_id')==T.VID and n.get('product_id')==T.APP_PID for n in nodes):
                        emit(dict(type='event',kind='wired_attached',time=at));reason='transport_changed';break
                    if present:
                        config,_=select_device(nodes,state['via'],state['serial'])
                        row=poll(config,state['via'],state['features']['flags'])
                except (OSError,ValueError,cfg.CfgError,cfg.hid.HidOpenError) as exc:
                    error=str(exc)
                emit(dict(type='sample',t=at,present=present,row=row,error=error));samples+=1
                for event in tracker.sample(present,row,at):emit(dict(type='event',**event))
                delay=max(0,interval-(clock()-start-at))
                if seconds:delay=min(delay,max(0,seconds-(clock()-start)))
                if delay:sleep(delay)
        except KeyboardInterrupt:reason='interrupted'
        finally:
            elapsed=clock()-start
            for event in tracker.close(elapsed):emit(dict(type='event',**event))
            emit(dict(type='end',elapsed_s=elapsed,samples=samples,reason=reason))
    return path


def load(path):
    records=[json.loads(line) for line in Path(path).read_text('utf-8').splitlines() if line.strip()]
    if not records or records[0].get('schema')!=SCHEMA or records[0].get('type')!='header':
        raise ValueError('not a SuperLamzu soak log')
    return records


def summarize(paths):
    hours=0;counts=Counter();incomplete=[];devices=[]
    for path in paths:
        records=load(path);devices.append(records[0]['device'])
        ends=[r for r in records if r['type']=='end']
        if ends:elapsed=ends[-1]['elapsed_s']
        else:
            incomplete.append(str(path))
            elapsed=max((r['t'] for r in records if r['type']=='sample'),default=0)
        hours+=elapsed/3600
        counts.update(r['kind'] for r in records if r['type']=='event')
    alg=algorithms();rates={}
    for kind,count in counts.items():
        lo,hi=alg.poisson_ci(count)
        rates[kind]=dict(count=count,per_hour=count/hours if hours else None,
                         poisson_95ci_per_hour=[lo/hours,hi/hours] if hours else None)
    return dict(hours=hours,rates=rates,incomplete_logs=incomplete,devices=devices)


def compare(a_paths,b_paths):
    a,b=summarize(a_paths),summarize(b_paths)
    if not a['hours'] or not b['hours'] or a['incomplete_logs'] or b['incomplete_logs']:
        raise ValueError('比较要求两组均有完整、非零时长日志')
    if len({(d['via'],d['polling'],d['dpi_now']) for group in (a,b) for d in group['devices']})!=1:
        raise ValueError('比较要求连接方式、回报率及CPI一致')
    alg=algorithms();result={}
    for kind in sorted(a['rates'].keys()|b['rates'].keys()):
        ca=a['rates'].get(kind,{}).get('count',0);cb=b['rates'].get(kind,{}).get('count',0)
        result[kind]=dict(a_per_hour=ca/a['hours'],b_per_hour=cb/b['hours'],
                          p_value=alg.rate_compare_pvalue(ca,a['hours'],cb,b['hours']))
    return dict(a_hours=a['hours'],b_hours=b['hours'],events=result,
                meaning='observed event rates; query gaps include sleep/out-of-range and are not confirmed crashes')


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    p=sub.add_parser('run');p.add_argument('--via',choices=('wired','receiver'),required=True);p.add_argument('--serial',required=True)
    p.add_argument('--seconds',type=float,default=300);p.add_argument('--interval',type=float,default=5);p.add_argument('--out',type=Path,required=True)
    p=sub.add_parser('summary');p.add_argument('files',type=Path,nargs='+')
    p=sub.add_parser('compare');p.add_argument('a',type=Path,nargs='+');p.add_argument('--vs',type=Path,nargs='+',required=True)
    args=ap.parse_args(argv)
    try:
        if args.command=='summary':result=summarize(args.files)
        elif args.command=='compare':result=compare(args.a,args.vs)
        else:
            if args.out.exists():raise ValueError('输出日志已存在，请选择新路径')
            if not math.isfinite(args.seconds) or args.seconds<0 or not math.isfinite(args.interval) or args.interval<1:
                raise ValueError('seconds须为非负有限值；interval至少1秒')
            import hid
            config,_=select_device(hid.enumerate(T.VID),args.via,args.serial)
            state=device_state(config,args.via)
            print('周期只读记录已开始；不要同时测试无线报告或回报率。Ctrl+C保存并结束。',flush=True)
            path=run(args.out,state,seconds=args.seconds,interval=args.interval)
            result=summarize([path])
        print(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False));return 0
    except (OSError,ValueError,cfg.CfgError,cfg.hid.HidOpenError) as exc:
        print(f'error: {exc}',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
