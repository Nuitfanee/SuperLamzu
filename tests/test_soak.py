import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from superlamzu import soak


def nodes(pid=0x2E,serial='fixture'):
    return [dict(vendor_id=0x37B0,product_id=pid,serial_number=serial,
                 interface_number=i,usage_page=p,usage=u,path=f'fixture-{i}'.encode())
            for i,p,u in [(0,1,2),(2,0xFFFF,0)]]


def row(value=5000,enabled=True):
    return dict(battery_pct=85,charging=False,profile=2,
                stats=dict(counting_enabled=enabled,counters=dict.fromkeys(soak.MONOTONIC,value)))


class SoakTests(unittest.TestCase):
    def setUp(self):
        self.state=dict(serial='fixture',via='receiver',polling=1000,dpi_now=3200,features={'flags':8})

    def test_receiver_requires_unplugging_wired_thorn(self):
        with self.assertRaisesRegex(ValueError,'拔下Thorn'):
            soak.select_device(nodes(0x40,'mouse')+nodes(),'receiver','fixture')
        config,mouse=soak.select_device(nodes()+nodes(0x44,'maya'),'receiver','fixture')
        self.assertEqual((config['interface_number'],mouse['interface_number']),(2,0))
        self.assertEqual(mouse['serial_number'],'fixture')

    def test_selection_is_exact_serial_and_collection(self):
        both=nodes(0x40,'wanted')+nodes(0x40,'other')+nodes()
        self.assertEqual(soak.select_device(both,'wired','wanted')[0]['serial_number'],'wanted')
        with self.assertRaises(ValueError):soak.select_device(both,'wired','missing')
        with self.assertRaises(ValueError):soak.select_device(nodes(0x40,'wanted')*2,'wired','wanted')

    def test_device_handle_closes_after_readonly_snapshot(self):
        class Mouse:
            def __init__(self,link,target):pass
            def fw(self):return '0.0.1.16'
            def capabilities(self):return {'flags':0}
            def sensor_model(self):return 4
            def current_dpi(self):return 1,(800,800)
            def polling(self):return 1000
            def active_profile(self):return 1
            def __getattr__(self,name):return lambda: None
        handle=Mock()
        def open_node(node):
            self.assertIsInstance(node,soak.cfg.hid.Node)
            self.assertIsInstance(node.raw,bytes)
            self.assertEqual((node.vid,node.pid,node.iface),(0x37B0,0x2E,2))
            return handle
        with patch.object(soak.cfg.hid,'open_node',side_effect=open_node),patch.object(soak.cfg,'Mouse',Mouse):
            self.assertEqual(soak.device_state(nodes()[1],'receiver')['receiver_fw'],['0.0.1.16']*2)
        handle.close.assert_called_once()

    def test_reset_evidence_excludes_wrap_disabled_and_single_counter(self):
        self.assertEqual(soak.reset_evidence(row(),row(2))['kind'],'counter_reset_candidate')
        self.assertIsNone(soak.reset_evidence(row(0xFFFFFF00),row(2)))
        self.assertIsNone(soak.reset_evidence(row(enabled=False),row(2)))
        current=row();current['stats']['counters']['ticks']=0
        self.assertIsNone(soak.reset_evidence(row(),current))
        self.assertIsNone(soak.reset_evidence(None,row()))

    def test_usb_absence_and_query_gap_are_observations_not_crashes(self):
        t=soak.Tracker()
        self.assertEqual(t.sample(True,row(),0),[])
        self.assertEqual(t.sample(False,None,5),[])
        events=t.sample(True,row(),10)
        self.assertEqual([e['kind'] for e in events],['usb_absence','query_gap'])
        self.assertTrue(all(e['duration_s']==5 for e in events))
        self.assertEqual(t.close(11),[])
        t.sample(True,None,12)
        self.assertTrue(t.close(17)[0]['open'])

    def test_run_records_failure_recovery_and_never_enables_stats(self):
        now=[0.0];calls=[]
        def enum():return [] if now[0]==1 else nodes()
        def poll(node,via,flags):
            calls.append((node['serial_number'],via,flags))
            return row(enabled=False)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'real-log.jsonl'
            soak.run(path,self.state,seconds=3,interval=1,enumerate_nodes=enum,poll=poll,
                     clock=lambda:now[0],sleep=lambda s:now.__setitem__(0,now[0]+s))
            records=soak.load(path)
            self.assertEqual(calls,[('fixture','receiver',8)]*2)
            self.assertEqual(records[-1]['samples'],3)
            summary=soak.summarize([path])
            self.assertAlmostEqual(summary['hours'],3/3600)
            self.assertEqual(summary['rates']['usb_absence']['count'],1)
            self.assertEqual(summary['rates']['query_gap']['count'],1)
            self.assertEqual(summary['incomplete_logs'],[])
            with self.assertRaises(FileExistsError):
                soak.run(path,self.state,seconds=1,enumerate_nodes=lambda:None)

    def test_attaching_wire_ends_wireless_log_without_polling(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'switch.jsonl'
            soak.run(p,self.state,seconds=5,enumerate_nodes=lambda:nodes()+nodes(0x40,'mouse'),
                     poll=lambda *a: self.fail('must not query newly wired mouse'))
            records=soak.load(p)
            self.assertEqual(records[-1]['reason'],'transport_changed')
            self.assertEqual(records[-2]['kind'],'wired_attached')

    def test_failed_query_closes_gap_in_log(self):
        now=[0.0]
        def poll(*args):raise OSError('disconnected')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'failure.jsonl'
            soak.run(p,self.state,seconds=2,interval=1,enumerate_nodes=nodes,poll=poll,
                     clock=lambda:now[0],sleep=lambda s:now.__setitem__(0,now[0]+s))
            records=soak.load(p)
            event=next(r for r in records if r.get('kind')=='query_gap')
            self.assertTrue(event['open'])
            self.assertEqual(event['duration_s'],2)
            self.assertIn('disconnected',records[1]['error'])

    def test_incomplete_log_remains_readable_but_cannot_be_compared(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'interrupted.jsonl'
            records=[dict(type='header',schema=soak.SCHEMA,device=self.state),dict(type='sample',t=10,row=row())]
            p.write_text('\n'.join(json.dumps(r) for r in records))
            self.assertEqual(soak.summarize([p])['incomplete_logs'],[str(p)])
            with self.assertRaises(ValueError):soak.compare([p],[p])

    def test_complete_comparison_uses_pinned_dev_rates(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths=[]
            for name,count in [('a',1),('b',3)]:
                p=Path(tmp)/(name+'.jsonl');paths.append(p)
                records=[dict(type='header',schema=soak.SCHEMA,device=self.state)]
                records += [dict(type='event',kind='query_gap',time=i) for i in range(count)]
                records += [dict(type='end',elapsed_s=3600)]
                p.write_text('\n'.join(json.dumps(r) for r in records))
            report=soak.compare([paths[0]],[paths[1]])['events']['query_gap']
            self.assertEqual((report['a_per_hour'],report['b_per_hour']),(1,3))
            self.assertGreater(report['p_value'],0)

    def test_cli_rejects_invalid_duration_and_existing_files_without_usb(self):
        import hid
        with tempfile.TemporaryDirectory() as tmp,patch.object(hid,'enumerate',side_effect=AssertionError('no USB')):
            p=Path(tmp)/'existing';p.write_text('preserved')
            common=['run','--via','receiver','--serial','fixture','--out',str(p)]
            self.assertEqual(soak.main(common),1)
            self.assertEqual(soak.main(common[:-1]+[str(Path(tmp)/'new'),'--seconds','nan']),1)
            self.assertEqual(p.read_text(),'preserved')
