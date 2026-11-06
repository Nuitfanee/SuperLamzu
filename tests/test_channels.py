import unittest
from superlamzu.patch import build
from superlamzu.channel_checks import verify
from superlamzu import cfg


@unittest.skip('CHAN instrumentation is compiled out of SUPER')
class ChannelsTests(unittest.TestCase):
    def test_native_thumb_matches_donor_chan_contract(self):
        self.assertGreaterEqual(verify(build()),147)

    def test_host_explicit_enable_reset_and_readback(self):
        from test_integration import FirmwareDevice
        device=FirmwareDevice(build())
        try:
            mouse=cfg.Mouse(cfg.Link(device,delay=0),0,1)
            self.assertFalse(mouse.channels()['enabled'])
            self.assertTrue(mouse.channels('on')['enabled'])
            self.assertEqual(mouse.channels('reset')['sent'],[0]*5)
            self.assertFalse(mouse.channels('off')['enabled'])
            for action in (True,1,'save'):
                with self.assertRaises(cfg.CfgError):mouse.channels(action)
        finally:device.close()


if __name__=='__main__':unittest.main()
