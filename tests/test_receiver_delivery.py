import unittest

from superlamzu.receiver import build
from superlamzu.receiver_delivery_checks import verify


class ReceiverDeliveryTests(unittest.TestCase):
    def test_radio_backlog_reaches_native_usb_endpoint(self):
        result=verify(build())
        self.assertEqual(result['scenarios'],7)
        self.assertEqual(result['native_types'],4)
        self.assertEqual(result['result'],'PASS')
