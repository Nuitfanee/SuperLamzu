"""Stock performance evidence must execute the original, unpatched image."""
import unittest

from superlamzu.patch import build
from tools.audit_hotpaths import hotpaths


class StockAuditTests(unittest.TestCase):
    def test_stock_is_independent_of_super_builder_edits(self):
        from superlamzu.common import Builder
        super_=build('SUPER')
        original=hotpaths(super_,stock=True)
        self.assertEqual(original,hotpaths(Builder(),stock=True))
        self.assertEqual(original['recipe.1']['instructions'],415)
        self.assertEqual(original['chan.ack.stats0.chan0.heap0']['instructions'],5)
        self.assertEqual(original['abs.total.enabled0']['instructions'],10)
        self.assertEqual(original['optical.stock_idle']['instructions'],61)


if __name__=='__main__':unittest.main()
