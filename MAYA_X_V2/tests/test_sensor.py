"""Real Thumb comparison against stock across nine recipes and mode selection."""
import copy
import unittest

from MAYA_X_V2 import target as T
from MAYA_X_V2.sensor import LAYOUT, build_foundation, run
from superlamzu.emulation import Arm
from superlamzu.hexfile import Image
from superlamzu.patch import check_external_recipe_entries


def changed_image(builder):
    image = copy.copy(builder.image)
    image.data = builder.output_image()
    image.mem = dict(builder.image.mem)
    image.mem.update(builder.changes)
    return image


class SensorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_foundation()
        cls.changed = changed_image(cls.builder)

    def test_nine_recipes_share_existing_interpreter(self):
        self.assertEqual(self.builder.recipes,
                         dict(register_count=136, value_families=2,
                              entries=9, early_cached_read=[6]))
        self.assertGreater(sum(z-a for a,z in self.builder.pools), 8000)
        for allocation in self.builder.allocations:
            start = int(allocation['address'],16)
            end = start + allocation['bytes']
            self.assertTrue(any(a+10<=start<end<=a+n
                                for a,n in zip(T.FLASH_RECIPES,T.RECIPE_SIZES)))

    def test_all_ordered_spi_events_stock_except_downshift(self):
        entries = [(entry,()) for entry in T.FLASH_RECIPES]
        entries += [(T.SENSOR_STARTUP,())]
        entries += [(T.RECIPE_DISPATCH,(mode,variant))
                    for mode in range(1,9) for variant in range(1,4)]
        for entry,args in entries:
            for value in (0,0xA5,0xFF):
                with self.subTest(entry=hex(entry),args=args,read=value):
                    before = run(self.builder.image,entry,rd_value=value,args=args)
                    after = run(self.changed,entry,rd_value=value,args=args)
                    def events(log, downshift=False):
                        return [(e['op'],e['page'],e['reg'],
                                 e['value']|64 if downshift and e['op']=='write'
                                 and (e['page'],e['reg'])==(5,0x44) else e['value'])
                                for e in log]
                    self.assertEqual(events(before,True),events(after))

    def test_recipe_abi_preserves_registers_stack_failure_and_return(self):
        def execute(image,entry,read_ok,write_result):
            with Arm(image,layout=LAYOUT) as cpu:
                events=[]
                page=[0]
                def clobber(cpu):
                    for reg in ('r1','r2','r3','r12'):
                        cpu.setreg(reg,0xDEADBEEF)
                def write(cpu):
                    reg,value=cpu.reg('r0')&255,cpu.reg('r1')&255
                    if reg==127:page[0]=value
                    events.append((page[0],reg,value,cpu.reg('sp')&7))
                    clobber(cpu)
                    return write_result
                def read(cpu):
                    if read_ok:cpu.uc.mem_write(cpu.reg('r1'),b'\xd7')
                    clobber(cpu)
                    return int(read_ok)
                cpu.stub(T.WR,effect=write)
                cpu.stub(T.RD,effect=read)
                for reg in range(4,12):cpu.setreg(f'r{reg}',0x1000+reg)
                result=cpu.run(entry,count=100000)
                return events,result,[cpu.reg(f'r{reg}') for reg in range(4,12)],cpu.reg('sp')
        for entry in T.FLASH_RECIPES:
            for read_ok in (False,True):
                for result in (0,1,0x76543210):
                    with self.subTest(entry=hex(entry),read_ok=read_ok,result=result):
                        before=execute(self.builder.image,entry,read_ok,result)
                        after=execute(self.changed,entry,read_ok,result)
                        expected=[(p,r,v|64 if (p,r)==(5,0x44) else v,s)
                                  for p,r,v,s in before[0]]
                        self.assertEqual(after[0],expected)
                        self.assertEqual(after[1:],before[1:])
                        self.assertEqual(after[2],[0x1000+i for i in range(4,12)])
                        self.assertEqual(after[3],T.SP)

    def test_pointer_collision_exceptions_require_original_instructions(self):
        image=Image(T.STOCK)
        address=next(iter(T.RECIPE_NONPOINTERS))
        data=bytearray(image.data)
        data[address-image.base]^=1
        image.data=bytes(data)
        with self.assertRaisesRegex(ValueError,'nonpointer instruction changed'):
            check_external_recipe_entries(image,target=T)

    def test_real_interior_pointer_is_still_rejected(self):
        image=Image(T.STOCK)
        address=0x3CA3C
        data=bytearray(image.data)
        data[address-image.base:address-image.base+4]=(T.FLASH_RECIPES[0]+2).to_bytes(4,'little')
        image.data=bytes(data)
        with self.assertRaisesRegex(ValueError,'external interior recipe reference'):
            check_external_recipe_entries(image,target=T)


if __name__ == '__main__':
    unittest.main()
