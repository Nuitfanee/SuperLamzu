"""Build SUPER firmware without opening HID."""
import argparse
import csv
import json
import struct
from pathlib import Path

from . import protocol as P, target as T
from .common import Builder, assemble


def recipe_events(image, entry, *, target=T, runner=None):
    if runner is None:
        from .emulation import sensor_run as runner
    logs = [runner(image,entry,target.WR,target.RD,x) for x in (0,0xA5,0xFF)]
    tables=[]
    for log in logs:
        tab=[]
        for i,e in enumerate(log):
            if e["op"]=="read":
                if e["reg"]!=0x40 or e["page"]!=0:
                    raise ValueError("unrecognized recipe read")
                tab.append((0xC0,0))
                continue
            values=[x[i]["value"] for x in logs]
            if len(set(values))>1:
                if e["page"]!=0 or e["reg"]!=0x40:
                    raise ValueError("unrecognized recipe RMW")
                if any(v != (rv&0xFC)|(values[0]&3) for v,rv in zip(values,(0,0xA5,0xFF))):
                    raise ValueError("unrecognized RMW mask")
                tab.append((0xFE,e["value"] & 3))
            else:
                tab.append((e["reg"],e["value"]))
        tables.append(tab)
    if not tables[0]==tables[1]==tables[2]:
        raise ValueError("recipe has unmodeled read-dependent writes")
    return bytes(v for pair in tables[0] for v in pair)


def check_external_recipe_entries(image, *, target=T):
    """Conservative byte-level direct branch and pointer scan, including copied RAM source."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    ranges=list(zip(target.FLASH_RECIPES,[a+n for a,n in zip(target.FLASH_RECIPES,target.RECIPE_SIZES)]))
    def check(source,dest):
        for a,z in ranges:
            if a < dest < z and not a <= source < z:
                raise ValueError(f"external interior recipe reference {source:#x}->{dest:#x}")
    nonpointers = getattr(target, 'RECIPE_NONPOINTERS', {})
    for address, original in nonpointers.items():
        if image.get(address, len(original)) != original:
            raise ValueError(f'recipe nonpointer instruction changed at {address:#x}')
    for a in range(image.base,image.end-3):
        if a in nonpointers:
            continue
        check(a,image.u32(a)&~1)
    for a in range(image.base,image.end-1,2):
        h=int.from_bytes(image.get(a,2),"little")
        if h&0xF800 in (0xE000,0xF000) or h&0xF000==0xD000 or h&0xF500==0xB100:
            ins=next(cs.disasm(image.get(a,4),a),None)
            if ins and ins.mnemonic.startswith("b") and "#" in ins.op_str:
                try:dest=int(ins.op_str.split("#")[-1],0)&~1
                except ValueError:continue
                check(a,dest)


def recipe_layout(image, *, target=T, runner=None):
    """Share registers and two value families, preserving every ordered event.

    S6 reads 00:40 before its writes and uses that cached value at the end.
    Its normalized read slot is skipped by the interpreter, never re-read.
    """
    tables, early = [], []
    for entry in target.FLASH_RECIPES:
        table=bytearray(recipe_events(image,entry,target=target,runner=runner))
        page=0
        for i in range(0,len(table),2):
            reg,val=table[i:i+2]
            if reg==0x7F:page=val
            elif page==5 and reg==0x44:table[i+1]=val|0x40
        pairs=list(zip(table[::2],table[1::2]))
        first_read=pairs[0]==(0xC0,0)
        if first_read:
            pairs.pop(0)
            pairs.insert(next(i for i,p in enumerate(pairs) if p[0]==0xFE), (0xC0,0))
        tables.append(pairs)
        early.append(first_read)
    registers=bytes(r for r,v in tables[0])
    if len(registers)>=255 or any(len(t)!=len(registers) for t in tables):
        raise ValueError('recipe stream lengths no longer match')
    bases=[bytes(v for r,v in tables[i]) for i in (0,2)]
    variants=[]
    for table,first_read in zip(tables,early):
        values=bytes(v for r,v in table)
        family=min(range(2),key=lambda i:sum(a!=b for a,b in zip(bases[i],values)))
        overrides=bytes(x for i,((r,v),a) in enumerate(zip(table,bases[family]))
                        if v!=a or r!=registers[i] for x in (i,r,v))+b'\xff'
        variants.append((family,overrides,first_read))
    return registers,bases,variants


def compress_recipes(b, *, target=T, runner=None):
    check_external_recipe_entries(b.image,target=target)
    registers,bases,variants=recipe_layout(b.image,target=target,runner=runner)
    # Only verified recipe bodies become pools; every original entry stays.
    for entry,size in zip(target.FLASH_RECIPES,target.RECIPE_SIZES):
        stub_bytes = len(assemble(['ldr r0,=0', f'b.w #{entry:#x}', '.ltorg'], entry))
        b.add_pool(entry+stub_bytes,entry+size)
    regs=b.alloc('recipe_registers',registers)
    values=[b.alloc(f'recipe_values_{i}',data) for i,data in enumerate(bases)]
    descriptors=[]
    for i,(family,overrides,early) in enumerate(variants):
        delta=b.alloc(f'recipe_overrides_{i}',overrides)
        descriptors.append(b.alloc(f'recipe_descriptor_{i}',struct.pack('<IIB',values[family],delta,early)))
    interpreter=b.code("recipe_execute",[
        "push.w {r4,r5,r6,r7,r8,lr}","sub sp,#8","ldr r5,[r0]","ldr r6,[r0,#4]",
        "ldrb.w r8,[r0,#8]",f"movw r4,#{regs&65535}",f"movt r4,#{regs>>16}",
        "movs r7,#0","str r7,[sp]","cmp r8,#0","beq next",
        "movs r0,#0x40","mov r1,sp",f"bl #{target.RD:#x}",
        "next:","ldrb r0,[r4],#1","ldrb r1,[r5],#1","ldrb r2,[r6]","cmp r2,r7","bne selected",
        "ldrb r0,[r6,#1]","ldrb r1,[r6,#2]","adds r6,#3",
        # Normal register writes dominate. Fall through to the loop step;
        # only the two synthetic read/cached-RMW opcodes take the slow arm.
        "selected:","cmp r0,#0xc0","bhs special","write:",f"bl #{target.WR:#x}",
        "step:","adds r7,#1",f"cmp r7,#{len(registers)}","bne next","add sp,#8","pop.w {r4,r5,r6,r7,r8,pc}",
        "special:","cmp r0,#0xfe","beq cached","cmp r0,#0xc0","bne write",
        "read:","cmp r8,#0","bne step","movs r0,#0x40","mov r1,sp",f"bl #{target.RD:#x}","b step",
        "cached:","ldrb r0,[sp]","and r0,r0,#0xfc","orrs r1,r0","movs r0,#0x40",f"bl #{target.WR:#x}","b step"])
    for entry,descriptor in zip(target.FLASH_RECIPES,descriptors):
        code=assemble([f"ldr r0,={descriptor:#x}", f"b.w #{interpreter:#x}", '.ltorg'],entry)
        if len(code) != len(assemble(['ldr r0,=0', f'b.w #{entry:#x}', '.ltorg'], entry)):
            raise ValueError("recipe stub size")
        b.edit(entry,code,"equivalent recipe entry")
    return dict(register_count=len(registers),value_families=2,entries=len(descriptors),
                early_cached_read=[i+1 for i,v in enumerate(variants) if v[2]])


def install_extension(b, advanced, *, target=T):
    flags = P.F_DB | P.F_B | advanced["flags"]
    cap=b.alloc("capability_data",P.capabilities(flags,advanced["preset_count"]))
    # Main handler is called with native group1 ABI, via a four-byte veneer.
    # Non-SLZ1 commands execute the untouched original prologue and continuation.
    fallback=b.code("group1_original",["push.w {r4,r5,r6,r7,r8,lr}",f"b.w #{target.GROUP1+4:#x}"])
    getadv=advanced["get"]; setadv=advanced["set"]
    lines=[
        "push {r4,r5,r6,r7,lr}","sub sp,#4","str r0,[sp]",
        f"movw r4,#{target.PACKET&65535}",f"movt r4,#{target.PACKET>>16}",
        "ldrb r0,[r4,#5]",f"cmp r0,#{P.GET}","beq ext",f"cmp r0,#{P.SET}","beq ext",
        "ldr r0,[sp]","add sp,#4","pop {r4,r5,r6,r7,lr}",f"b.w #{fallback:#x}",
        "ext:","mov r7,r0","ldrb r0,[r4,#3]","cmp r0,#2","blo reject",
        "ldrb r5,[r4,#7]","ldrb r6,[r4,#6]","cbz r5,caps",
        "cmp r5,#1","beq db", "b advanced",
        "caps:",f"cmp r7,#{P.GET}","bne reject","cmp r0,#2","bne reject","cmp r6,#0","bne reject",
        f"movw r1,#{cap&65535}",f"movt r1,#{cap>>16}","add r2,r4,#6","movs r3,#12",
        "cp:","ldrb r0,[r1],#1","strb r0,[r2],#1","subs r3,#1","bne cp","movs r0,#12","b length",
        "db:","cmp r6,#1","blo reject","cmp r6,#3","bhi reject",
        f"cmp r7,#{P.GET}","beq dbgetcheck","cmp r0,#6","bne reject","b dbaddr",
        "dbgetcheck:","cmp r0,#2","bne reject",
        "dbaddr:","subs r0,r6,#1",f"movs r1,#{target.PROFILE_STRIDE}","muls r0,r1,r0",
        f"movw r1,#{target.SETTINGS&65535}",f"movt r1,#{target.SETTINGS>>16}","add r1,r0","adds r1,#7",
        f"cmp r7,#{P.GET}","beq dbreply",
        # Byte operations avoid unaligned words and preserve each field's native representation.
        "ldrb r0,[r4,#8]","strb r0,[r1]","ldrb r0,[r4,#9]","strb r0,[r1,#1]",
        "ldrb r0,[r4,#10]","strb r0,[r1,#2]","ldrb r0,[r4,#11]","strb r0,[r1,#3]",
        "str r1,[sp]",
        f"movw r0,#{target.ACTIVE_PROFILE&65535}",f"movt r0,#{target.ACTIVE_PROFILE>>16}","ldrb r0,[r0]",
        "adds r0,#1","cmp r0,r6","bne dbsave",f"bl #{target.RELOAD_DB:#x}",
        "dbsave:","movs r0,#8","movs r1,#0",f"bl #{target.SCHEDULE_SAVE:#x}","ldr r1,[sp]",
        "dbreply:","strb r6,[r4,#6]","ldrb r0,[r1]","strb r0,[r4,#7]",
        "ldrb r0,[r1,#1]","strb r0,[r4,#8]","ldrb r0,[r1,#2]","strb r0,[r4,#9]",
        "ldrb r0,[r1,#3]","strb r0,[r4,#10]","movs r0,#5","b length",
        "advanced:"]
    lines += [f"cmp r7,#{P.GET}","bne advset",f"bl #{getadv:#x}","b advdone",
              "advset:",f"bl #{setadv:#x}","advdone:","cbz r0,reject","b success"]
    lines += ["length:","strb r0,[r4,#3]","success:","movs r0,#0xa0","strb r0,[r4]","b done",
              "reject:","movs r0,#0xa2","strb r0,[r4]","done:","add sp,#4","pop {r4,r5,r6,r7,pc}"]
    handler=b.code("extension_dispatch",lines)
    if b.image.get(target.GROUP1,4)!=bytes.fromhex("2de9f041"):
        raise ValueError("unexpected group1 prologue")
    b.branch(target.GROUP1,handler,"SLZ1 extension veneer; preserve native commands")
    return dict(handler=handler,flags=flags,capability=cap)


def build(profile="FULL", source=T.STOCK):
    from .profiles import telemetry
    enabled = telemetry(profile)
    b=Builder(source)
    b.recipes=compress_recipes(b)
    # Compressed Flash recipes already carry B; update remaining RAM/startup sites only.
    rows=csv.DictReader(T.LANDMARKS.read_text(encoding="utf-8").splitlines())
    sites={int(r["runtime_callsite"],16):int(r["stock_value"],16) for r in rows
           if r["page"]=="0x05" and r["reg"]=="0x44"}
    if len(sites) != 14:
        raise ValueError("expected fourteen independently located downshift writes")
    for site,old in sites.items():
        if any(a<=T.flash_source(site)<a+n for a,n in zip(T.FLASH_RECIPES,T.RECIPE_SIZES)):continue
        a=T.flash_source(site)-4
        if b.image.get(a,4)!=bytes([old,0x21,0x44,0x20]):raise ValueError("B preimage")
        b.edit(a,bytes([old|0x40]),"B outside compressed Flash recipes")
    from .advanced import install
    b.profile=profile
    b.advanced=install(b,telemetry=enabled)
    b.extension=install_extension(b,b.advanced)
    return b


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("profile",choices=("SUPER",),nargs="?",default="SUPER")
    p.add_argument("source",type=Path,nargs="?",default=T.STOCK)
    p.add_argument("-o","--output",type=Path)
    p.add_argument("--skip-check",action="store_true",help="build only; output is not marked verified")
    p.add_argument("--target",choices=("mouse","receiver","all"),default="mouse",
                   help="firmware target; receiver emits CPUAPP and CPURAD, mouse remains the default")
    a=p.parse_args(argv)
    if a.target != 'mouse':
        if a.output or a.source != T.STOCK:
            p.error('--target receiver/all uses registered receiver sources and default output names')
        from . import receiver
        from .receiver_checks import verify as verify_receiver
        for core in ('cpuapp','cpurad'):
            rb=receiver.build(core)
            rd=T.ROOT/'build'/f'LAMZU_RECEIVER_{core.upper()}_{a.profile}_00.00.01.16.hex'
            rm=rb.manifest(a.profile)
            rm['telemetry']=False
            rm['compatible_mouse_profiles']=['FULL','SUPER']
            rm['verification']='not run' if a.skip_check else verify_receiver(rb)
            rb.write(rd)
            rd.with_suffix('.json').write_text(json.dumps(rm,indent=2)+'\n',encoding='utf-8')
            print(f'{a.profile} receiver {core}: {rd} ({len(rb.changes)} changed bytes); {rm["verification"]}')
        if a.target == 'receiver':
            return 0
    dest=a.output or T.ROOT/"build"/f"LAMZU_{a.profile}_00.00.01.16.hex"
    if dest.suffix.lower() != ".hex":
        p.error("--output must end in .hex; its .json sidecar is reserved for the manifest")
    if dest.resolve() in (a.source.resolve(), T.STOCK.resolve()):
        p.error("refusing to overwrite original firmware")
    b=build(a.profile,a.source)
    manifest=b.manifest(a.profile)
    manifest['scope']=dict(downshift='B',
                           native_debounce_profiles=True,
                           advanced_device_persistence=b.advanced['persistence'],
                           preserved=['five stock LOD presets','six-byte motion burst',
                                      'native high-CPI recipe','native debounce state machine'],
                           device_acceptance='not run')
    from .profiles import policy
    manifest['variant']=policy(a.profile)
    manifest['extension']=b.extension
    manifest['recipe_compression']=b.recipes
    manifest['advanced']=b.advanced
    manifest['optical']=b.optical
    manifest['capacity']=dict(allocated_bytes=sum(v['bytes'] for v in b.allocations),
        remaining_code_bytes=sum(z-a for a,z in b.pools),
        largest_contiguous_code_bytes=max((z-a for a,z in b.pools),default=0),
        remaining_pools=[dict(start=hex(a),end=hex(z),bytes=z-a) for a,z in b.pools if z>a])
    manifest["verification"]="not run"
    if not a.skip_check:
        from .verify import verify
        manifest["verification"]=verify(b,a.profile)
    b.write(dest)
    dest.with_suffix(".json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    print(f"{a.profile}: {dest} ({len(b.changes)} changed bytes); {manifest['verification']}")
    return 0


if __name__=="__main__":raise SystemExit(main())
