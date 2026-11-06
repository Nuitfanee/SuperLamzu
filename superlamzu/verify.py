"""Execute original and generated Thumb code; never access a device."""
import copy
import struct

from . import protocol as P, target as T


def patched_image(b):
    im=copy.copy(b.image)
    im.data=b.output_image()
    im.mem=dict(b.image.mem)
    im.mem.update(b.changes)
    return im


def arm(image):
    from .emulation import Arm
    a=Arm(image)
    a.uc.mem_write(T.SETTINGS,image.get(0x0E0883E0,704))
    return a


def request(a,cmd,payload,length=None, *, target=T):
    packet=bytearray(64)
    packet[0]=0xA0
    packet[3:6]=bytes([len(payload) if length is None else length,1,cmd])
    packet[6:6+len(payload)]=bytes(payload)
    a.uc.mem_write(target.PACKET,bytes(packet))
    a.run(target.GROUP1)
    reply=bytes(a.uc.mem_read(target.PACKET,64))
    return reply[0],reply[6:6+reply[3]]


def sensor_comparison(b,downshift):
    from .emulation import sensor_run as run
    image=patched_image(b)
    cases=0
    entries=[(e,(),False) for e in T.FLASH_RECIPES]
    entries += [(0x0E086F7A,(),False)]
    entries += [(0x23003C6C,(m,v),True) for m in range(1,9) for v in range(1,4)]
    for entry,args,mapped in entries:
        for rv in (0,0xA5,0xFF):
            stock=run(b.image,entry,T.WR,T.RD,rv,args=args,mapped=mapped)
            changed=run(image,entry,T.WR,T.RD,rv,args=args,mapped=mapped)
            def event(e,patch=False):
                val=e['value']
                if patch and downshift and e['op']=='write' and e['page']==5 and e['reg']==0x44:
                    val|=0x40
                return e['op'],e['page'],e['reg'],val
            assert [event(e,True) for e in stock]==[event(e) for e in changed],(hex(entry),args,rv)
            cases+=1
    return cases


def recipe_abi(b):
    original,changed=b.image,patched_image(b)
    def execute(im,entry,read_value,read_ok,write_return):
        with arm(im) as a:
            writes=[]
            page=[0]
            def wr(a):
                r,v=a.reg('r0')&255,a.reg('r1')&255
                if r==127:page[0]=v
                writes.append((page[0],r,v,a.reg('sp')&7))
                # Simulate only AAPCS caller-saved corruption, not arbitrary callee state.
                for reg in ('r1','r2','r3','r12'):a.setreg(reg,0xDEADBEEF)
                return write_return
            def rd(a):
                if read_ok:a.uc.mem_write(a.reg('r1'),bytes([read_value]))
                for reg in ('r1','r2','r3','r12'):a.setreg(reg,0xDEADBEEF)
                return int(read_ok)
            a.stub(T.WR,effect=wr)
            a.stub(T.RD,effect=rd)
            for reg in range(4,12):a.setreg(f'r{reg}',0x1000+reg)
            r=a.run(entry,count=100000)
            return writes,r,[a.reg(f'r{reg}') for reg in range(4,12)],a.reg('sp')
    cases=0
    for e in T.FLASH_RECIPES:
        for ok in (False,True):
            for ret in (0,1,0x76543210):
                before=execute(original,e,0xD7,ok,ret)
                after=execute(changed,e,0xD7,ok,ret)
                # B may alter only 05:44 values; ABI and all other writes must be exact.
                expected=[(p,r,(v|64) if p==5 and r==68 and v in (4,5) and b.changes else v,s)
                          for p,r,v,s in before[0]]
                if before[0]!=after[0]:assert expected==after[0],(hex(e),before,after)
                assert before[1:]==after[1:],(hex(e),before[1:],after[1:])
                assert all(s==0 for _,_,_,s in after[0])
                cases+=1
    return cases


def debounce_check(b):
    with arm(patched_image(b)) as a:
        a.stub(T.SCHEDULE_SAVE)
        status,caps=request(a,P.GET,(0,P.CAPS))
        assert status==0xA0 and P.decode_capabilities(caps)['flags']&P.F_DB
        cases=0
        for active in range(3):
            a.uc.mem_write(T.ACTIVE_PROFILE,bytes([active]))
            a.run(T.RELOAD_DB)
            for profile in range(1,4):
                values=(profile*3,profile*5,profile*7,profile*11)
                before=bytes(a.uc.mem_read(T.SETTINGS,704))
                live=bytes(a.uc.mem_read(0x2300CC50,4))
                status,data=request(a,P.SET,(profile,P.DEBOUNCE,*values))
                assert status==0xA0 and data==bytes([profile,*values])
                offset=(profile-1)*232+7
                expected=bytearray(before);expected[offset:offset+4]=bytes(values)
                assert bytes(a.uc.mem_read(T.SETTINGS,704))==expected
                assert bytes(a.uc.mem_read(0x2300CC50,4))==(bytes(values) if active==profile-1 else live)
                assert request(a,P.GET,(profile,P.DEBOUNCE))==(0xA0,bytes([profile,*values]))
                cases+=1
        for val in (0,1,100,254,255):
            assert request(a,P.SET,(1,P.DEBOUNCE,val,val,val,val))[0]==0xA0
            assert request(a,P.GET,(1,P.DEBOUNCE))[1]==bytes([1,val,val,val,val])
            cases+=1
        for cmd,payload,n in [(P.GET,(0,1),2),(P.GET,(4,1),2),(P.SET,(0,1,1,2,3,4),6),
                              (P.SET,(4,1,1,2,3,4),6),(P.SET,(1,1,1,2,3,4),5),
                              (P.GET,(1,1),3),(P.GET,(0,0),1),(P.SET,(0,0),2)]:
            before=bytes(a.uc.mem_read(T.SETTINGS,704))
            live=bytes(a.uc.mem_read(0x2300CC50,4));count=len(a.calls)
            assert request(a,cmd,payload,n)[0]==0xA2
            assert before==bytes(a.uc.mem_read(T.SETTINGS,704)) and live==bytes(a.uc.mem_read(0x2300CC50,4))
            assert len(a.calls)==count
            cases+=1
        return cases


def persistence_check(b):
    """Exercise original save + profile portion of original boot load with NVM stubs."""
    image=patched_image(b)
    with arm(image) as a:
        a.stub(T.SCHEDULE_SAVE)
        for p in range(1,4):request(a,P.SET,(p,1,0,p,10+p,20+p))
        nvm={}
        def store(a):nvm[a.reg('r0')]=bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2')))
        a.stub(0x0E072628,effect=store)
        a.stub(0x0E06821C)
        a.run(0x0E0726B8)
        assert len(nvm[0x1A7000])==704
    with arm(image) as c:
        def load(a):
            if a.reg('r0') in nvm:a.uc.mem_write(a.reg('r1'),nvm[a.reg('r0')])
            return 0
        def memcpy(a):
            a.uc.mem_write(a.reg('r0'),bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2'))))
            return a.reg('r0')
        c.stub(0x0E072824)
        c.stub(0x0E07260C,effect=load)
        c.stub(0x0E0877E0,effect=memcpy)
        c.stub(0x0E072860)
        c.uc.mem_write(0x230087D0,struct.pack('<H',336))
        crc=c.run(0x0E07F806,0x230087D0,80,0)
        c.uc.mem_write(0x23008912,struct.pack('<H',crc))
        c.ends.add(0x0E072AF2)
        c.run(0x0E072990,count=100000)
        for p in range(3):
            assert bytes(c.uc.mem_read(T.SETTINGS+p*232+7,4))==bytes([0,p+1,11+p,21+p])
            c.uc.mem_write(T.ACTIVE_PROFILE,bytes([p]));c.run(T.RELOAD_DB)
            assert bytes(c.uc.mem_read(0x2300CC50,4))==bytes([0,p+1,11+p,21+p])
        return 3


def native_comparison(b):
    # Continue through original group1 entry, including preserved TBH/literal addresses.
    cases=[(0x8F,(1,)),(0x88,(1,)),(0x89,(1,)),(0x8B,(1,)),(0x93,(1,)),
           (8,(1,0x87)),(8,(2,0x13)),(8,(3,2)),(0x8D,(1,))]
    for cmd,payload in cases:
        results=[]
        for image in (b.image,patched_image(b)):
            with arm(image) as a:
                a.uc.mem_write(0x2300BE10,b'\x04');a.put32(0x2300BE14,0x0E089769)
                for fn in (T.SCHEDULE_SAVE,0x0E07E4B4,0x0E07E4EC,0x0E07E568):a.stub(fn)
                a.stub(0x0E07E260,2);a.stub(0x0E07E278,1)
                reply=request(a,cmd,payload)
                results.append((reply,bytes(a.uc.mem_read(T.SETTINGS,704)),a.calls))
        assert results[0]==results[1],(cmd,results)
    return len(cases)


def verify(b,profile=None):
    from .profiles import telemetry
    profile=profile or getattr(b,'profile','FULL')
    enabled=telemetry(profile)
    if getattr(b,'profile','FULL') != profile:
        raise ValueError('verification profile does not match the candidate')
    if not __debug__:
        raise RuntimeError('firmware verification requires Python without -O / PYTHONOPTIMIZE')
    result=dict(sensor_cases=sensor_comparison(b,True),
                recipe_abi_cases=recipe_abi(b),
                db_cases=debounce_check(b),db_native_save_load_profiles=persistence_check(b),
                native_commands=native_comparison(b))
    from .advanced import verify as advanced_verify
    result['advanced']=advanced_verify(b)
    from .optical_checks import verify as optical_verify
    result['optical']=dict(mode='stock',native=True,cases=optical_verify(b),result='PASS',hardware='not run')
    if enabled:
        from .channel_checks import verify as channel_verify
        result['channels']=dict(cases=channel_verify(b),result='PASS',hardware='not run')
    else:
        from .profile_checks import verify_super
        result['telemetry_absence']=verify_super(b)
    result['result']='PASS'
    return result
