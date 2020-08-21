#!/usr/bin/env python3

"""
Focus is on ARM ADI
But should be extenable to other devices if there is demand... 

IHI0031C_debug_interface_as.pdf
"""

import re

part_id2str = {
    "ARM Ltd.": {
        0xBA00: "A9",
        }
    }

# Table 3-2 Standard IR instructions
ir_b2str = {
    # IMPLEMENTATION DEFINED extensions to the IR instruction set on page 3-76
    "0xxx": "IMPL",
    "1000": "ABORT",
    "1001": "RESERVED1",
    "1010": "DPACC",
    "1011": "APACC",
    "110x": "RESERVED2",
    "1110": "IDCODE",
    "1111": "BYPASS",
}

def match_ir(ir):
    assert len(ir) == 4
    for k, v in ir_b2str.items():
        if k == ir:
            return v
    return ir



def parse_jep106(fn="jep106.inc"):
    id2str = {}
    str2id = {}

    f = open(fn, "r")
    f.readline()
    for l in f:
        l = l.strip()
        if '/*' in l:
            continue
        # [0][0x15 - 1] = "NXP (Philips)",
        m = re.match(r"\[(.*)\]\[(.*) - 1\] = \"(.*)\"", l)
        id1 = int(m.group(1), 0)
        id0 = int(m.group(2), 0)
        id = (id1 << 7) | id0
        mfg = m.group(3)
        id2str[id] = mfg
        str2id[mfg] = id
    return id2str, str2id

jed_id2str, jed_str2id = parse_jep106()

def parse_b(s):
    # 0b  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111  1111
    s = s.replace(" ", "")
    s = s.replace("0b", "")
    return s

def iter_decode(fn):
    """Time [s]    TAP state    TDI    TDO    TDIBitCount    TDOBitCount"""
    f = open(fn, "r")
    f.readline()
    for l in f:
        l = l.strip()
        t, state, tdi, tdo, tdin, tdon = l.split(",")
        t = float(t)
        tdi = parse_b(tdi)
        if tdi:
            tdin = int(tdin)
            assert len(tdi) == tdin
        else:
            tdi = None
            tdin = None
        tdo = parse_b(tdo)
        if tdo:
            tdon = int(tdon)
            assert len(tdo) == tdon
        else:
            tdo = None
            tdon = None
        yield t, state, tdi, tdo


def parse_idcode(idcode):
    """
    Version
    (bits 31–28)
    
    Part Number
    (bits 27–12)
    
    Manufacturer Identity
    (bits 11–1)

    Fixed
    (bit 0)
    
    Figure 3-8. Device Identification Register Structure


    JTAG tap: imx6.dap tap/device found: 0x4ba00477
    (mfg: 0x23b (ARM Ltd.), part: 0xba00, ver: 0x4)

    """
    idcode = int(idcode, 2)
    version = (idcode >> 28) & 0xF
    part = (idcode >> 12) & 0xFFFF
    vendor = (idcode >> 1) & 0x7FF
    fixed = idcode & 1
    assert fixed == 1
    return vendor, part, version 

def parse_idcode_str(idcode):
    vendor, part, version  = parse_idcode(idcode)
    vendors = jed_id2str[vendor]
    parts = part_id2str[vendors][part]
    print("  vendor 0x%03X => %s" %(vendor, vendors))
    print("  part 0x%04X => %s" % (part, parts))
    print("  version 0x%01X" % version)
    return vendors, parts, version

def tdi2ir(tdi):
    # hmm a lot of bits but we are at the end
    # will need to handle this more properly later...
    # 111111111111111
    return tdi[-4:]

def tdo2dr(tdo):
    return tdo[-32:]

def main():
    import argparse

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--verbose', action="store_true")
    parser.add_argument('fn_in', default=None, help='')
    args = parser.parse_args()

    parse_jep106()
    ir = None
    last_state = None
    vendor = None
    part = None
    part_ver = None
    cmdn = 0
    cmd_max = 5
    for p in iter_decode(args.fn_in):
        t, state, tdi, tdo = p
        if state == 'Run-Test/Idle':
            print("")
            cmdn += 1
            if cmdn >= cmd_max:
                return
        print(state)
        if state == "Test-Logic-Reset":
            ir = "IDCODE"
        if state == "Capture-IR":
            ir = "IDCODE"
        if state == "Shift-IR":
            ir_raw = tdi2ir(tdi)
            ir = match_ir(ir_raw)
            print("  New IR: %s (%s)" % (ir_raw, ir))
        if state == "Shift-DR":
            print("  TDI", tdi)
            print("  TDO", tdo)
        if ir == "IDCODE" and state == "Shift-DR" and last_state == "Capture-DR":
            print("  IDCODE (full)", tdo[-72:])
            id32 = tdo2dr(tdo)
            print("  IDCODE (32)", id32)
            vendor, part, part_ver = parse_idcode_str(id32)
        last_state = state

if __name__ == "__main__":
    main()
