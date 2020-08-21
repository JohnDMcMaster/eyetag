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

# 2.2.5 DP architecture version 2 (DPv2) address map

# 2.3.9 SELECT, AP Select register

# 32 bit + 3 bit ack
# In the Shift-DR state, this data is shifted out, least significant bit first. As shown in Figure 3-7,
# the first three bits of data shifted out are ACK[2:0].

"""
If RnW is shifted in as 0, the request is to write the value in DATAIN[31:0] to the addressed register.

If RnW is shifted in as 1, the request is to read the value of the addressed register. The value in DATAIN[31:0]
is ignored. You must read the scan chain again to obtain the value read from the register.
"""

def parse_dpap_tdo(tdo, prefix=""):
    assert len(tdo) == 35, len(tdo)
    ackbits = tdo[32:35]
    if ackbits == "010":
        # OK/FAULT
        ack = "OKF"
    elif ackbits == "001":
        ack = "WAIT"
    # All other ACK encodings are reserved.
    else:
        assert 0, ackbits
    data = int(tdo[0:32], 2)
    print("  %s tdo data 0x%08X, ack %s" % (prefix, data, ack))
    return data, ack

def parse_dpap_tdi(tdi, prefix=""):
    assert len(tdi) == 35
    data = int(tdi[0:32], 2)
    a = int(tdi[32:34], 2)
    rnw = int(tdi[34], 2)
    if rnw:
        rnw = "r"
    else:
        rnw = "w"
    print("  %s tdi data 0x%08X,  a %s, rnw %s" % (prefix, data, a, rnw))
    return data, a, rnw

class EyeTAG:
    def __init__(self):
        self.cmd_max = float('inf')
        # self.cmd_max = 8

    def iter_jtag_wr(self, fn_in):
        self.ir = None
        self.last_state = None
        self.vendor = None
        self.part = None
        self.part_ver = None
        self.cmdn = 0
        for p in iter_decode(fn_in):
            t, state, tdi, tdo = p
            if state == 'Run-Test/Idle':
                self.cmdn += 1
                if self.cmdn >= self.cmd_max:
                    return
                print("")
                print("Group %u" % self.cmdn)
            print(state)
            if state == "Test-Logic-Reset":
                ir = "IDCODE"
            elif state == "Capture-IR":
                ir = "IDCODE"
            elif state == "Shift-IR":
                ir_raw = tdi2ir(tdi)
                ir = match_ir(ir_raw)
                print("  New IR: %s (%s)" % (ir_raw, ir))
            elif state == "Shift-DR":
                print("  TDI %u %s" % (len(tdi), tdi))
                print("  TDO %u %s" %(len(tdo), tdo))
                if ir == "IDCODE" and self.last_state == "Capture-DR":
                    print("  IDCODE (full)", tdo[-72:])
                    id32 = tdo2dr(tdo)
                    print("  IDCODE (32)", id32)
                    vendor, part, part_ver = parse_idcode_str(id32)
                elif ir == "DPACC":
                    # several things in bypass (1 bit each)
                    yield ir, tdi[2:], tdo[2:]
                elif ir == "APACC":
                    yield ir, tdi[2:], tdo[2:]
            last_state = state

    def next_decode(self):
        def next_data():
            ir, tdi, tdo = next(self.cmds)
            if ir == "DPACC":
                # Table 3-6 JTAG-DP target response summary, when previous scan a was a DPACC access
                tdi_dec = parse_dpap_tdi(tdi, "DPACC")
                tdo_dec = parse_dpap_tdo(tdo, "DPACC")
                return ir, tdi_dec, tdo_dec
            elif ir == "APACC":
                # Table 3-7 JTAG-DP target response summary, when previous scan a was an APACC access
                tdi_dec = parse_dpap_tdi(tdi, "APACC")
                tdo_dec = parse_dpap_tdo(tdo, "APACC")
                return ir, tdi_dec, tdo_dec
            else:
                assert 0, ir

        try:
            ir, tdi_dec, tdo_dec = next_data()
        except StopIteration:
            raise
            # return None

        if ir == "DPACC":
            datai, a, rnw = tdi_dec
            astr = {
                0: "UNKNOWN",
                # 2.3.2 CTRL/STAT, Control/Status register
                1: "CTRL_STAT",
                2: "SELECT",
                3: "RDBUFF",
                }[a]
            print("  DPACC %s %s pending..." % (rnw, astr))
            if rnw == "r":
                # read response
                ir2, tdi_dec2, tdo_dec2 = next_data()
                assert ir2 == "DPACC", ir2
                datao, ack = tdo_dec2
                print("  DPACC R %s: 0x%08X, ack %s" % (astr, datao, ack))
            else:
                # read response
                ir2, tdi_dec2, tdo_dec2 = next_data()
                datao, ack = tdo_dec2
                print("  DPACC W %s: 0x%08X, ack %s" % (astr, datai, ack))

        elif ir == "APACC":
            pass
        else:
            assert 0, ir

    def run(self, fn_in):
        self.cmds = self.iter_jtag_wr(fn_in)
        while True:
            try:
                self.next_decode()
            except StopIteration:
                break


def main():
    import argparse

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--verbose', action="store_true")
    parser.add_argument('--cmd-max', type=str, default='inf')
    parser.add_argument('fn_in', default=None, help='')
    args = parser.parse_args()

    parse_jep106()
    et = EyeTAG()
    et.cmd_max = float(args.cmd_max)
    et.run(args.fn_in)

if __name__ == "__main__":
    main()
