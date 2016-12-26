from idaapi import *
from idc import *
from idautils import Assemble
from payload import Item


# the following code was taken from
# http://hexblog.com/2009/09/assembling_and_finding_instruc.html
# -----------------------------------------------------------------------
def FindInstructions(instr, asm_where=None):
    """
    Finds instructions/opcodes
    @return: Returns a tuple(True, [ ea, ... ]) or a tuple(False, "error message")
    """

    failasm = "Failed to assemble:"

    if not asm_where:
        # get first segment
        asm_where = FirstSeg()
        if asm_where == idaapi.BADADDR:
            return (False, "No segments defined")

    # regular expression to distinguish between opcodes and instructions
    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)

    # split lines
    lines = instr.split(";")

    # all the assembled buffers (for each instruction)
    bufs = []
    for line in lines:
        if re_opcode.match(line):
            # convert from hex string to a character list then join the list to form one string
            try:
                buf = ''.join([chr(int(x, 16)) for x in line.split()])
            except ValueError:
                return (False, failasm + line)
        else:
            # assemble the instruction
            ret, buf = Assemble(asm_where, line)
            if not ret:
                return (False, failasm + line)
        # add the assembled buffer
        bufs.append(buf)

    # join the buffer into one string
    buf = ''.join(bufs)

    # take total assembled instructions length
    tlen = len(buf)

    # convert from binary string to space separated hex string
    bin_str = ' '.join(["%02X" % ord(x) for x in buf])

    # find all binary strings
    ea = MinEA()
    ret = []
    while True:
        ea = FindBinary(ea, SEARCH_DOWN, bin_str)
        if ea == idaapi.BADADDR:
            break
        ret.append(ea)
        ea += tlen
    if not ret:
        return (False, "Could not match [%s]" % bin_str)

    return (True, ret)


# -----------------------------------------------------------------------
def find(s=None, x=False, asm_where=None):
    result = None
    b, ret = FindInstructions(s, asm_where)
    if b:
        # executable segs only?
        if x:
            for ea in ret:
                seg = idaapi.getseg(ea)
                if (not seg) or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                result = ea
                break
        else:
            print "bug"
    return result


class drgadgetplugin_t:
    def __init__(self, payload, rv):
        self.payload = payload
        self.rv = rv
        self.menucallbacks = [("dROP", self.run, "Ctrl-F5")]

    # mandatory
    # must return list of tuples
    # (label of menu, callback)
    # or None if no callbacks should be installed
    def get_callback_list(self):
        result = None
        if self.payload.proc.supports_assemble():
            result = self.menucallbacks
        return result

    def run(self):
        n = self.rv.Count()
        for i in xrange(n):
            item = self.rv.get_item(i)
            if item is not None and item.type == Item.TYPE_CODE:
                cmt = item.comment
                ea = find(cmt, True)
                if ea is not None:
                    item.ea = ea
                    self.rv.set_item(i, item)
                else:
                    print "Could not find gadget for item %d" % i

    def term(self):
        pass
