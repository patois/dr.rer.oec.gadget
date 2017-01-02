import idaapi
from idc import *
import pickle
from idautils import DecodeInstruction
import struct


# add support for xrefs?
class Item:
    TYPE_IMMEDIATE, TYPE_CODE, TYPE_ADDRESS = range(3)
    TYPES = (TYPE_IMMEDIATE, TYPE_CODE, TYPE_ADDRESS)

    def __init__(self, ea, _type, comment=""):
        self.ea = ea
        self.type = _type
        self.comment = comment
        self.block_num = 0


class TargetProcessor:
    def __init__(self):
        self.flags = idaapi.ph_get_flag()
        # instead of checking ph flags, should __EA64__ be used?
        self.is_64bit = (self.flags & idaapi.PR_USE64) != 0
        self.is_32bit = (self.flags & idaapi.PR_USE32) != 0
        self.is_stack_up = (self.flags & idaapi.PR_STACK_UP) != 0
        self.id = idaapi.ph_get_id()
        self.is_assemble_supported = (self.flags & idaapi.PR_ASSEMBLE) != 0
        self.is_delayslot_proc = (self.flags & idaapi.PR_DELAYED) != 0

        # processor default ret instruction (icode, not opcode!)
        self.ret_icodes = [idaapi.ph_get_icode_return()]

        # ptrsize in bytes
        self.ptrsize = 2
        if self.is_32bit:
            self.ptrsize = 4
        if self.is_64bit:
            self.ptrsize = 8

        self.ptrsize_pyfmt_mapper = {2: "H", 4: "I", 8: "Q"}
        self.ptrsize_mask_mapper = {2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
        self.datafmt_mapper = {2: "%04X", 4: "%08X", 8: "%016X"}
        self.endianness = idaapi.get_inf_structure().mf

    def uses_delay_slot(self):
        return self.is_delayslot_proc

    def supports_assemble(self):
        return self.is_assemble_supported

    def add_ret_icode(self, icode):
        self.ret_icodes.append(icode)

    def get_ret_instructions(self):
        return self.ret_icodes

    def is_little_endian(self):
        return self.endianness == 0

    def get_pointer_size(self):
        return self.ptrsize

    def get_ptr_pack_fmt_string(self):
        endiannesfmt = "<" if self.is_little_endian() else ">"
        return endiannesfmt + self.ptrsize_pyfmt_mapper[self.get_pointer_size()]

    def get_data_fmt_string(self):
        return self.datafmt_mapper[self.get_pointer_size()]

    def get_ptr_mask(self):
        return self.ptrsize_mask_mapper[self.get_pointer_size()]


def to_hex_str(s):
    hs = ""
    if s is not None:
        for e in s:
            hs += "%02X " % ord(e)
    return hs


class DisasmEngine:
    def __init__(self, proc):
        self.proc = proc
        self.maxinstr = 20  # max instructions to disasm per "gadget"

    def set_max_insn(self, count):
        self.maxinstr = count

    def get_max_insn(self):
        return self.maxinstr

    def is_ret(self, ea):
        return idaapi.is_ret_insn(ea)

    def disasm_single_ins(self, ea):
        result = None
        i = DecodeInstruction(ea)
        if i is not None:
            flags = GetSegmentAttr(ea, SEGATTR_FLAGS)
            use_dbg = flags & SFL_DEBUG != 0
            stream = GetManyBytes(ea, i.size, use_dbg)
            result = (ea, i, GetDisasmEx(ea, GENDSM_FORCE_CODE), self.is_ret(ea), stream)
        return result

    def get_disasm(self, ea):
        disasm = []
        insns = self.get_disasm_internal(ea)

        for i in insns:
            if i is not None:
                ea, ins, line, isret, strm = i
                strm = to_hex_str(strm)
                if isret:
                    color = idaapi.SCOLOR_CREFTAIL
                else:
                    color = idaapi.SCOLOR_CODNAME
                asm = idaapi.COLSTR("%s\n" % line, color)
                data = idaapi.COLSTR("%s\n" % strm, color)
            else:
                asm = idaapi.COLSTR("; invalid instruction \n", idaapi.SCOLOR_HIDNAME)
                data = ""
            disasm.append((asm, data))
        if len(disasm) == self.get_max_insn():
            cont = idaapi.COLSTR("...", idaapi.SCOLOR_HIDNAME)
            disasm.append((cont, cont))
        return disasm

    def get_disasm_internal(self, ea):
        nextea = ea
        disasm = []
        endEA = idaapi.BADADDR
        inscnt = 0
        while (nextea != endEA) and (inscnt < self.maxinstr):
            ins = self.disasm_single_ins(nextea)
            if ins is not None:
                ea, i, line, isret, strm = ins
                disasm.append(ins)
                nextea += i.size
                # TODO: stop disassembling at
                # user-defined instructions (taken from "proc" instance?)
                # also: should unconditional jumps be followed? :)
                if isret:
                    # TODO: can we safely assume the return instruction
                    # to follow exactly one single instruction?
                    # are there any processors that support both
                    # "delay-slot" and "non-delay-slot" return instructions?
                    if self.proc.uses_delay_slot():
                        inscnt += 1
                        disasm.append(self.disasm_single_ins(nextea))
                    return disasm
                inscnt += 1
            else:
                nextea = BADADDR
            if nextea == BADADDR:
                disasm.append(None)
        return disasm


class Payload:
    def __init__(self):
        self.size = 0
        self.rawbuf = ""
        self.nodename = "$ drgadget"
        self.proc = TargetProcessor()
        # would it be better to use inheritance?
        self.da = DisasmEngine(self.proc)
        self.init()

    def init(self, items=[]):
        self.items = items

    def load_from_idb(self):
        node = idaapi.netnode(0x41414141)
        node.create(self.nodename)
        result = node.getblob(0, "D")
        if result:
            self.items = pickle.loads(result)
        return result

    def save_to_idb(self):
        node = idaapi.netnode(0x41414141)
        node.create(self.nodename)
        node.setblob(pickle.dumps(self.items), 0, "D")

    def load_from_file(self, fileName):
        self.init()
        result = False
        f = None
        try:
            f = open(fileName, "rb")
            self.rawbuf = f.read()
            self.size = len(self.rawbuf)
            self.items = self.deserialize_items_from_buf(self.rawbuf)
            result = True
        except:
            pass
        finally:
            if f:
                f.close()
        return result

    def save_to_file(self, fileName):
        result = False
        f = None
        try:
            f = open(fileName, "wb")
            buf = self.serialize_buf_from_items()
            f.write(buf)
            result = True
        except:
            pass
        finally:
            if f:
                f.close()
        return result

    def serialize_buf_from_items(self):
        buf = ""
        for item in self.items:
            buf += struct.pack(self.proc.get_ptr_pack_fmt_string(), item.ea)
        return buf

    def deserialize_items_from_buf(self, buf):
        items = []
        for p in xrange(0, len(buf), self.proc.get_pointer_size()):
            try:
                ea = struct.unpack(self.proc.get_ptr_pack_fmt_string(), buf[p:p + self.proc.get_pointer_size()])[0]
            except:
                break
            items.append(Item(ea, 0))
        return items

    def get_number_of_items(self):
        return len(self.items)

    def mask_ea(self, item):
        item.ea = item.ea & self.proc.get_ptr_mask()
        return item

    def get_item(self, n):
        return self.mask_ea(self.items[n])

    def set_item(self, n, item):
        self.items[n] = item

    def insert_item(self, n, item):
        self.items.insert(n, item)

    def append_item(self, item):
        self.items.insert(len(self.items), item)

    def remove_item(self, n):
        self.items.pop(n)

    def reset_types(self):
        for n in xrange(self.get_number_of_items()):
            # self.set_type(n, 0)
            self.get_item(n).type = Item.TYPE_IMMEDIATE
