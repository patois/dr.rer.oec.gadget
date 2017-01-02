from idaapi import *
from idc import *
from idautils import Assemble, Modules, DecodeInstruction
from payload import Item


class FindInstructionsForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:iInstructions}
BUTTON YES* Ok
BUTTON CANCEL Cancel
Find instruction(s)
{FormChangeCb}

Filters:
<Exclude ASLR modules:{rASLR}>
<Exclude DEP modules:{rDEP}>
<Exclude non-executable segments:{rExec}>{cGroup1}>

Options:
<#Refreshes memory content before starting search process#Sync memory:{rSync}>
<#Find regex expression (less speed, more flexibility)#Regex:{rRegex}>{cGroup2}>

Find instruction(s):
<#mov eax, 1; pop; pop; 33 C0; ret#:{iInstructions}>
""", {
            'cGroup1': Form.ChkGroupControl(("rASLR", "rDEP", "rExec")),
            'cGroup2': Form.ChkGroupControl(("rSync", "rRegex")),
            'iInstructions': Form.StringInput(),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if GetProcessState() == DSTATE_NOTASK:
            self.SetControlValue(self.rASLR, False)
            self.SetControlValue(self.rDEP, False)
            self.SetControlValue(self.rSync, False)

            self.EnableField(self.rASLR, False)
            self.EnableField(self.rDEP, False)
            self.EnableField(self.rSync, False)
            self.SetFocusedField(self.iInstructions)

        return 1


def AskInstructionsUsingForm():
    result = (False, "Cancelled")
    f = FindInstructionsForm()
    f.Compile()

    f.rASLR.checked = True
    f.rDEP.checked = True
    f.rExec.checked = True

    f.rSync.checked = True
    f.rRegex.checked = False

    ok = f.Execute()
    f.Free()
    if ok == 1:
        result = (True, (
        f.iInstructions.value, f.rASLR.checked, f.rDEP.checked, f.rExec.checked, f.rSync.checked, f.rRegex.checked))
    return result


class SearchResultChoose(Choose2):
    def __init__(self, ealist, title):
        self.list = ealist
        global payload
        global ropviewer
        self.payload = payload
        self.rv = ropviewer
        self.copy_item_cmd_id = self.append_item_cmd_id = None
        Choose2.__init__(self,
                         title,
                         [["address", 10 | Choose2.CHCOL_PLAIN],
                          ["segment", 10 | Choose2.CHCOL_PLAIN],
                          ["code", 30 | Choose2.CHCOL_PLAIN]],
                         popup_names=["Insert", "Delete", "Edit", "Copy item"])

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.copy_item_cmd_id:
            ropviewer.set_clipboard((0, "c", Item(self.list[n - 1].ea, Item.TYPE_CODE)))

        return 0

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.list[n - 1].columns

    def OnGetSize(self):
        return len(self.list)

    # dbl click / enter
    def OnSelectLine(self, n):
        Jump(self.list[n - 1].ea)

    def set_copy_item_handler(self, cmd_id):
        self.copy_item_cmd_id = cmd_id


class SearchResult:
    def __init__(self, ea):
        self.ea = ea
        self.columns = []

        name = SegName(ea)
        disasm = GetDisasmEx(ea, GENDSM_FORCE_CODE)

        self.columns.append("%X" % ea)
        self.columns.append(name)
        self.columns.append(disasm)


def assemble_code(instructions):
    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)
    lines = instructions.split(";")
    bufs = []
    global payload

    for line in lines:
        if re_opcode.match(line):
            # convert from hex string to a character list then join the list to form one string
            buf = ''.join([chr(int(x, 16)) for x in line.split()])
        else:
            # assemble the instruction
            if payload.proc.supports_assemble():
                ret, buf = Assemble(FirstSeg(), line)
                if not ret:
                    return (False, "Failed to assemble instruction:" + line)
            else:
                return (False, "Processor module can't assemble code. Please use regex option.")
                # add the assembled buffer
        bufs.append(buf)
    buf = ''.join(bufs)
    bin_str = ' '.join(["%02X" % ord(x) for x in buf])
    return (True, bin_str)


def get_disasm(ea, maxinstr=5):
    result = ""
    delim = "\n"

    i = 0
    while i < maxinstr:
        ins = DecodeInstruction(ea)
        if not ins:
            break

        disasm = GetDisasmEx(ea, GENDSM_FORCE_CODE)
        if not disasm:
            break
        result += disasm + delim
        ea += ins.size
        i += 1
    return result


def compile_regex(s):
    try:
        regex = re.compile(s, re.I | re.DOTALL)
    except:
        return (False, "Could not compile regex.")
    return (True, regex)


def match_regex(startEA, endEA, regex):
    result = BADADDR

    ea = startEA
    while ea < endEA:
        disasm = get_disasm(ea)
        if disasm:
            if regex.match(disasm):
                result = ea
                break
        ea += 1
    return result


def FindInstructionsInSegments(segments, bin_str, exclASLR, exclDEP, exclNonExec, checkDllChars=False):
    ret = []
    cancelled = False
    isRegex = isinstance(bin_str, type(re.compile('foo')))
    curseg = 0
    maxseg = len(segments)

    # thedude had too much coffee
    thedude = ["       " + "\n" \
                           "  (._.)" + "\n" \
                                       " /(  )\\" + "\n" \
                                                    "  |  |" + "\n",
               "    .  " + "\n" \
                           " (._.)" + "\n" \
                                      " /(  )\\" + "\n" \
                                                   "  /  \\" + "\n",
               "    o  " + "\n" \
                           "  (._.)" + "\n" \
                                       " /(  )\\" + "\n" \
                                                    "  |  |" + "\n",
               "    O  " + "\n" \
                           " (._.)" + "\n" \
                                      " /(  )\\" + "\n" \
                                                   "  /  \\" + "\n",
               "    *  " + "\n" \
                           "  (._.)" + "\n" \
                                       " /(  )\\" + "\n" \
                                                    "  |  |" + "\n"]

    show_wait_box("Say hello to thedude!")

    nMatches = 0
    for seg in segments:
        curseg += 1
        if (seg.perm & SEGPERM_EXEC) == 0 and exclNonExec:
            continue
        ea = sea = seg.startEA
        segname = SegName(ea)
        eea = seg.endEA
        if checkDllChars:
            dllchar = get_dll_characteristics(sea, eea - sea)
            if dllchar:
                dynbase, nx = get_security_flags(dllchar)
                if dynbase and exclASLR:
                    continue
                if nx and exclDEP:
                    continue

        pos = 0
        if isRegex:
            while True:
                ea = match_regex(ea, eea, bin_str)
                if ea == BADADDR:
                    break
                ret.append(ea)
                ea += 1
                nMatches += 1
                if wasBreak():
                    cancelled = True
                    break
                replace_wait_box("Segment: %d/%d (%s)\n0x%X-0x%X\nMatches: %d\n\n%s" % (
                curseg, maxseg, segname, ea, eea, nMatches, thedude[pos]))
                pos += 1
                pos %= len(thedude)
        else:
            while True:
                ea = find_binary(ea, eea, bin_str, 16, SEARCH_DOWN)
                if ea == BADADDR:
                    break
                ret.append(ea)
                ea += 1
                nMatches += 1
                if wasBreak():
                    cancelled = True
                    break
                replace_wait_box("Segment: %d/%d (%s)\n0x%X-0x%X\nMatches: %d\n\n%s" % (
                curseg, maxseg, segname, ea, eea, nMatches, thedude[pos]))
                pos += 1
                pos %= len(thedude)

        if cancelled:
            break

    hide_wait_box()

    if not ret:
        return (False, "Could not match [%s]" % bin_str if not isRegex else "regular expression")
    return (True, ret)


def FindInstructionsInModules(modules, bin_str, exclASLR, exclDEP, exclNonExec):
    segments = []
    for mod in modules:
        if mod.dynbase and exclASLR:
            continue
        if mod.nx and exclDEP:
            continue

        segments += get_segments(mod.base, mod.base + mod.size)
    return FindInstructionsInSegments(segments, bin_str, exclASLR, exclDEP, exclNonExec)


def get_security_flags(dllchars):
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100

    dynbase = dllchars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    nx = dllchars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0
    return (dynbase, nx)


class ModuleInfo(object):
    def __init__(self, mod):
        self.dynbase = self.nx = None
        self.name = mod.name
        self.base = mod.base
        self.size = mod.size
        self.rebase_to = mod.rebase_to
        self.dll_char = get_dll_characteristics(self.base, self.size)
        if self.dll_char:
            self.dynbase, self.nx = get_security_flags(self.dll_char)

        self.columns = []
        aslr = "N/A"
        dep = "N/A"
        if self.dll_char:
            aslr = "X" if self.dynbase else ""
            dep = "X" if self.dynbase else ""
        self.columns.append(self.name)
        self.columns.append("%X" % self.base)
        self.columns.append("%X" % self.size)
        self.columns.append(aslr)
        self.columns.append(dep)


# -----------------------------------------------------------------------
# TODO: add NOSEH
def get_dll_characteristics(base, size):
    # minimal, bugged pe parser
    result = None
    if size >= 0x40:
        mz = DbgWord(base)
        if mz == 0x5A4D or mz == 0x4D5A:
            offs_pe = DbgDword(base + 0x3C)
            if size > offs_pe + 2:
                pe = DbgWord(base + offs_pe)
                if pe == 0x4550:
                    if size > offs_pe + 0x5E + 2:
                        result = DbgWord(base + offs_pe + 0x5E)
    return result


def get_modules():
    results = []

    for mod in Modules():
        results.append(ModuleInfo(mod))
    return results


def get_segments(startEA=MinEA(), endEA=MaxEA()):
    segments = []

    seg = getseg(startEA)
    while seg and seg.endEA <= endEA:
        segments.append(seg)
        seg = get_next_seg(seg.startEA)

    return segments


payload = None
ropviewer = None


class drgadgetplugin_t:
    def __init__(self, pl, rv):
        global payload
        global ropviewer

        payload = pl
        ropviewer = rv
        self.menucallbacks = [("Find gadgets", self.run, "Ctrl-F3")]

    # mandatory
    # must return list of tuples
    # (label of menu, callback)
    # or None if no callbacks should be installed
    def get_callback_list(self):
        global payload
        result = self.menucallbacks
        return result

    def run(self):
        success, s = AskInstructionsUsingForm()
        if success:
            findstr, excl_aslr, excl_dep, excl_nonexec, sync, regex = s
            if sync:
                RefreshDebuggerMemory()

            if regex:
                success, s = compile_regex(findstr)
            else:
                success, s = assemble_code(findstr)
            if not success:
                Warning(s)
                return 0

            if GetProcessState() == DSTATE_NOTASK:
                success, ret = FindInstructionsInSegments(get_segments(), s, excl_aslr, excl_dep, excl_nonexec)
            else:
                success, ret = FindInstructionsInModules(get_modules(), s, excl_aslr, excl_dep, excl_nonexec)

            if success:
                results = []
                for ea in ret:
                    results.append(SearchResult(ea))

                title = "Search result for: [%s]" % findstr
                close_chooser(title)
                c = SearchResultChoose(results, title)
                c.Show()
                c.set_copy_item_handler(c.AddCommand("Copy item"))
            else:
                Warning(ret)
        else:
            Warning(s)

    def term(self):
        pass
