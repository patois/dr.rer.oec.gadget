from idc import *
from payload import Item
import idaapi

"""
This plugin sets the internal "type" field
of any item's address that points into an
executable section to "TYPE_CODE"
"""


def analyze(payload):
    for n in xrange(payload.get_number_of_items()):
        ea = payload.get_item(n).ea
        seg = idaapi.getseg(ea)
        if seg:
            # address points to one of the segments
            if (seg.perm & idaapi.SEGPERM_EXEC) != 0:
                payload.get_item(n).type = Item.TYPE_CODE
            else:
                payload.get_item(n).type = Item.TYPE_ADDRESS


class drgadgetplugin_t:
    def __init__(self, payload, rv):
        self.payload = payload
        self.rv = rv
        self.menucallbacks = [("Simple payload analysis", self.run, "Ctrl-F2")]

    # mandatory
    # must return list of tuples
    # (label of menu, callback)
    # or None if no callbacks should be installed    
    def get_callback_list(self):
        return self.menucallbacks

    def run(self):
        analyze(self.payload)
        self.rv.refresh()

    def term(self):
        pass
