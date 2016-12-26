"""
known bugs:
- the dr.rer.oec.gadget GUI needs an overhaul. if you
  are experiencing any issues, try closing the window
  and reopen it using the plugin hotkey

todo:
- finish/improve disasm "engine"?
- support stack directions?
- add xrefs to "items" class?
- add proper handling/support for plugin hotkeys
"""

pluginname = "Dr.Gadget"
__author__ = "patois"
__version__ = "0.59b"

import struct, os, sys
from idaapi import *
from idc import *

sys.path.append(idadir(os.path.join("plugins", "drgadget")))

import ropviewer
import payload

pluginname = pluginname + " " + __version__


# -----------------------------------------------------------------------


class idp_hook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def savebase(self, *args):
        if pl:
            print "\n%s: saving...\n" % pluginname
            pl.save_to_idb()
        return _idaapi.IDP_Hooks_savebase(self, *args)


pl = None
rv = None


class drgadget(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = pluginname
    wanted_hotkey = "Alt-F5"

    def init(self):
        global rv

        self.hook = idp_hook()
        self.hook.hook()
        print "%s: plugin initialized." % pluginname
        rv = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global pl
        global rv

        if not pl:
            pl = payload.Payload()
            if pl.load_from_idb():
                print "%s: loaded data from IDB." % pluginname
        if not rv:
            rv = ropviewer.ropviewer_t(pl)
            if not rv.Create():
                print "could not create window."
                return

        rv.Show()
        rv.show_content_viewers()

    def term(self):
        if self.hook:
            self.hook.unhook()
        pass


# -----------------------------------------------------------------------

def PLUGIN_ENTRY():
    return drgadget()
