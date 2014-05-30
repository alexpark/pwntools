#!python

import os, sys
import tempfile
import pprint

from pwn import *
context('i386', 'linux')


def patch(fname, patched):
    elf = ELF(fname)
    addy = [0x8048e1a, 0x8048e32, 0x8048e4a, 0x8048e62, 0x8048fb8, 0x8049348]
    patch_bytes = 5

    for a in addy:
        elf.write(a, '\x90'*patch_bytes)
        # payload = asm("xor eax, eax").ljust(patch_bytes, "\x90")
        # elf.write(a, payload)

    open(patched, 'wb').write(elf.get_data())
    log.info('%s has been patched' % fname) 


def GenDiff(ori, chg):
    CMD = "diff -urN %s %s"
    OBJ = 'objdump -d -j .text %s > %s'
    ori_diff = tempfile.mktemp()
    chg_diff = tempfile.mktemp()
    rv = os.popen(OBJ % (ori, ori_diff))
    rv = os.popen(OBJ % (chg, chg_diff))
    rv = os.popen(CMD % (ori_diff, chg_diff)).readlines()
    os.unlink(ori_diff)
    os.unlink(chg_diff)
    for r in rv:
        print r.strip()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print "Binary name is not set"
        sys.exit(-1)

    fname = sys.argv[1]
    patched = "%s.patched" % fname
    patch(fname, patched)
    GenDiff(fname, patched)
