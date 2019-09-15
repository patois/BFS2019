# test1.py
from capstone import *

CODE = b"\x48\x8b\x01\xC3\xC3\xC3\xC3"

md = Cs(CS_ARCH_X86, CS_MODE_64)
for j in xrange(256):
    for i in md.disasm("%c"%j+CODE, 0x1000):
        print("0x%x:\t%s\t%s" %(j, i.mnemonic, i.op_str))
        #print ("%c"%j+CODE).encode("hex")
    print "======================="
