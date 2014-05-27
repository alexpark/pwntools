from pwn.internal.shellcode_helper import *
import random

@shellcode_reqs(blob = True, avoider = True, arch=['i386', 'arm'], os=['linux'])
def scramble(data, unclobber = None, bufreg = None, arch=None, os=None):

    if arch == 'i386':
        if unclobber == None:
            unclobber = ['esp']
        return _scramble_i386(flat(data), unclobber, bufreg, get_avoid())

    elif arch == 'arm':
        if os == 'linux':
            return _scramble_arm_linux(flat(data))

    bug('OS/arch combination (%s, %s) is not supported for scramble' % (os, arch))

# def alpha_mixed(code, **kwargs):
#     avoid, getpc = __parse_kwargs(kwargs)
#     pass

def _scramble_i386(code, unclobber, bufreg, avoid):
    """AKA shikata ga nai"""

    def encode(code):
        orig_key = p32(random.randint(0, 1 << 32))
        key = orig_key
        while True:
            encoded = []
            keyblock = key
            okkey = True
            for block in group(4, code):
                block = ''.join(block)
                oblock = xor(block, keyblock)
                keyblock = p32((u32(block) + u32(keyblock)) % (1 << 32))
                for i in range(4):
                    if oblock[i] in avoid:
                        key = list(key)
                        while True:
                            key[i] = chr((ord(key[i]) + 1) % 0x100)
                            if key[i] == orig_key[i]:
                                return None
                            if xor(key[i], block[i]) not in avoid:
                                break
                        key = ''.join(key)
                        okkey = False
                        break
                if not okkey:
                    break

                encoded.append(oblock)
            if okkey:
                break

        encoded = ''.join(encoded)
        return key, encoded

    def regnum(reg):
        if   reg == 'eax':
            return 0
        elif reg == 'ecx':
            return 1
        elif reg == 'edx':
            return 2
        elif reg == 'ebx':
            return 3
        elif reg == 'ebp':
            return 5
        elif reg == 'esi':
            return 6
        elif reg == 'edi':
            return 7

    def choose(bs):
        bs = filter(lambda block: all(b not in avoid for b in block), bs)
        if bs == []:
            raise Exception('Cannot build decoder under given restrictions')
        return random.choice(bs)
    def mix(blocks):
        random.shuffle(blocks)
        return ''.join(blocks)

    length = align(4, len(code))

    decoder_size = sum([2, # clear_counter
                        2 if length <= 255 else 4, # init_counter
                        5, # init key
                        2 + 4 + 1,
                        3 + 3 + 3, # loop body
                        2]) # loop inst
    cutoff = length - len(code)

    regs = ['eax', 'edx', 'ebx']
    regs = filter(lambda r: r not in unclobber, regs)
    random.shuffle(regs)
    if len(regs) < 3:
        return None
    counter = regnum('ecx')
    key, bufptr = map(regnum, regs[:2])

    clear_counter = \
        [b + p8(0xc0 + counter + counter * 8) for b in '\x31\x29\x33\x2b']

    if length <= 255:
        init_counter = p8(0xb0 + counter) + p8(length)
    else:
        init_counter = '\x66' + p8(0xb8 + counter) + p16(length)

    init_key = p8(0xb8 + key)

    xorv = '\x31' + p8(0x40 + bufptr + 8 * key)
    add = '\x03' + p8(0x40 + bufptr + 8 * key)
    sub4 = '\x83' + p8(0xe8 + bufptr) + p8(-4)
    add4 = '\x83' + p8(0xc0 + bufptr) + p8(4)

    fpu = []
    fpu += ['\xd9' + p8(x) for x in range(0xe8, 0xee)]
    fpu += ['\xd9' + p8(x) for x in range(0xc0, 0xcf)]
    fpu += ['\xd9' + x for x in '\xd0\xe1\xf6\xf7\xe5']
    fpu += ['\xda' + p8(x) for x in range(0xc0, 0xdf)]
    fpu += ['\xdb' + p8(x) for x in range(0xc0, 0xdf)]
    fpu += ['\xdd' + p8(x) for x in range(0xc0, 0xc7)]
    fnstenv = '\xd9\x74\x24\xf4'
    getpc = choose(fpu) + fnstenv + p8(0x58 + bufptr)

    xor1 = xorv + p8(decoder_size - cutoff)
    xor2 = xorv + p8(decoder_size - 4 - cutoff)
    add1 = add + p8(decoder_size - cutoff)
    add2 = add + p8(decoder_size - 4 - cutoff)

    loop_body = [xor1 + add1 + sub4,
                 xor1 + sub4 + add2,
                 sub4 + xor2 + add2,
                 xor1 + add1 + add4,
                 xor1 + add4 + add2,
                 add4 + xor2 + add2]

    loop_inst = '\xe2\xf5'

    loop = choose(loop_body) + loop_inst

    if cutoff > 0:
        code = loop[-cutoff:] + code
        loop = loop[:-cutoff]

    key, encoded = encode(code)

    init = mix([choose(clear_counter) + init_counter, init_key + key])

    stub = getpc + init + loop

    return stub + encoded

def _scramble_arm_linux(sc):
    """Args: sc = plain shellcode in ARM with thumb_to_arm shellcode 
    Scrambles ARM shellcode
    """
    def EncodingSC(sc, key):
        xsc = ''
        for i in range(0, len(sc)):
            xsc += chr( ord(sc[i]) ^ key )

        return xsc
 
    def CheckBadChar(sc):
        badChar = [ '\x00', '\x0a', '\x0d' ]
        q = {}
        q['null'] = 0
        q['0A'] = 0
        q['0D'] = 0
        for s in sc:
            if s in badChar:
                if s == '\x00':
                    q['null'] += 1
                elif s == '\x0a':
                    q['0A'] += 1
                elif s == '\x0a':
                    q['0D'] += 1
        return q
     
    def XORing_Thumb(size=0, key=0x58):
        xor = []
        loopsize = 256-size
        __ARM_NR_cacheflush = 0x0f0002
        xor += ['add r6, pc, #92', # #80+#12
                'bx r6',
                'main:',
                    'mov r4, #%s' % str(loopsize),
                    'add r6, pc, #40', # #28+#12
                    'ldrb r5, [r6, #36]',
                    'eor  r5, r5, r5',
                    'strb r5, [r6, #36]',
                'loop:',
                    'cmp r4, #256',
                    'bxhi r6', 
                    'sub r4, r4, #%s' % str(loopsize),
                    'ldrb r5, [lr, r4]',
                    'eor  r5, r5, #%s'% str(key), 
                    'strb r5, [lr, r4]',
                    'add  r4, r4, #%s' % str(loopsize+1),
                'b loop',
                'sync:',
                    'mov r7, #2',
                    'mov r1, #2',
                    'mov r7, r7, LSL #19', # 0x100000
                    'mov r1, r1, LSL #15', # 0x010000
                    'add r6, pc, #1',
                    'bx r6',
                    '.code 16',
                    'sub r7, r7, r1',      # 0x0f0000
                    'add r7, #2',          # 0x0f0002 = __ARM_NR_cacheflush
                    'sub r2, r2, r2',
                    'mov r0, lr',
                    'mov r1, lr',
                    'add r1, #%s' % str(size+1),
                    'svc 1',
                    'b scode',
                '.code 32',
                'bl main',
                'scode:'
               ]
     
        return indent_shellcode(xor)
 
    def FindXORKey(sc):
        size = len(sc)
        for i in range(0x00, 0xff):
            key = 1
            for s in sc:
                x = (ord(s) ^ i)
                if x in [0x0, 0xa, 0xd]:
                    key = -1
                    break
            if key == 1:
                log.info("Found XORing Key: 0x%02x" % (i))
                return i
                break


    key = FindXORKey(sc)
    decoder = XORing_Thumb(len(sc), key)
    asm_decoder = asm(decoder)
    xored_sc = EncodingSC(sc, key)
    return asm_decoder + xored_sc

