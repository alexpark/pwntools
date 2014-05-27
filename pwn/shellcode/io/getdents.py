from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

@shellcode_reqs(arch=['i386', 'arm', 'amd64'], os=['linux'])
def getdents(in_fd = 0, size = 255, allocate_stack = True, arch = None, os = None):

    in_fd  = arg_fixup(in_fd)
    if arch == 'i386':
        if os == 'linux':
            return _getdents_linux_i386(in_fd, size, allocate_stack)

    elif arch == 'arm':
        if os == 'linux':
            return _getdents_linux_arm(in_fd, size, allocate_stack)

    elif arch == 'amd64':
        if os == 'linux':
            return _getdents_linux_amd64(in_fd, size, allocate_stack)

    no_support('getdents', os, arch)


def _getdents_linux_arm(in_fd = 0, size = 255, allocate_stack = True):
    out = []

    if allocate_stack:
        out += ['adds r3, sp, #%s' % str(size),
                'mov  r1, r3'
               ]
    else:
        out += ['mov r1, sp']

    out += ['mov  r0, #%s' % (str(in_fd)),
            'mov  r2, #%s' % (str(size)),
            'svc  SYS_getdents',
            '.align 2']
    if allocate_stack:  
        out += ['mov sp, r3'] # restore stack point

    return indent_shellcode(out)

def _getdents_linux_i386(in_fd = 0, size = 255, allocate_stack = True):    
    """Args: [in_fd (imm/reg) = STDIN_FILENO] [size = 255] [allocate_stack = True]

    Reads to the stack from a directory.

    You can optioanlly shave a few bytes not allocating the stack space.

    Leaves the size read in eax.
    """

    out = """
            """ + pwn.shellcode.mov('ebx', in_fd, raw = True) + """
            xor eax, eax
            mov al, SYS_getdents
            cdq
            mov dl, %s""" % size

    if allocate_stack:
        out += """
            sub esp, edx"""

    out += """
            mov ecx, esp
            int 0x80"""

    return out

def _getdents_linux_amd64(in_fd=0, size=255, allocate_stack=True):

    out = []
    out += [ #"mov rdi, rax",
             "xor rax, rax",
             "mov al, SYS_getdents",
             "push %s" % str(in_fd),
             "pop rdi",
             "push %s" % str(size),
             "pop rdx",
           ]

    if allocate_stack:
        out += [ "sub rsp, rdx" ]

    out += [ "mov rsi, rsp",
             "int 0x80"  
           ]

    return indent_shellcode(out)
