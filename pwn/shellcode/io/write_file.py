from pwn.internal.shellcode_helper import *
from ..misc.pushstr import pushstr

def _mov(reg, val):
    return pwn.shellcode.mov(reg, val, raw = True).strip()

@shellcode_reqs(arch=['i386', 'amd64', 'arm'], os=['linux'])
def write_file(in_fd = 1, contents = '', size = 127, arch = None, os = None):

    size = arg_fixup(size)
    in_fd = arg_fixup(in_fd)
    contents = arg_fixup(contents)


    if arch == 'i386':
        if os == 'linux':
            return _write_file_linux_i386(in_fd, contents, size)
    elif arch == 'arm':
        if os == 'linux':
            return _write_file_linux_arm(in_fd, contents, size)
    elif arch == 'amd64':
        if os == 'linux':
            return _write_file_linux_amd64(in_fd, contents, size)

    bug('OS/arch combination (%s, %s) is not supported for write_file' % (os, arch))


def _write_file_linux_i386(in_fd, contents, size):
    def trans_str(s):
        ran = len(s) / 4
        txt = []
        j = 0
        for i in range(0, ran):
            t  = s[j+3]
            t += s[j+2]
            t += s[j+1]
            t += s[j+0]
            j += 4
            txt.append('push 0x%s' % t.encode('hex').ljust(8, '0'))
        txt.append('push 0x%s' % s[j:][::-1].encode('hex').rjust(8, '0'))
        txt.reverse()
        return  txt

    out = []
    out += [ "push SYS_write",
             "pop eax",
             "push byte %s" % str(in_fd),
             "pop ebx", # file_no
             "xor edx, edx",
             "push edx"  # NULL Terminated
           ]
    out += trans_str(contents)
    
    out += [ "mov ecx, esp",
             "push byte %s" % str(size),
             "pop edx",
             "int 0x80"
            ]

    return indent_shellcode(out)

def _write_file_linux_amd64(in_fd, contents, size):
    out = []
    out += [ "jmp str_addr" ]

    out += [ "run:",
             "xor rax, rax",
             "xor rdi, rdi",
             "xor rdx, rdx",

             "add rax, SYS_write",
             "add rdi, %s" % str(in_fd),
             "pop rsi",
             "add rdx, %s" % str(size),
             "syscall",
             "jmp next"
            ]

    out += [ "str_addr:",
             "call run",
             'db "%s" , 0x0A' % (contents) 
           ]

    out += [ "next:" ]


    return indent_shellcode(out)

def _write_file_linux_arm(in_fd, contents, size):
    out = []
    out += ['mov r0, #%s' % str(in_fd),
            'mov r1, pc',
            'adds r1, #12', # 'contents' offset
            'mov r2, #%s' % str(size),
            'svc SYS_write',
            'b next',
            '.ascii "%s\x00"' % (contents),
            '.align 2',
            'next:'
            ]

    return indent_shellcode(out)
