from pwn.internal.shellcode_helper import *
from open_file import open_file
from write_stack import write_stack
from getdents import getdents

@shellcode_reqs(arch=['i386', 'arm'], os='linux')
def ls(filepath = '.', out_fd = 1, in_fd = 0, os = None, arch = None):
    """Args: filepath, [out_fd (imm/reg) = STDOUT_FILENO]

    Opens a directory and writes its content to the specified file descriptor.
    """

    if arch == 'i386':
        if os == 'linux':
            return _ls_linux_i386(filepath, out_fd, in_fd)

    elif arch == 'arm':
        if os == 'linux':
            return _ls_linux_arm(filepath, out_fd, in_fd)

def _ls_linux_i386(filepath='.', out_fd = 1, in_fd = 0):
    out = (open_file(filepath),
            "xchg ebp, eax\n",
            "ls_helper1:\n",
             getdents('ebp', 255, False),
             "test eax, eax\n",
             "jle ls_helper2\n",
             write_stack(out_fd, 'eax'),
             "jmp ls_helper1\n",
             "ls_helper2:\n")
    return out

def _ls_linux_arm(filepath='.', out_fd = 1, in_fd = 0):
    out = (open_file(filepath),
           "mov r6, r0\n", # backup the file descriptor
           "loop:\n",
           getdents(in_fd),
           "sub r4, r4, r4\n",
           "cmp r0, r4\n",
           "ble next\n",
           write_stack(out_fd, size=255),
           "sub r4, r4, r4\n",
           "cmp r0, r4\n",
           "bgt loop\n",
           "next:\n",
           )

    return out
