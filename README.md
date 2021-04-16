HEY guys this my writeup of the 247ctf non executable stack challenge

The File is A 32-bit linux ELf executeable

The Binary contains the vulnerable gets() function.It reads any arbitary amount of bytes supplied from the user without any check

The binary also has NX bit set.So the stack is non-executable(hence the name of the challenge)

So we will be performing a ret2libc attack using buffer overflow

The Idea goes something like this:

1) Find the padding need to control THE EIP(instruction pointer)
2) Using The overflow to leak the address of puts from the server
3) Finding the libc version used in the remote server using the address
4) find the libc base address using the leak by = libcbase = putsleak - putsoffset
5) finding system,exit and /bin/sh address by adding the libc_base to their offsets
6) building the final payload = padding + addr(system) + addr(exit) + addr(/bin/sh)
7) send the payload and get your shell :)


