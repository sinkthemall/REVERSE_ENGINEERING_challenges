from pwn import *
s = process(executable = "./supervisor", env = {"LD_PRELOAD" : "./ptrace_hook.so"}, aslr = False, argv=  [])
s.interactive()

