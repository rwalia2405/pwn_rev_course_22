# What is Shellcode?
Shellcode is a small piece of code (usually some assembly instructions) that is injected into the memory to perform arbitrary code execution. 

# What is NX?
NX (no execute), also known as DEP (Data execution prevention) is an exploit mitigation technique which marks certain areas of the program as non executable, specially the stack.

In case NX is disabled, a shellcode can be injected on the stack and if there is a buffer overflow, the RIP can be manipulated to point to our shellcode which would give arbitrary code execution.

## System Calls (syscalls)
To understand system calls, we need to know the difference between user mode and kernel mode. A process running in user mode has restricted access to the resources such as the hardware, CPU, etc. Hardware level operations cannot be perform directly in user mode.

A process running in kernel mode (or supervisor mode) has infinite or unrestricted access to the system's resources and can do anything with it. The core functionalities of the operating system run in the kernel mode. Any crash or memory corruption in the kernel mode can destroy the entire operating system. So, there needs to be a way by which user mode processes can do operations such as read, write, open, etc. This is done through system calls or syscalls.
    A system call is a programmatic way by which a program requests some service from the kernel. 
Various types of system calls are open, read, write, execl, execve, fork, mmap, etc.

For example, our favorite function `system("/bin/sh")` uses the fork() system call to create a new child process followed by execl syscall to spawn a shell.


Now, you need to use system calls in your shellcode. Checkout the famous System call table by Ryan Rchapman https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/.

Usually, in binary exploitation, execve("/bin/sh",0,0) system call is used to spawn a shell. According to Rchapman's blog, the value present in rax for execve syscall is 59.

Thus, to perform an execve("/bin/sh",0,0):
rax -> 59
rdi -> pointer to /bin/sh\x00
rsi -> 0
rdx -> 0

Checkout https://shell-storm.org/shellcode/ for different shellcodes

A simple piece of shellcode that calls the above syscall to spawn a shell is :
```
	xor 	rsi, rsi			;clear rsi
	push	rsi				;push null on the stack
	mov 	rdi,	0x68732f2f6e69622f	 ;/bin//sh in reverse order
	push	rdi
	push	rsp		;set the stack pointer to /bin//sh
	pop	rdi				
	mov 	al,	59			;sys_execve 
	cdq					;sign extend of eax
	syscall
```

We can make our life easier by using pwntools 

```
shellcode = asm(shellcraft.sh())   -> This generates shellcode to spawn a shell
```
If NX is disabled, you may store this shellcode on the stack and redirect the RIP to point to your shellcode in order to execute it and get a shell.


## Seccomp (Secure Computing Mode)
Seccomp is a security feature in the Linux kernel that filters. The Berkeley Packet Filter (BPF) is used. Seccomp filtering provides a means for a process to specify a filter for incoming system calls, which allows enabling only a small set of syscalls. If a syscall that's not allowed is made, the program will terminate. 
https://github.com/david942j/seccomp-tools can be used to find out which syscalls are allowed, which are not allowed, etc.

```
seccomp-tools  dump ./binaryName
```


## File Descriptors
Everything in Linux is a file! A file descriptor is a number that uniquely identifies an open file in the  operating system. The values 0,1 and 2 are fixed.

0 -> stdin
1 -> stdout
2 -> stderr

File descriptors exist sequentially. For example, consider the following piece of code:

```
#include<fcntl.h>
.....
int fd1 = open("file1",O_RDWR);
int fd2 = open("file2",O_RDWR);

Suppose the value of fd1 is 3, then the value of fd2 will be 4 and so on, since, file descriptors identify open files.
```

various syscalls can be used to open, read and write files. Please refer to Rchapman's blog and the Linux man pages for more details.


## Performing Ret2libc when there's a buffer overflow and you have the libc

In this case, you need to leak some GOT entry and find the libc base address from it.
```
payload = b'a'*offset + p64(pop_rdi_ret) + p64(elf.got.functionName) + p64(elf.plt.puts)+ p64(target_to_return_to)   -> usually target_to_return_to is a function that is vulnerable to buffer overflow


```

## Ret2libc when there's a buffer overflow and you do not have the libc

In this case, you need to leak multiple libc addresses, usually from the GOT (Global Offset Table). 
```
payload = b'a'*offset + p64(pop_rdi_ret)+ p64(elf.got.functionName1)+p64(elf.plt.puts)
+p64(pop_rdi_ret)+ p64(elf.got.functionName2)+ p64(elf.plt.puts) + p64(function_vulnerable_to_buffer_overflow)
```

Find the addresses leaked by calling puts(elf.got.functionName1) and puts(elf.got.functionName2), search them in a libc database such as https://libc.rip/, and from there you can find the correct libc used. In some cases, you may have to perform hit and try with various possible libcs according to the leaked values, to find out the correct libc used. 


## Automatic Format String exploitation using pwntools

```
payload = fmtstr_payload(fmt_offset, {elf.got.functionName: elf.sym.someOtherFunction})
Usually, someOtherFunction will be a function that spawns a shell or reads a flag, etc.
Pass this payload to printf() to write  elf.sym.someOtherFunction to elf.got.functionName.

Please note that anything can be corrupted using this bug, not only function pointers. You can use the above snippet to write any data anywhere!!!

You can only write to the Global Offset Table if there is Partial RELRO or No RELRO. In case of Full RELRO, you cannot write anything to the GOT.

fini_array is yet another array that can be used as a location to write function pointers.

fini_array is an array that stores some function pointers that are called whenever a program proceeds towards termination. So, if we insert some function that spawns a shell into the fini_array, it will get called when the program would proceed towards termination.

Note: you cannot overwrite it in case of Full RELRO.
```


## PIE (Position Independent Executables)
It is yet another exploit mitigation technique. With PIE, everything in the binary's memory regions is compiled to have an offset versus a fixed address. Each time the binary is run, the binary generates a random number known as a base. Then the address of everything becomes the base address plus the offset. To actually defeat PIE, you need to get some ELF address leak.

Suppose, you have a function winner
In case PIE is enabled, you cannot use elf.sym.winner directly. First of all, you will need to find the ELF base address ( using some format string bug or read+puts-printf combo). After that, you need to set `elf.address = <correct_base_address>`

Now, since you have set the elf.address or the elf base address to the correct value, you can safely find the correct address of the function winner by doing `elf.sym.winner`






