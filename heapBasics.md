## Linux Heap Exploitation

### LIBC
LIBC -> Stands for GNU C library, it is an open source library that takes the form of a shared object. Alternate libc implementations also exist such as `musl`.It provides all the C functions such as printf, puts, etc. LIBC provides code for important functions of the operating system. It is so important that the system won't work without it.

To list the shared objects needed by a binary, use ldd (list dynamic dependencies)
```
ldd /bin/ls
```
Running the libc shared object prints its version.

Heap grows from lower memory addresses to higher memory addresses.

### malloc

```
#include <stdlib.h>
void *malloc(size_t size);
```

malloc is a dynamic memory allocator. Used when a program can't decide the size or number of objects needed by it at runtime. malloc allocates memory chunks which come from large, contiguous region of memory known as heap. It is so widely used that it's a great target for exploitation. It takes some size as an argument and returns a pointer to a memory chunk of slightly larger or same size.

`vmmap` command in gdb prints the memory map for a process. Location of the heap can be found using this command.

Use `dq mp_.sbrk_base <number>` to print the starting of the heap
```
void* a = malloc(16);

```
Just as stack metadata such as frame pointers, malloc chunks also use metadata which is stored on the heap. 

Malloc chunk's size increases in multiples of 16 bytes. For example,
malloc(24) creates a chunk of size 32 bytes.
malloc(25) creates a chunk of size 48 bytes

The structure of a chunk is:

```
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk, if it is free. */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;                /* double links -- used only if this chunk is free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if this chunk is free. */
  struct malloc_chunk* bk_nextsize;
};

typedef struct malloc_chunk* mchunkptr;
```


Structure of an allocated chunk
```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```



The LSB of the chunk size field indicates the `PREV_INUSE` flag. The first chunk's PREV_INUSE will always be set because it has no previous chunk. `PREV_INUSE` indicates that previous chunk (the adjacent chunk in lower memory) is being used by the program.
Malloc considers chunks to start 16 bytes before the user data. 


## Top Chunk
Based on the output of the vmmap command, we can see that the size of the heap is way larger than the size of some allocated chunk. Malloc treats the remaining unused memory as a single, large chunk known as the top chunk. The size of the top chunk reduces if /the number of allocated chunks increases.

Note: Heap exploitation techniques change with the version of libc used !

`vis` command in pwndbg can be used to see the heap

To see the type of a struct, run
```
ptype struct_name
```

## free
`free(ptr)` Its argument is a pointer to the chunk that needs to get freed. From malloc's perspective, a free chunk will be present in one of the many bins present.


Structure of a free chunk
```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .

```

## Arenas
Arenas are structures in which malloc keeps all of its inline metadata, consisting primarily of the heads of the free lists called bins. A single arena can administrate multiple heaps and a new arena is created with a initial heap every time a thread uses malloc for the first time, up to a limit based on the number of available cores. The main thread gets a special arena called the main arena, which resides in the libc data section.To view pwndbg commands related to the arena, run the command `pwndbg arena`.


## Bins
A bin is a list (singly linked or doubly linked list) of free chunks. When a chunk is freed, it is inserted into a bin.
There are various types of bins:

1. Fastbin
2. Unsorted bin
3. Small bin
4. Large bin
5. Tcache


### Fastbins
Fastbins are just a small collection of singly linked non-circular linked lists that hold free chunks of specific sizes. Fastbins can be seen in pwndbg by using the command `fastbins`. Whenever a chunk, that falls in the fastbin range gets freed, its address is written to the head of the appropriate fastbin in the heap's arena. Fastbins work on the LIFO principle (Last in, first out). Size range for fastbins is 0x20 to 0x80 under default conditions.

In case malloc is called, first of all the program will check if a chunk of similar or larger size is available in the bins or not. If it is available, the entire chunk or some part of it will be removed from the bins and will be provided to malloc. This is done to improve the memory management.


## Double Free
One of the most dangerous vulnerabilities!
Double free occurs when a free chunk is freed again. For example:

```
void* chunk1 = malloc(size);
void* chunk2 = malloc(size);
Type 1:

free(chunk1);
free(chunk2);


Type2:

This method is used to bypass the double free checks
free(chunk1);
free(chunk2);
free(chunk1);

```
Double free can be used to cause memory corruption.

## UAF (Use After Free)
One of the most dangerous vulnerabilities!
Use After free is a bug which comes in three forms: Read after free, write after free and execute after free. This occurs when a chunk is used after being freed. UAF can be exploited to cause memory corruption by overwriting pointers. A good method to prevent a UAF is 

```
free(chunk)
*chunk = 0
```

## __malloc_hook  and  __free_hook

Hooks are nothing but pointers that allow you to modify the behavior of functions such as malloc and free. Suppose __malloc_hook points to the function `pwnFunction` and a call to malloc is made. Then, whenever malloc would be called, the function `pwnFunction` will also get called!

Similarly, suppose __free_hook points to the function `pwnFunction`. Then, whenever free would be called, the function `pwnFunction` would also get called with the argument as the data present in the chunk.


## __malloc_hook -> pwnFunction

## __free_hook -> pwnFunction

## __free_hook -> system



## one_gadget
A tool used for finding the offset to call `execve('/bin/sh',0,0)`.
https://github.com/david942j/one_gadget

uses:
```
one_gadget libc_file

one_gadget_target = libc.address + <offset_given_by_one_gadget>

```

Overwriting __malloc_hook with one_gadget and calling malloc would spawn a shell for old versions of libc. For newer versions, either system('/bin/sh') or a ROP chain needs to be called.





free(chunk1)

edit(chunk1,data)