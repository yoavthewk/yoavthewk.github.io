# rootkit - pwnable.kr

Let us tackle another Grotesque pwnable challenge.

```
Server admin says he can't access a file even if he has root.
Can you access the file?
```

This challenge seems less pwn-y, and more linux-y. Let's dive right in.

After `ssh`ing in, we are in a weird linux environment. We can see this message in the boot log:
```
[    1.857784] rootkit: module license 'unspecified' taints kernel.
```

This most likely means that this `rootkit` module, which is most likely a part of the challenge, is loaded.

Let's take a look at our environment:
```
/ # ls
bin         etc         lib         lost+found  sbin        usr
dev         flag        linuxrc     rootkit.ko  tmp         var
```

The things I noticed first are the fact that there is no /proc, and the fact that there is a rootkit.ko file here which is most likely the loaded rootkit.

We are run as admin:
```shell
/ # whoami
whoami: unknown uid 0
```
so let's just open the flag:
```shell
/ # cat flag
[  136.934395] You will not see the flag...
cat: can't open 'flag': Operation not permitted
```

Now I think I understand what the challenge meant. Let's extract the loaded rootkit.ko to try and understand what's going on. Unfortunately, we have no ways of transferring files, so we need to use base64 to encode/decode:
```shell
/ # base64 rootkit.ko > rk.b64
/ # cat rk.b64
f0VMRgEBAQAAAAAAAAAAAAEAAwABAAAAAAAAAAAAAACACAAAAAAAADQAAAAAACgAFQASAAQAAAAU...
...
```

Let's decode it:
```shell
~/pwn/rootkit$ base64 -d rk.b64 > rk.bin
```

Let's decompile it, and go to `initmodule`:
```c
int initmodule()
{
  _DWORD *v0; // eax
  _DWORD *v1; // eax
  int v2; // edx
  int result; // eax

  sct = 0xC15FA020;
  sys_open = MEMORY[0xC15FA034];
  sys_openat = MEMORY[0xC15FA4BC];
  sys_symlink = MEMORY[0xC15FA16C];
  sys_symlinkat = MEMORY[0xC15FA4E0];
  sys_link = MEMORY[0xC15FA044];
  sys_linkat = MEMORY[0xC15FA4DC];
  sys_rename = MEMORY[0xC15FA0B8];
  sys_renameat = (int (__cdecl *)(_DWORD, _DWORD, _DWORD))MEMORY[0xC15FA4D8];
  wp();
  v0 = (_DWORD *)sct;
  *(_DWORD *)(sct + 20) = sys_open_hooked;
  v0[295] = sys_openat_hooked;
  v0[83] = sys_symlink_hooked;
  v0[304] = sys_symlinkat_hooked;
  v0[9] = sys_link_hooked;
  v0[303] = sys_linkat_hooked;
  v0[38] = sys_rename_hooked;
  v0[302] = sys_renameat_hooked;
  wp();
  v1 = (_DWORD *)_this_module[2];
  v2 = _this_module[1];
  *(_DWORD *)(v2 + 4) = v1;
  *v1 = v2;
  result = 0;
  _this_module[1] = &_this_module[1];
  _this_module[2] = &_this_module[1];
  return result;
}
```

The decompiler seems to have messed up a bit here; but we get the gist. This rootkit modifies the syscall table to point to new, hooked, syscall functions for each syscall that is needed to read the `flag` file. 

Let's take a look at one of these functions:
```c
int __cdecl sys_open_hooked(int a1, int a2, int a3)
{
  const char *v4; // [esp+0h] [ebp-10h]
  const char *v5; // [esp+4h] [ebp-Ch]

  if ( !strstr(v4, v5) )
    return sys_open(a1, a2, a3);
  printk("You will not see the flag...\n");
  return -1;
}
```
once again, it seems the decompiler has messed up, but we can assume the `strstr(...)` call is performed on the file name and the string `"flag"`.

Now, we can try to find some random linux tricks around this (and I did try), but I could not find anything that does not use these syscalls to comfortably access the `flag` file.

The first thought that came to my mind is: "I am root, I can simply load any other kernel module that returns the previous state". That can be pretty easily done; right? Simply:
1. patch the instruction that loads the address into the `sct` and make it store the true address of `sys_open`.
2. change the modname to be anything other than `rootkit` (you cannot have two modules of the same name loaded).
3. load the module and win!

Well, not so easy. At the start, I mentioned we do not have the `/proc` directory. Therefore, we cannot even access `kallsyms`, let alone find the address of `sys_open` in any other trivial way. We're just.. stuck here (note that there is no `gcc`, `gdb`, etc.).

That was until I played around a bit and noticed this:
```shell
/ # stat flag
  File: flag
  Size: 46              Blocks: 2          IO Block: 1024   regular file
Device: 100h/256d       Inode: 13          Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/ UNKNOWN)   Gid: (    0/ UNKNOWN)
Access: 2025-05-17 12:53:17.000000000
Modify: 2025-05-17 12:53:14.000000000
Change: 2025-05-17 12:53:14.000000000
```

Notice anything that might help us here?
No? Well, it isn't trivial. The first thing that popped to my mind is the fact that I have the inode and the device ID where the file is stored.

But, how does this really help us? Well, we can parse the `fs` directly in the device and get the file using its inode number. This is not trivial, but it seems to be the best lead we have thus far. 

I begun researching on ways to do so, and was heavily advised to use `debugfs`, but unfortunately it is not installed, and some manual labor is due. 

The first thing we must do, is understand which device it is stored in. When googling, I found out that each device has a minor and a major, and that the device ID shown in `stat` contains them both in a way that can be extracted using macros:
```
# from the man pages
st_dev This field describes the device on which this file resides.
              (The major(3) and minor(3) macros may be useful to
              decompose the device ID in this field.)
```
These macros then give you the following formula:
```c
dev_t = (major << 8) | minor
```
Therefore, in our case:
```c
256 = (major << 8) | minor = (1 << 8) | 0
```
meaning our major is 1, and our minor is 0.

Let's find out which device matches these numbers. Using some googling again, I found out `ls -la /dev` will show us the major and minor numbers of the devices at the end:
```shell
/ # ls -la /dev
total 1
drwxr-xr-x    6 0        0             3260 Aug 26 10:33 .
drwxr-xr-x   11 0        0             1024 Aug 26 10:36 ..
...
Aug 26 10:33 oldmem
crw-------    1 0        0           1,   4 Aug 26 10:33 port
crw-------    1 0        0         108,   0 Aug 26 10:33 ppp
crw-------    1 0        0          10,   1 Aug 26 10:33 psaux
crw-rw-rw-    1 0        0           5,   2 Aug 26 10:33 ptmx
brw-------    1 0        0           1,   0 Aug 26 10:33 ram0
brw-------    1 0        0           1,   1 Aug 26 10:33 ram1
brw-------    1 0        0           1,  10 Aug 26 10:33 ram10
brw-------    1 0        0           1,  11 Aug 26 10:33 ram11
brw-------    1 0        0           1,  12 Aug 26 10:33 ram12
brw-------    1 0        0           1,  13 Aug 26 10:33 ram13
brw-------    1 0        0           1,  14 Aug 26 10:33 ram14
brw-------    1 0        0           1,  15 Aug 26 10:33 ram15
brw-------    1 0        0           1,   2 Aug 26 10:33 ram2
brw-------    1 0        0           1,   3 Aug 26 10:33 ram3
brw-------    1 0        0           1,   4 Aug 26 10:33 ram4
brw-------    1 0        0           1,   5 Aug 26 10:33 ram5
brw-------    1 0        0           1,   6 Aug 26 10:33 ram6
brw-------    1 0        0           1,   7 Aug 26 10:33 ram7
brw-------    1 0        0           1,   8 Aug 26 10:33 ram8
brw-------    1 0        0           1,   9 Aug 26 10:33 ram9
crw-rw-rw-    1 0        0           1,   8 Aug 26 10:33 random
crw-------    1 0        0          10,  62 Aug 26 10:33 rfkill
crw-------    1 0        0         254,   0 Aug 26 10:33 rtc0
crw-------    1 0        0          21,   0 Aug 26 10:33 sg0
crw-------    1 0        0          10, 231 Aug 26 10:33 snapshot
brw-------    1 0        0          11,   0 Aug 26 10:33 sr0
crw-rw-rw-    1 0        0           5,   0 Aug 26 10:33 tty
crw-------    1 0        0           4,   0 
...
Aug 26 10:33 ttyprintk
crw-------    1 0        0          10, 223 Aug 26 10:33 uinput
crw-rw-rw-    1 0        0           1,   9 Aug 26 10:33 urandom
crw-------    1 0        0           7,   0 Aug 26 10:33 vcs
crw-------    1 0        0           7,   1 Aug 26 10:33 vcs1
crw-------    1 0        0           7, 128 Aug 26 10:33 vcsa
crw-------    1 0        0           7, 129 Aug 26 10:33 vcsa1
crw-------    1 0        0          10,  63 Aug 26 10:33 vga_arbiter
crw-rw-rw-    1 0        0           1,   5 Aug 26 10:33 zero
```

The numbers `1, 4`, `108, 0` etc at the end are the `major, minor`. We can notice that `/dev/ram0` matches our expected `major, minor` tuple. Hence the flag file resides there. But how the heck do you parse it?

We now know that our `flag` file is on `/dev/ram0` that is partitioned with a filesystem that uses `inodes`. Some googling leads to us knowing it is some sort of `ext` filesystem. Due to the fact it is an old linux:
```shell
/ # uname -r
3.7.1
```
I took the dignity to guess it is `ext2` although I have no idea.

Let's start reading about `ext2` to understand how to extract our flag file.

From now on, [the ext2 manual](https://www.nongnu.org/ext2-doc/ext2.html) is our bible, so to say. I am mostly interested in the `disk organization`, as I want to understand where my file is. Let's read that section briefly and look at this table:
![](/assets/images/writeups/rootkit/image.png)

It seems as if the first block of the filesystem, which is 1024 bytes, is the boot record and some misc data. Afterwards, comes a thing named a `superblock`, then a `block group descriptor table`, `block bitmap`, `inode bitmap`, `inode table` and then `data blocks`. 

I can deduce here that the `superblock` contains some metadata regarding the filesystem, the `block group descriptor table` contains some sort of mapping of block groups, and that the `inode table` contains the structure of each inode that somehow points to the correct `data blocks`.

Lets start parsing. We will use the tool `dd` which is conveniently installed on the machine (don't know what `dd` is? `man dd`).

First of all, lets read the superblock and parse important fields for us:
```shell
/ #  dd if=/dev/ram0 bs=1024 skip=1 count=1 | hexdump -C
1+0 records in
1+0 records out
00000000  00 04 00 00 00 10 00 00  cc 00 00 00 13 08 00 00  |................|
00000010  7e 02 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |~...............|
00000020  00 20 00 00 00 20 00 00  00 04 00 00 68 8d ad 68  |. ... ......h..h|
00000030  68 8d ad 68 6b 00 ff ff  53 ef 00 00 01 00 00 00  |h..hk...S.......|
00000040  71 e2 02 52 00 00 00 00  00 00 00 00 01 00 00 00  |q..R............|
00000050  00 00 00 00 0b 00 00 00  80 00 00 00 38 00 00 00  |............8...|
00000060  02 00 00 00 01 00 00 00  ca c0 57 17 d0 74 42 af  |..........W..tB.|
00000070  af 87 18 3a 23 2b 2a 56  00 00 00 00 00 00 00 00  |...:#+*V........|
00000080  00 00 00 00 00 00 00 00  2f 00 6f 6d 65 2f 72 6f  |......../.ome/ro|
00000090  6f 74 6b 69 74 2f 6d 6e  74 00 00 00 00 00 00 00  |otkit/mnt.......|
000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
1024 bytes (1.0KB) copied, 0.004498 seconds, 222.3KB/s
*
000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 0f 00  |................|
000000d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000e0  00 00 00 00 00 00 00 00  00 00 00 00 9a a8 02 9f  |................|
000000f0  e5 96 4c 5c 9b 1b 5f b9  55 03 d6 a2 01 00 00 00  |..L\.._.U.......|
00000100  0c 00 00 00 00 00 00 00  71 e2 02 52 00 00 00 00  |........q..R....|
00000110  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000160  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000170  00 00 00 00 00 00 00 00  ff 00 00 00 00 00 00 00  |................|
00000180  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000400
```

Now we can parse it according to the `superblock` struct provided in the docs:
```shell
s_inodes_count = 0x400
s_blocks_count = 0x1000
...
s_inodes_per_group = 0x400
...
s_inode_size = 0x80
...
```

From this we can attest that (nmjhhhhhhhhhhhhhhhhjhnnnnnnnnnnnnnnnnnnnm ~ my cat, I refuse to delete it) our file is in the first block group; due to it being 13 (and there are 0x400 inodes per group). Also, we know the `inode size` which is good for our parsing later on.

Now, let's parse the `block group descriptor table` to understand where our `inode table` is:
![](/assets/images/writeups/rootkit/image1.png)

We'll dump it using `dd if=/dev/ram0 bs=1024 skip=2 count=1 | hexdump -C` and we'll parse the `bg_inode_table` to know at which block the inode structs begin. From parsing, we can see the `bg_inode_table` starts at block 0x14. 

Now we know our `Inode Structure` resides at `bg_inode_table_block * block_size + (inode - 1) * inode_size` which is `0x14 * 0x400 + 12 * 0x80 = 22016`.

Let's read and parse our `inode structure`: 
![](/assets/images/writeups/rootkit/image2.png)

```shell
/ # dd if=/dev/ram0 bs=1 skip=22016 count=128 | hexdump -C
128+0 records in
128+0 records out
00000000  a4 81 00 00 2e 00 00 00  bd 86 28 68 ba 86 28 68  |..........(h..(h|
00000010  ba 86 28 68 00 00 00 00  00 00 01 00 02 00 00 00  |..(h............|
00000020  00 00 00 00 00 00 00 00  02 0e 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000060  00 00 00 00 1a 85 8b 38  00 00 00 00 00 00 00 00  |.......8........|
00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000080
```
from this we only need the field `i_block` which shows us which blocks hold the file data.

Look at offset `0x28`, it contains the `i_block` array, and the first value seemingly is 0x0e02. That means the data block for our file is block number 0x0e02 or 3586 in decimal.

Lets read it (we know the size from the `stat` call, we could also parse it in the inode structure):
```shell
/ # dd if=/dev/ram0 bs=1024 skip=3586 count=1 | hexdump -C
1+0 records in
1+0 records out
00000000  1f 8b 08 08 6b 86 28 68  00 03 66 6c 61 67 00 0b  |....k.(h..flag..|
00000010  32 c8 2f f1 36 2c 29 a9  8c 0f 2e 4f 35 06 52 de  |2./.6,)....O5.R.|
00000020  99 25 25 91 5c 00 1c c0  4b 32 17 00 00 00 00 00  |.%%.\...K2......|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```
this looks correct, and it also looks encrypted? Let's dump it into a file, move it over to our machine using base64, and examine it:
```shell
$ dd if=/dev/ram0 bs=1024 skip=3586 count=1 | head -c 46 > ez.zip
$ base64 ez.zip
H4sICGuGKGgAA2ZsYWcACzLIL/E2LCmpjA8uTzUGUt6ZJSWRXAAcwEsyFwAAAA==
```

```shell
~/pwn/rootkit$ base64 -d ez.zip.b64 > ez.zip

# I now verify that it is indeed compressed and decompress
~/pwn/rootkit$ binwalk ez.zip

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             gzip compressed data, has original file name: "flag", from Unix, last modified: 2025-05-17 12:51:55

~/pwn/rootkit$ mv ez.zip ez.gz
~/pwn/rootkit$ gzip -d ez.gz 
~/pwn/rootkit$ cat ez
[only-use-writeups-after-you-solved]
```

r00tkit destroyed.