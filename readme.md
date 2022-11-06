# Writeup for the BFS Exploitation Challenge 2019

## Table of Contents

  - [Introduction](#introduction)
    - [TL;DR](#tldr)
  - [Initial Dynamic Analysis](#initial-dynamic-analysis)
  - [Statically Identifying the Vulnerability](#statically-identifying-the-vulnerability)
  - [Strategy](#strategy)
  - [Preparing the Exploit](#preparing-the-exploit)
  - [Building a ROP Chain](#building-a-rop-chain)
  - [See Exploit in Action](#see-exploit-in-action)
  - [Contact](#contact)

## Introduction

Having enjoyed and succeeded in [solving](https://github.com/patois/FancyVote) a previous BFS Exploitation Challenge from 2017,\
I've decided to give the [2019 BFS Exploitation Challenge](https://labs.bluefrostsecurity.de/blog/2019/09/07/bfs-ekoparty-2019-exploitation-challenge/) a try. It is a Windows 64 bit executable\
for which an exploit is expected to work on a Windows 10 Redstone machine.

The challenge's goals were set to:

1. Bypass ASLR remotely
2. Achieve arbitrary code execution (pop calc or notepad)
3. Have the exploited process properly continue its execution

### TL;DR

Spare me all the boring details, I want to

- [grab a copy of the challenge](https://static.bluefrostsecurity.de/files/lab/Eko2019_challenge.zip)
- [study the decompiled code](rsrc/eko2019.exe.c)
- [study the exploit](rsrc/sploit4.py)

## Initial Dynamic Analysis

Running the file named 'eko2019.exe' opens a console application that seemingly\
waits for and accepts incoming connections from (remote) network clients.

![Server Screenshot](rsrc/server.png?raw=true)

Quickly checking out the running process' security features using Sysinternals\
[Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) shows that DEP and ASLR are enabled, but Control Flow Guard is not. Good.

![Security features](rsrc/procexp.png?raw=true)

Further checking out the running process dynamically using tools such as Sysinternals\
[TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview), [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) or simply running netstat could have been an option right now,\
but personally I prefer diving directly into the code using my static analysis tool of choice,\
[IDA Pro](https://hex-rays.com/products/ida/index.shtml) (I recommended following along with your favourite disassembler / decompiler).

## Statically Identifying the Vulnerability

Having disassembled the executable file and looking at the list of identified functions,\
the maximum number of functions that need to be analyzed for weaknesses was as little as\
17 functions out of 188 in total - with the remaining ones being known library functions,\
imported functions and the _main()_ function itself.

Navigating to and running the disassembled code's _main()_ function through\
the [Hex-Rays decompiler](https://hex-rays.com/products/decompiler/index.shtml) and putting some additional effort into renaming functions,\
variables and annotating the code resulted in the following output:

![main function decompiled](rsrc/main.png?raw=true)

By looking at the code and annotations shown in the screenshot above, we can see there is\
 a call to a function in line 19 which creates a listening socket on TCP port 54321, shortly followed\
 by a call to _accept()_ in line 27. The socket handle returned by _accept()_ is then passed as an argument\
 to a function _handle_client()_ in line 36. Keeping in mind the goals of this challenge, this is probably\
 where the party is going to happen, so let's have a look at it.

![handle_client function decompiled](rsrc/handleclient.png?raw=true)

As an attacker, what we are going to look for and concentrate on are functions within the server's\
executable code that process any kind of input that is controlled client-side. All with the goal in mind\
of identifying faulty program logic that hopefully can be taken advantage of by us. In this case, it is the\
two calls to the _recv()_ function in lines 21 and 30 in the screenshot above which are responsible for\
receiving data from a remote network client.

The first call to _recv()_ in line 21 receives a hard-coded number of 16 bytes into a _"header"_ structure.\
It consists of three distinct fields, of which the first one at offset 0 is _"magic"_, a second at offset 8 is\
_"size_payload"_ and the third is unused.

![packet header structure](rsrc/header.png?raw=true)

By accessing the _"magic"_ field in line 25 and comparing it to a constant value _"Eko2019"_, the server\
ensures basic protocol compatibility between connected clients and the server. Any client packet\
that fails in complying with this magic constant as part of the _"header"_ packet is denied further\
processing as a consequence.

![header magic](rsrc/header_magic.png?raw=true)

By comparing the _"size_payload"_ field of the _"header"_ structure to a constant value in line 27,\
the server limits the field's maximum allowed value to 512. This is to ensure that a subsequent call to\
_recv()_ in line 30 receives a maximum number of 512 bytes in total. Doing so prevents the destination\
buffer _"buf"_ from being written to beyond its maximum size of 512 bytes - too bad!\
If this sanity check wasn't present, it would have allowed us to overwrite anything that follows the\
_"buf"_ buffer, including the return address to _main()_ on the stack. Overwriting the saved return address\
could have resulted in straightforward and reliable code execution.

Skimming through this function's remaining code (and also through all the other remaining functions)\
doesn't reveal any more code that'd process client-side input in any obviously dangerous way, either.\
So we must probably have overlooked something and -yes you guessed it- it's in the processing of\
the _"pkthdr"_ structure.

![vulnerability pseudo-c](rsrc/bug_c.png?raw=true)

A useful pointer to what the problem could be is provided by the hint window that appears\
as soon as the mouse is hovered over the comparison operator in line 27. As it turns out, it is a\
signed integer comparison, which means the size restriction of 512 can successfully be bypassed\
by providing a negative number along with the header packet in _"size_payload"_!

Looking further down the code at line 30, the _"size_payload"_ variable is typecast to a 16 bit integer\
type as indicated by the decompiler's _LOWORD()_ macro. Typecasting the 32 bit _"size_payload"_\
variable to a 16 bit integer effectively cuts off its upper 16 bits before it is passed as a size argument\
to _recv()_. This enables an attacker to cause the server to accept payload data with a size of up to\
65535 bytes in total. Sending the server a respectively crafted packet effectively bypasses the\
intended size restriction of 512 bytes and successfully overwrites the _"buf"_ variable on the stack\
beyond its intended limits.

If we wanted to verify the decompiler's results or if we refrained from using a decompiler entirely\
because we preferred sharpening or refreshing our assembly comprehension skills instead, we could\
just as well have a look at the assembler code:

- the _"jle"_ instruction indicates a signed integer comparison
- the _"movzx eax, word ptr..."_ instruction **mov**es 16 bits of data\
from a data source to a 32 bit register _eax_, **z**ero e**x**tending its\
upper 16 bits.

![vulnerability asm](rsrc/bug_asm.png?raw=true)

Alright, before we can start exploiting this vulnerability and take control of the server process'\
instruction pointer, we need to find a way to bypass ASLR _remotely_. Also, by checking out the\
_handle_client()_ function's prologue in the disassembly, we can see there is a stack cookie that\
will be checked by the function's epilogue which eventually needs to be taken care of .

![cookie](rsrc/cookie.png?raw=true)

## Strategy

In order to bypass ASLR, we need to cause the server to leak an address that belongs to\
its process space. Fortunately, there is a call to the _send()_ function in line 45, which sends\
8 bytes of data, so exactly the size of a pointer in 64 bit land. That should serve our purpose just fine.

![send function](rsrc/send.png?raw=true)

These 8 bytes of data are stored into a _QWORD variable _"gadget_buf"_ as the result of a call to the\
_exec_gadget()_ function in line 44.

Going further up the code to line 43, we can see self-modifying code that uses the\
_WriteProcessMemory()_ API function to patch the _exec_gadget()_ function with whatever data\
_"gadget_buf"_ contains.

The _"gadget_buf"_ variable in turn is the result of a call to the _copy_gadget()_ function in line 41\
which is passed the address of a global variable _"g_gadget_array"_ as an argument.

Looking at the _copy_gadget()_ function's decompiled code reveals that it takes an integer argument,\
swaps its endianness and then returns the result to the caller.

![copy_gadget function](rsrc/copygadget.png?raw=true)

In summary, whatever 8 bytes the _"g_gadget_array"_ at position _"gadget_idx % 256"_ points to will be\
executed by the call to _exec_gadget()_ and its result is then sent back to the connected client.

Looking at the cross references to _"g_gadget_array"_ which is only initialized during run-time,\
we can find a _for_ loop that initializes 256 elements of the array _"g_gadget_array"_ as part of\
the server's _main()_ function:

![gadget array initialization](rsrc/gadgetarray.png?raw=true)

Going back to the _handle_client()_ function, we find that the _"gadget_idx"_ variable is initialized\
with _62_, which means that a gadget pointed to by _"p_gadget_array[62]"_ is executed by default.

![gadget index](rsrc/gadgetidx.png?raw=true)

The strategy is getting control of the _"gadget_idx"_ variable. Luckily, it is a stack variable adjacent\
to the _"buf[512]"_ variable and thus can be written to by sending the server data that exceeds\
the _"buf"_ variable's maximum size of 512 bytes. Having _"gadget_idx"_ under control allows us\
to have the server execute a gadget other than the default one at index 62 (0x3e).

In order to be able to find a reasonable gadget in the first place, I wrote a little [Python script](rsrc/cap.py)\
that mimics the server's initialization of _"g_gadget_array"_ and then disassembles all its\
256 elements using the [Capstone Engine Python bindings](https://www.capstone-engine.org/lang_python.html):

![capstone script](rsrc/capstone.png?raw=true)

I spent quite some time reading the [resulting list of gadgets](rsrc/list.asm) trying to find a suitable\
gadget to be used for leaking a qualified pointer from the running process, but with\
partial success only. Knowing I must have been missing something, I still settled with\
a gadget that would manage to leak the lower 32 bits of a 64 bit pointer only, for the\
sake of progressing and then fixing it the other day:

![gadget 1b](rsrc/gadget_1b.png?raw=true)

Using this gadget would modify the pointer that is passed to the call to _exec_gadget()_,\
making it point to a location other than what the _"p"_ pointer usually points to, which\
could then be used to leak further data.

![exec gadget](rsrc/execgadget.png?raw=true)

Based on working around some limitations by hard-coding stuff, I still managed to\
develop quite a stable exploit including full process continuation. But it was only after a\
kind soul asked me whether I hadn't thought of reading from the _TEB_ that I got on the\
right track to writing an exploit that is more than just _quite_ stable. Thank you :-)

## Preparing the Exploit

The [TEB](https://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/TEB.html) holds vital information that can be used for bypassing ASLR, and it is accessed\
via the _gs_ segment register on 64 bit Windows systems. Looking through the list of\
gadgets for any occurence of _"gs:"_ yields a single hit at index 0x65 of the\
_"g_gadget_array"_ pointer.

![gadget 65](rsrc/teb_gadget.png?raw=true)

Acquiring the current thread's TEB address is possible by reading from gs:[030h]. In order to\
have the gadget that is shown in the screenshot above to do so, the _rcx_ register must first be\
set to 0x30.\
The _rcx_ register is the first argument to the _exec_gadget()_ function, which is loaded\
from the _"p"_ variable on the stack. Like the _"gadget_idx_ variable", _"p"_ is adjacent to the\
overflowable buffer, hence overwritable as well. Great.

![p argument](rsrc/p_arg.png?raw=true)

By sending a particularly crafted sequence of network packets, we are now given the ability\
to leak arbitrary data of the server thread's TEB structure. For example, by sending the following\
packet to the server, gadget number 0x65 will be called with _rcx_ set to 0x30.

```
[0x200*'A'] + ['\x65\x00\x00\x00\x00\x00\x00\x00'] + ['\x30\x00\x00\x00\x00\x00\x00\x00']
```

Sending this packet will overwrite the target thread's following variables on the stack and will\
cause the server to send us the current thread's TEB address:

```
[buf] + [gadget_idx] + [p]
```

The following screenshot shows the Python implementation of the _leak_teb()_ function used by\
the [exploit](rsrc/sploit4.py).

![leak teb](rsrc/leakteb.png?raw=true)

With the process' TEB address leaked to us, we are well prepared for leaking further information\
by using the default gagdet 62 (0x3e), which dereferences arbitrary 64 bits of process memory pointed\
to by _rcx_ per request:

![gadget index](rsrc/gadget_3e.png?raw=true)

In turn, leaking arbitrary memory allows us to

- bypass DEP and ASLR
- identify the stack cookie's position on the stack
- leak the stack cookie
- locate ourselves on the stack
- eventually run an external process

In order to bypass ASLR, the _"ImageBaseAddress"_ of the target executable must be acquired\
from the [Process Environment Block](https://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB.html) which is accessible at _gs:[060h]_. This will allow for relative\
addressing of the individual ROP gadgets and is required for building a ROP chain that bypasses\
Data Execution Prevention.\
Based on the executable's in-memory _"ImageBaseAddress"_, the address of the _WinExec()_ API\
function, as well as the stack cookie's xor key can be leaked.

![infoleaks](rsrc/leaks.png?raw=true)

What's still missing is a way of acquiring the stack cookie from the current thread's stack frame.

>Although I knew that the approach was faulty, I had\
initially leaked the cookie by abusing the fact that\
there exists a reliable pointer to the formatted text that\
is created by any preceding call to the _printf()_ function.\
\
![leak cookie](rsrc/leak_cookie.png?raw=true)\
\
By sending the server a packet that solely consisted of\
printable characters with a size that would overflow the\
entire stack frame but stopping right before the stack\
cookie's position, the call to _printf()_ would leak the\
stack cookie from the stack into the buffer holding the\
formatted text whose address had previously been acquired.\
\
![buf](rsrc/bufcookie.png?raw=true)\
\
While this might have been an interesting approach, it is an\
approach that is error-prone because if the cookie contained\
any null-bytes right in the middle, the call to _printf()_ will\
make a partial copy of the cookie only which would have\
caused the exploit to become unreliable.

Instead, I've decided to leak both _"StackBase"_ and _"StackLimit"_ from the [TIB](https://www.nirsoft.net/kernel_struct/vista/NT_TIB.html) which is part of the TEB\
and walk the entire stack, starting from _StackLimit_, looking for the first occurence of the saved return\
address to _main()_.

![leak cookie 2](rsrc/leak_cookie2.png?raw=true)

Relative from there, the cookie that belongs to the _handle_client()_ function's stack frame\
can be addressed and subsequently leaked to our client. Having a copy of the cookie\
and a copy of the xor key at hand will allow the _rsp_ register to be recovered, which can\
then be used to build the final ROP chain.

![restore rsp](rsrc/restore_rsp.png?raw=true)

## Building a ROP Chain

Now that we know how to leak all information from the vulnerable process that is required for\
building a fully working exploit, we can build a ROP chain and have it cause the server to pop calc.

Using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), a [list of gadgets](rsrc/gadgets.txt) was created which was then used to craft the following chain:

![ropchain](rsrc/ropchain.png?raw=true)

1. The ROP chain starts at _"entry_point"_, which is located at offset 0x230 of the\
vulnerable function's _"buf"_ variable and which previously contained the orignal\
return address to _main()_. It loads _"ptr_to_chain"_ at offset 0x228 into the _rsp_\
register which effectively lets _rsp_ point into the next gadget at _2.)_.\
\
Stack pivoting is a vital step in order to avoid trashing the caller's stack frame.\
Messing up the caller's frame would risk stable process continuation

2. This gadget loads the address of a "pop rax" gadget into _r12_ in preparation for\
a "workaround" that is required in order to compensate for the return address\
that is pushed onto the stack by the _call r12_ instruction in _4.)_.

3. A pointer to _"buf"_ is loaded into _rax_, which now points to the _"calc\0"_ string

4. The pointer to _"calc\0"_ is copied to _rcx_ which is the first argument for the \
subsequent API call to _WinExec()_ in _5.)_. The call to _r12_ pushes a return address\
on the stack and causes a "pop rax" gadget to be executed which will pop the address\
off of the stack again

5. This gadget causes the _WinExec()_ API function to be called

6. The call to _WinExec()_ happens to overwrite some of our ROP chain on the stack, hence\
the stack pointer is adjusted by this gadget to skip the data that is "corrupted" by the\
call to _WinExec()_

7. The original return address to _main()+0x14a_ is loaded into _rax_

8. _rbx_ is loaded with the address of _"entry_point"_

9. The original return address to _main()+0x14a_ is restored by patching _"entry_point"_\
on the stack -> "mov qword ptr [entry_point], main+0x14a". After that, _rsp_ is adjusted,\
followed by a few dummy bytes

10. _rsp_ is adjusted so it will slowly slide into its old position at offset 0x230 of\
_"buf"_, in order to return to _main()_ and guarantee process continuation

11. see _10.)_

12. see _10.)_

13. see _10.)_

## See Exploit in Action

![sploit in action](rsrc/action.gif?raw=true)
