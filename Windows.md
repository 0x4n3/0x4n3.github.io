---
layout: default
---

# Overview

[Return to Home](./index.md)

Welcome to Windows or in other words welcome to recursive APIs and general lack of documentation. In this chapter I will go over the various resources I have personally found helpful also dive into some tips and tricks that proved useful in my journey.


## Blogs and Presentations


### Recommended

* [Connor McGarr's Blog](https://connormcgarr.github.io/)
* [Spaceraccoon's Blog](https://spaceraccoon.dev/)
* [Richard Osgood's Blog](https://www.richardosgood.com/)
* [Yarden Shafir's Blog](https://medium.com/@yardenshafir2)
* [ihack4falafel's Blog](https://ihack4falafel.github.io/)
* [DHN's Blog](https://zer0-day.pw/)


### Technical Deep-Dives

* [Part 19: Kernel Exploitation -> Logic bugs in Razer rzpnk.sys](https://fuzzysecurity.com/tutorials/expDev/23.html) by Fuzzy Security
* [I Got 99 Problem But a Kernel Pointer Ain't One](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf) by Alex Ionescu
* [Bypassing Control Flow Guard in Windows 10 - Part II](https://blog.improsec.com/tech-blog/bypassing-control-flow-guard-on-windows-10-part-ii) by Morten Schenk
* [Windows Code Injection: Bypassing CIG Through KnownDlls](https://www.tiraniddo.dev/2019/08/windows-code-injection-bypassing-cig.html?m=1) by Tyranid's Lair
* [Floating-Poison Math in Chakra](https://www.zerodayinitiative.com/blog/2018/8/22/floating-poison-math-in-chakra) by Simon Zuckerbraun
* [The Info Leak Era on Software Exploitation](https://www.youtube.com/watch?v=VgWoPa8Whmc) by Fermin J. Serna
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 1](https://www.youtube.com/watch?v=pJZjWXxUEl4) by OJ Reeves
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 2](https://www.youtube.com/watch?v=UGWqq5kTiso) by OJ Reeves


## Courses I've Taken

* [EXP-301](https://www.offsec.com/documentation/EXP301-syllabus.pdf) by OffSec
  * This course is a great introduction to x86 Windows exploit development. Don't expect anything fancy, but this is a must-have if you are new to the field.
* [EXP-401](https://www.offensive-security.com/awe/EXP401_syllabus.pdf) by OffSec
  * The gold standard in terms of modern Windows exploit development and security research. If you have the opportunity to attend this course, do so by all means.

## Courses I Want to Take

* [Windows Internal Architecture by CodeMachine](https://codemachine.com/trainings/winint.html)
* [Windows Malware Techniques by CodeMachine](https://codemachine.com/trainings/winmal.html)
* [Windows Kernel Internals by CodeMachine](https://codemachine.com/trainings/kerint.html)
* [Windows Kernel Rootkits by CodeMachine](https://codemachine.com/trainings/kerrkt.html)

# WinDbg

[back to top](#table-of-contents)

This section will discuss various tips and tricks I have found useful while working with WinDbg


## Revelant Blog(s)

* [Setting up kernel debugging using WinDbg and VMware](https://www.triplefault.io/2017/07/setting-up-kernel-debugging-using.html) by triplefault.io


## Important

* **!!!Run RP++ in Target Environment!!!**
* Memcpy produces no bad characters
* use `!showimports` to view imports


## General Advice


### Breaking on a Specified Thread Context

`~.` as a prefix to the breakpoint.  For example:

```
~. bp <module_name>!<function_name>+0xfff
```


### Determining the File Source of a Function Call

When you are examining a program with WinDbg you may need to find what file defines a particular function executed in memory. One approach to doing so is by examining the call stack soon after the function is called.  Within WinDbg, this can be accomplished through the command `k`.  `k` lists a series of functions and their associated modules that were called upon in memory. Taking this knowledge, you can then have an idea of what files to search for using the following syntax in WinDbg: `lm m <module_name>`.  Note: The module name is displayed prior to the `!` in the call stack shown by `k`. 


### Returning to Where You Left Off

Whenever you leave for a bit and lose your place in WinDbg, you can get back to where you were by setting a breakpoint at the last opcode you were examining.  For example for 

```
005c182c    3bc8                cmp     ecx,eax
```

The command would be 

```
bp 5c182c
```


### Setting Breakpoints

You can set a breakpoint by using the hexadecimal location of a particular instruction in IDA. For example if you see the following in IDA:

```
.text:005C182C  cmp     ecx, eax
```

Assuming that you have the correct base address, you can break at that particular location using the command:

```
bp 5C182c
```


## Registers

This section covers the various purposes of registers that I have found interesting


### EAX

The EAX register is a 32-bit general-purpose register that is commonly used to store the return value for an arbitrary function.  


## WinDbg Commands

This section discusses various WinDbg commands that I have found particularly useful to use. 


### ba - Break on Access

What is *Break on Access*? Well, in WinDbg, the `ba` command, or *Break on Access*, sets a processor breakpoint which is subsequently triggered if the target memory is accessed.[^1] What is the target memory? Well, for example, if you have an input buffer that you would like to monitor, that is a perfect example of target memory. Thus, the processor breakpoint is particularly useful when you do not want to step into (`t`) a function call and would rather set a processor breakpoint and then step over the command (`p`). Thus, if the targeted memory is accessed when you step over the function call, the processor breakpoint would be subsequently triggered indicating that the function call accessed the target memory. This allows you to save potentially massive amounts of time since you can step over long function calls that may not necessarily be relevent to the function chain you are investigating. 


#### Usage

`ba r1 <memory_address>`

The provided example sets a processor breakpoint at the specified `<memory_address>` with `r` indicating to break if the CPU reads or writes at the specified address with the size of the location, in bytes, to monitor for access indicated by `1`. [Source](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ba--break-on-access-)


### pt - Step to Next Return

Unlike debugging with visual studio, the debugging features within WinDbg are far more robust. For example, the `pt` command can execute a program and breaks until a return instruction is hit. This ability allows us to step into a function (`t`) and then continue until the function's return. This allows for alot of flexability because with `p`, it simply steps over only one instruction where as `pt` repeatedly steps over instructions until, as stated before, a `ret` instuction is executed. 

