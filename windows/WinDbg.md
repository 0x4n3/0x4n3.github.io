
# Overview

[Return to Home](../index.md)

This section will discuss various tips and tricks I have found useful while working with WinDbg

# Revelant Blog(s)

* [Setting up kernel debugging using WinDbg and VMware](https://www.triplefault.io/2017/07/setting-up-kernel-debugging-using.html) by triplefault.io


# Important

* **!!!Run RP++ in Target Environment!!!**
* Memcpy produces no bad characters
* use `!showimports` to view imports


# General Advice


## Breaking on a Specified Thread Context

`~.` as a prefix to the breakpoint.  For example:

```
~. bp <module_name>!<function_name>+0xfff
```


## Determining the File Source of a Function Call

When you are examining a program with WinDbg you may need to find what file defines a particular function executed in memory. One approach to doing so is by examining the call stack soon after the function is called.  Within WinDbg, this can be accomplished through the command `k`.  `k` lists a series of functions and their associated modules that were called upon in memory. Taking this knowledge, you can then have an idea of what files to search for using the following syntax in WinDbg: `lm m <module_name>`.  Note: The module name is displayed prior to the `!` in the call stack shown by `k`. 


## Returning to Where You Left Off

Whenever you leave for a bit and lose your place in WinDbg, you can get back to where you were by setting a breakpoint at the last opcode you were examining.  For example for 

```
005c182c    3bc8                cmp     ecx,eax
```

The command would be 

```
bp 5c182c
```


## Setting Breakpoints

You can set a breakpoint by using the hexadecimal location of a particular instruction in IDA. For example if you see the following in IDA:

```
.text:005C182C  cmp     ecx, eax
```

Assuming that you have the correct base address, you can break at that particular location using the command:

```
bp 5C182c
```


# Registers

This section covers the various purposes of registers that I have found interesting


## EAX

The EAX register is a 32-bit general-purpose register that is commonly used to store the return value for an arbitrary function.  


# WinDbg Commands

This section discusses various WinDbg commands that I have found particularly useful to use. 


## ba - Break on Access

What is *Break on Access*? Well, in WinDbg, the `ba` command, or *Break on Access*, sets a processor breakpoint which is subsequently triggered if the target memory is accessed.[^1] What is the target memory? Well, for example, if you have an input buffer that you would like to monitor, that is a perfect example of target memory. Thus, the processor breakpoint is particularly useful when you do not want to step into (`t`) a function call and would rather set a processor breakpoint and then step over the command (`p`). Thus, if the targeted memory is accessed when you step over the function call, the processor breakpoint would be subsequently triggered indicating that the function call accessed the target memory. This allows you to save potentially massive amounts of time since you can step over long function calls that may not necessarily be relevent to the function chain you are investigating. 


### Usage

`ba r1 <memory_address>`

The provided example sets a processor breakpoint at the specified `<memory_address>` with `r` indicating to break if the CPU reads or writes at the specified address with the size of the location, in bytes, to monitor for access indicated by `1`. [Source](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/ba--break-on-access-)


## pt - Step to Next Return

Unlike debugging with visual studio, the debugging features within WinDbg are far more robust. For example, the `pt` command can execute a program and breaks until a return instruction is hit. This ability allows us to step into a function (`t`) and then continue until the function's return. This allows for alot of flexability because with `p`, it simply steps over only one instruction where as `pt` repeatedly steps over instructions until, as stated before, a `ret` instuction is executed. 

