---
layout: default
---

# Resources

[Return to Home](./index.md)

Here is a list of curated resources that cover various aspects of Windows security research:


## Recommended Blogs

* [Marcus Hutchins' Blog](https://malwaretech.com/)
* [Tavis Ormandy's Blog](https://lock.cmpxchg8b.com/)
* [Robel Campbell's Blog](https://reverencecyber.com/blog/)
* [Connor McGarr's Blog](https://connormcgarr.github.io/)
* [Spaceraccoon's Blog](https://spaceraccoon.dev/)
* [Richard Osgood's Blog](https://www.richardosgood.com/)
* [Yarden Shafir's Blog](https://medium.com/@yardenshafir2)
* [Hashim Jawad's Blog](https://ihack4falafel.github.io/)
* [DHN's Blog](https://zer0-day.pw/)
* [Project Zero's Blog](https://googleprojectzero.blogspot.com/)


## Recommended Repositories

* [Morten Schenk's GitHub](https://github.com/MortenSchenk)
* [Tavis Ormandy's GitHub](https://github.com/taviso)


## Technical Deep-Dives


### Windows Mitigation Bypasses and Analysis

* [IRQLs Close Encounters of the Rootkit Kind](https://www.offsec.com/offsec/irqls-close-encounters/) by OffSec
* [Windows Exploitation Tricks: Trapping Virtual Memory Access](https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html) by James Forshaw
* [Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html) by James Forshaw
* [Discovery and analysis of a Windows PhoneBook Use-After-Free vulnerability (CVE-2020-1530)](https://symeonp.github.io/2020/12/08/phonebook-uaf-analysis.html) by Symeon
* [itsec stuff about fuzzing, vuln hunting and (hopefully) exploitation!](https://symeonp.github.io/) by Symeon
* [Part 19: Kernel Exploitation -> Logic bugs in Razer rzpnk.sys](https://fuzzysecurity.com/tutorials/expDev/23.html) by Fuzzy Security
* [I Got 99 Problem But a Kernel Pointer Ain't One](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf) by Alex Ionescu
* [Windows Code Injection: Bypassing CIG Through KnownDlls](https://www.tiraniddo.dev/2019/08/windows-code-injection-bypassing-cig.html?m=1) by Tyranid's Lair


#### Intel CET

* [Bypassing Intel CET with Counterfeit Objects](https://www.offsec.com/offsec/bypassing-intel-cet-with-counterfeit-objects/) by Matteo Malvica
* [Intel CET in Action](https://www.offsec.com/offsec/intel-cet-in-action/) by OffSec


#### Windows Defender Exploit Guard (Previously EMET)

* [eXtended Flow Guard Under The Microscope](https://www.offsec.com/offsec/extended-flow-guard/) by OffSec
* [Disarming EMET v5.0](https://www.offsec.com/vulndev/disarming-emet-v5-0/) by Matteo Memelli
* [Disarming Enhanced Mitigation Experience Toolkit (EMET)](https://www.offsec.com/vulndev/disarming-enhanced-mitigation-experience-toolkit-emet/) by Matteo Memelli
* [Bypassing Control Flow Guard in Windows 10 - Part II](https://blog.improsec.com/tech-blog/bypassing-control-flow-guard-on-windows-10-part-ii) by Morten Schenk


### Just-in-Time Compilation

> Note: Some of these blog posts are iOS-related, but since JIT is used in Windows applications, I have included them here.

* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 1)](https://connormcgarr.github.io/type-confusion-part-1/) by Connor McGarr
* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 2)](https://connormcgarr.github.io/type-confusion-part-2/) by Connor McGarr
* [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 3)](https://connormcgarr.github.io/type-confusion-part-3/) by Connor McGarr
* [Understanding the Risk in the Unintended Giant: JavaScript](https://www.zerodayinitiative.com/blog/2017/7/18/understanding-risk-in-the-unintended-giant-javascript) by Simon Zuckerbraun
* [Check It Out: Enforcement of Bounds Checks in Native JIT Code](https://www.zerodayinitiative.com/blog/2017/10/5/check-it-out-enforcement-of-bounds-checks-in-native-jit-code) by Simon Zuckerbraun
* [Floating-Poison Math in Chakra](https://www.zerodayinitiative.com/blog/2018/8/22/floating-poison-math-in-chakra) by Simon Zuckerbraun
* [Bypassing Mitigations by Attacking JIT Server in Microsoft Edge](https://googleprojectzero.blogspot.com/2018/05/bypassing-mitigations-by-attacking-jit.html) by Ivan Fratric
* [JITSploitation I: A JIT Bug](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-one.html) by Samuel Groß
* [JITSploitation II: Getting Read/Write](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-two.html) by Samuel Groß
* [JITSploitation III: Subverting Control Flow](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-three.html) by Samuel Groß


### Hyper-V

* [First Steps in Hyper-V Research](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/) by Microsoft
* [Fuzzing para-virtualized devices in Hyper-V](https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/) by Microsoft


### WinDbg

* [My WinDbg Blog](./windows/WinDbg.md)


### Fuzzing

* [Gamozo Labs' Blog](https://gamozolabs.github.io/)
* [Google Project Zero's WinAFL](https://github.com/googleprojectzero/winafl)
* [SafeBreach & Guardicore Labs' hAFL1](https://github.com/SB-GC-Labs/hAFL1)


### Presentations and Walkthroughs

* [The Info Leak Era on Software Exploitation](https://www.youtube.com/watch?v=VgWoPa8Whmc) by Fermin J. Serna
* [Windows 10 Mitigation Improvements](https://www.youtube.com/watch?v=gCu2GQd0GSE) by David Weston and Matt Miller
* [Windows 10 Segment Heap Internals](https://www.youtube.com/watch?v=hetZx78SQ_A) by Mark Vincent Yason
* [Taking Windows 10 Kernel Exploitation to the next level](https://www.youtube.com/watch?v=Gu_5kkErQ6Y) by Morten Schenk
* [PowerShell as an attack platform](https://www.youtube.com/watch?v=MOab2Icpecc) by Morten Schenk
* [Data-Only Pwning Microsoft Windows Kernel](https://www.youtube.com/watch?v=FxZoAupttMI) by Nikita Tarakanov
* [Advanced Heap Manipulation in Windows 8](https://www.youtube.com/watch?v=0lURSnDOPfQ) by Zhenhua Liu
* [Demystifying Windows Kernel Exploitation by Abusing GDI Objects](https://www.youtube.com/watch?v=2chDv_wTymc) by Saif El Sherei
* [Exploiting Hardcore Pool Corruptions in MS Windows Kernel](https://www.youtube.com/watch?v=2yuza8PRGVQ) by Nikita Tarakanov
* [Windows kernel exploitation techniques](https://www.youtube.com/watch?v=f8hTwFpRphU) by Adrien Garin
* [Practical Windows Kernel Exploitation](https://www.youtube.com/watch?v=hUCmV7uT29I) by Spencer McIntyre
* [Over The Edge: Pwning The Windows Kernel](https://www.youtube.com/watch?v=0tFmqSbWSZE) by Rancho Han
* [Theres a party at ring0](https://www.youtube.com/watch?v=BCavCemZPoI) by Tavis Ormandy and Julien Tinnes
* [Extreme Privilege Escalation On Windows 8 UEFI Systems](https://www.youtube.com/watch?v=Qj_YCpoct3k) by Corey Kallenberg, Xeno Kovah, John Butterworth, and Sam Cornwell
* [Windows privilege escalation using 3rd party services](https://www.youtube.com/watch?v=nRVbYt9LKXk) by Kacper Szurek
* [Practical Windows Privilege Escalation](https://www.youtube.com/watch?v=PC_iMqiuIRQ) by Andrew Smith
* [Windows Kernel Vulnerability Research and Exploitation](https://www.youtube.com/watch?v=aRZ5Wi-NWXs) by Gilad Bakas
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 1](https://www.youtube.com/watch?v=pJZjWXxUEl4) by OJ Reeves
* [Hackingz Ze Komputerz - Exploiting CAPCOM.SYS Part 2](https://www.youtube.com/watch?v=UGWqq5kTiso) by OJ Reeves
* [ROP mitigations and Control Flow Guard - the end of code reuse attacks?](https://www.youtube.com/watch?v=pqU9jsCmlYA) by Matthias Ganz 
* [Building Windows Kernel Fuzzer](https://www.youtube.com/watch?v=mpXQvto4Vy4) by Jaanus Kääp


## Books

* [Windows Kernel Programming](https://www.amazon.com/Windows-Kernel-Programming-Pavel-Yosifovich/dp/1977593372) by Pavel Yosifovich
* [Windows Internals, Part 1: System architecture, processes, threads, memory management, and more, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188) by Pavel Yosifovich, Mark E. Russinovich, Alex Ionescu, David A. Solomon
* [Windows Internals, Part 2, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409) by Andrea Allievi, Mark E. Russinovich, Alex Ionescu, David A. Solomon
* [What Makes it Page? The Windows 7 (x64) Virtual Memory Manager](https://www.amazon.com/What-Makes-Page-Windows-Virtual/dp/1479114294) by Enrico Martignetti


## Courses

* [EXP-301](https://www.offsec.com/documentation/EXP301-syllabus.pdf) by OffSec
* [EXP-401](https://www.offensive-security.com/awe/EXP401_syllabus.pdf) by OffSec
* [Windows Internal Architecture](https://codemachine.com/trainings/winint.html) by CodeMachine
* [Windows Malware Techniques](https://codemachine.com/trainings/winmal.html) by CodeMachine
* [Windows Kernel Internals](https://codemachine.com/trainings/kerint.html) by CodeMachine
* [Windows Kernel Rootkits](https://codemachine.com/trainings/kerrkt.html) by CodeMachine
* [SEC760: Advanced Exploit Development for Penetration Testers](https://www.sans.org/cyber-security-courses/advanced-exploit-development-penetration-testers/) by OffSec
* [Corelan Advanced - Heap Exploitation](https://www.corelan-training.com/index.php/training/advanced/) by Corelan
* [Corelan Bootcamp - Stack Exploitation](https://www.corelan-training.com/index.php/training/bootcamp/) by Corelan