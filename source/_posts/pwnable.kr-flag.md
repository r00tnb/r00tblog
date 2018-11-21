---
title: pwnable.kr-flag
date: 2017-12-09 12:07:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这是一道Linux逆向题，题目很简单，但是对于我这样的新手来说还是纠结了一会儿，嘿嘿~
## 分析
下载下来的程序直接加载到ida中发现没找到main函数，有一个start函数，应该想到程序可能加了壳（当时还傻乎乎的看了半天汇编代码），最想想到的是upx的壳，于是拿到kali下用upx去了一下壳
```
root@kali:~# upx -t flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

testing flag [OK]

Tested 1 file.
root@kali:~# upx -d flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```
然后直接将flag程序加载到gdb中，用`diassemble main`查看main函数的汇编代码
```nasm
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:	push   rbp
   0x0000000000401165 <+1>:	mov    rbp,rsp
   0x0000000000401168 <+4>:	sub    rsp,0x10
   0x000000000040116c <+8>:	mov    edi,0x496658
   0x0000000000401171 <+13>:	call   0x402080 <puts>
   0x0000000000401176 <+18>:	mov    edi,0x64
   0x000000000040117b <+23>:	call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401184 <+32>:	mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
   0x000000000040118b <+39>:	mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040118f <+43>:	mov    rsi,rdx
   0x0000000000401192 <+46>:	mov    rdi,rax
   0x0000000000401195 <+49>:	call   0x400320
   0x000000000040119a <+54>:	mov    eax,0x0
   0x000000000040119f <+59>:	leave  
   0x00000000004011a0 <+60>:	ret    
End of assembler dump.
```
分析汇编代码的逻辑可以知道，程序首先执行put函数输出一句话，这句话在调试时可以看到是`I will malloc() and strcpy the flag there. take it.`,然后调用malloc申请了一段内存，最后执行了一个函数。通过put的一句话知道程序最后会把flag复制到申请的内存中，那么就按照他的意思调试时记住申请的内存地址，等到程序最后在查看。果然flag就在这里
```
gdb-peda$ x/10s 0x6c96b0
0x6c96b0:	"UPX...? sounds like a delivery service :)"
0x6c96da:	""
0x6c96db:	""
0x6c96dc:	""
0x6c96dd:	""
0x6c96de:	""
0x6c96df:	""
0x6c96e0:	""
0x6c96e1:	""
0x6c96e2:	""
```
## 总结
这次做这道题，发现gdb命令用的不熟，Linux的命令也不太熟，这方面要掌握才行。