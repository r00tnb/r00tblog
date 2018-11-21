---
title: pwnable.kr-random
date: 2017-12-10 21:33:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 分析
还是先分析源码
```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}

```
程序先是使用rand函数产生一个随机数然后和输入的一个整数进行异或，如果结果等于`0xdeadbeef`则getflag。
显然rand函数前没有设置随机种子，所以每次程序启动random的值都是不变的，于是只要获得random的值然后和`0xdeadbeef`异或就能得到应该输入的整数了。
```nasm
Dump of assembler code for function main:
   0x00000000004005f4 <+0>:	push   %rbp
   0x00000000004005f5 <+1>:	mov    %rsp,%rbp
   0x00000000004005f8 <+4>:	sub    $0x10,%rsp
   0x00000000004005fc <+8>:	mov    $0x0,%eax
   0x0000000000400601 <+13>:	callq  0x400500 <rand@plt>
   0x0000000000400606 <+18>:	mov    %eax,-0x4(%rbp)
=> 0x0000000000400609 <+21>:	movl   $0x0,-0x8(%rbp)
   0x0000000000400610 <+28>:	mov    $0x400760,%eax
   0x0000000000400615 <+33>:	lea    -0x8(%rbp),%rdx
   0x0000000000400619 <+37>:	mov    %rdx,%rsi
   0x000000000040061c <+40>:	mov    %rax,%rdi
   0x000000000040061f <+43>:	mov    $0x0,%eax
   0x0000000000400624 <+48>:	callq  0x4004f0 <__isoc99_scanf@plt>
   0x0000000000400629 <+53>:	mov    -0x8(%rbp),%eax
   0x000000000040062c <+56>:	xor    -0x4(%rbp),%eax
   0x000000000040062f <+59>:	cmp    $0xdeadbeef,%eax
   0x0000000000400634 <+64>:	jne    0x400656 <main+98>
   0x0000000000400636 <+66>:	mov    $0x400763,%edi
   0x000000000040063b <+71>:	callq  0x4004c0 <puts@plt>
   0x0000000000400640 <+76>:	mov    $0x400769,%edi
   0x0000000000400645 <+81>:	mov    $0x0,%eax
   0x000000000040064a <+86>:	callq  0x4004d0 <system@plt>
---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) i r
rax            0x6b8b4567	1804289383
rbx            0x0	0
rcx            0x7f6b1fb420a4	140098070126756
rdx            0x7f6b1fb420a8	140098070126760
rsi            0x7ffed4bf634c	140732467733324
rdi            0x7f6b1fb42620	140098070128160
rbp            0x7ffed4bf6380	0x7ffed4bf6380
```
上面是题目平台中使用gdb调试获的信息，可以看出`random=rax=0x6b8b4567`。
于是`payload=random ^ 0xdeadbeef=0xb526fb88=3039230856`
```
random@ubuntu:~$ echo 3039230856 | ./random
Good!
Mommy, I thought libc random is unpredictable...
```