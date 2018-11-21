---
title: pwnable.kr--fd
date: 2017-12-06 20:28:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
最近在做[pwnable.kr](http://pwnable.kr)上的题目，本来也是新手就准备把解题的思路写下来加深印象。
这是第一题，较简单，题目很基础。
## 分析
先看一下都有什么文件
```
fd@ubuntu:~$ ls -l
total 16
-r-sr-x--- 1 fd_pwn fd   7322 Jun 11  2014 fd
-rw-r--r-- 1 root   root  418 Jun 11  2014 fd.c
-r--r----- 1 fd_pwn root   50 Jun 11  2014 flag

```
由于没权限访问`flag`文件，看来只有通过`fd`程序的执行来查看了，这里`fd.c`是源码
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}

```
通过分析源码发现，只要控制使第一个参数为`0x1234`然后`fd=0`再输入`LETMEWIN\n`就可以执行查看flag的命令了。操作一下确实是这样的
```
fd@ubuntu:~$ ./fd `python -c 'print 0x1234'`
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!

```
## 总结
这道题考察基本的Linux文件操作，适合我这样的萌新,哈哈。