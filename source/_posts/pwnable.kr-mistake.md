---
title: pwnable.kr-mistake
date: 2018-01-17 20:33:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这题其实考察细心，不难。
## 分析
还是先贴代码
```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}

```
题目逻辑很简单，只要从`password`文件中读取的数据跟输入的数据的异或加密后的结果相等，就会得到flag。
但是整个逻辑如果不细心，就不会发现错误，就真的如我上面所想像的逻辑了。
根据题目提示：运算符优先级。可以看到open函数直接跟小于号与零比较，由于c语言中小于号优先级高于赋值的等号，又由于这里open函数会返回大于零的值，那么先进行比较运算返回逻辑假值，在c语言中就是0，所以fd的值就是0。
知道了这些，那么后面的read调用就会从标准输入中读取值，那么两个值就都在控制之中了，于是就能getflag了。要注意第二次输入要进行异或加密。
```PowerShell
mistake@ubuntu:~$ ./mistake 
do not bruteforce...
1234567890
input password : 0325476981
Password OK
Mommy, the operator priority always confuses me :(
mistake@ubuntu:~$ 
```
## 总结
这题当时纠结了一会儿，确实要细心，安全漏洞总会发生在最容易忽略的地方，要时刻保持细心。