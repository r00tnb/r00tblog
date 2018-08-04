---
title: pwnable.kr-memcpy
date: 2018-02-13 14:43:00
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
这道题还是参考了别人的writeup，学到了内存对齐的知识。
# 分析
先分析源代码`memcpy.c`
```c
// compiled with : gcc -o memcpy memcpy.c -m32 -lm
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

unsigned long long rdtsc(){
        asm("rdtsc");
}

char* slow_memcpy(char* dest, const char* src, size_t len){
	int i;
	for (i=0; i<len; i++) {
		dest[i] = src[i];
	}
	return dest;
}

char* fast_memcpy(char* dest, const char* src, size_t len){
	size_t i;
	// 64-byte block fast copy
	if(len >= 64){
		i = len / 64;
		len &= (64-1);
		while(i-- > 0){
			__asm__ __volatile__ (
			"movdqa (%0), %%xmm0\n"
			"movdqa 16(%0), %%xmm1\n"
			"movdqa 32(%0), %%xmm2\n"
			"movdqa 48(%0), %%xmm3\n"
			"movntps %%xmm0, (%1)\n"
			"movntps %%xmm1, 16(%1)\n"
			"movntps %%xmm2, 32(%1)\n"
			"movntps %%xmm3, 48(%1)\n"
			::"r"(src),"r"(dest):"memory");
			dest += 64;
			src += 64;
		}
	}

	// byte-to-byte slow copy
	if(len) slow_memcpy(dest, src, len);
	return dest;
}

int main(void){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Hey, I have a boring assignment for CS class.. :(\n");
	printf("The assignment is simple.\n");

	printf("-----------------------------------------------------\n");
	printf("- What is the best implementation of memcpy?        -\n");
	printf("- 1. implement your own slow/fast version of memcpy -\n");
	printf("- 2. compare them with various size of data         -\n");
	printf("- 3. conclude your experiment and submit report     -\n");
	printf("-----------------------------------------------------\n");

	printf("This time, just help me out with my experiment and get flag\n");
	printf("No fancy hacking, I promise :D\n");

	unsigned long long t1, t2;
	int e;
	char* src;
	char* dest;
	unsigned int low, high;
	unsigned int size;
	// allocate memory
	char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	size_t sizes[10];
	int i=0;

	// setup experiment parameters
	for(e=4; e<14; e++){	// 2^13 = 8K
		low = pow(2,e-1);
		high = pow(2,e);
		printf("specify the memcpy amount between %d ~ %d : ", low, high);
		scanf("%d", &size);
		if( size < low || size > high ){
			printf("don't mess with the experiment.\n");
			exit(0);
		}
		sizes[i++] = size;
	}

	sleep(1);
	printf("ok, lets run the experiment with your configuration\n");
	sleep(1);

	// run experiment
	for(i=0; i<10; i++){
		size = sizes[i];
		printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
		dest = malloc( size );

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		slow_memcpy(dest, src, size);		// byte-to-byte memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		fast_memcpy(dest, src, size);		// block-to-block memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
		printf("\n");
	}

	printf("thanks for helping my experiment!\n");
	printf("flag : ----- erased in this source code -----\n");
	return 0;
}

```
程序的大概逻辑是比较两个内存复制算法`slow_memcpy`和`fast_memcpy`的效率。其中，程序要求输入10次要分配的内存大小，每次大小都限定在两个相邻的2的幂次之间，并且使用`malloc`函数来分配内存，如果所有步骤执行完毕程序会在最后输出flag。
先是按照要求跑一遍程序，发现程序最后会在某一次比较中突然停下，也就是说程序异常退出了。当时真不知道咋回事，也没有自己编译调试程序，于是便参考了人家的writeup，并有了思路。
- `fast_memcpy`函数中用于内存复制的两个指令`movdqa`和`movntps`他们的操作数如果是内存地址的话，那么这个地址必须是16字节对齐的，否则会产生一般保护性异常导致程序退出。
- `malloc`在分配内存时它实际上还会多分配4字节用于存储堆块信息，所以如果分配a字节实际上分配的是`a+4`字节。另外32位系统上该函数分配的内存是以8字节对齐的。

有了这两点就知道程序的异常退出是因为分配的内存没有16字节对齐，那么要getflag只需要每次分配的内存地址能够被16整除就可以了（实际上由于`malloc`函数分配的内存8字节对齐，只要内存大小除以16的余数大于9就可以了）。下面贴出exp
```python
from socket import *
import time

def work():
    host = 'pwnable.kr'
    port = 9022
    
    sock = socket(AF_INET,SOCK_STREAM)
    sock.connect((host,port))
    
    print sock.recv(100)
    for i in xrange(4,14):
        tmp = 2**i-4
        print sock.recv(1024),tmp
        time.sleep(1)
        sock.send(str(tmp)+'\n')
        
    while True:
        r = sock.recv(1024)
        if r:
            print r
            time.sleep(0.5)
        else:
            break

work()
```
```bash
C:\Users\admin\Desktop>python 2.py
Hey, I have a boring assignment for CS class.. :(

The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 :  12
specify the memcpy amount between 16 ~ 32 :  28
specify the memcpy amount between 32 ~ 64 :  60
specify the memcpy amount between 64 ~ 128 :  124
specify the memcpy amount between 128 ~ 256 :  252
specify the memcpy amount between 256 ~ 512 :  508
specify the memcpy amount between 512 ~ 1024 :  1020
specify the memcpy amount between 1024 ~ 2048 :  2044
specify the memcpy amount between 2048 ~ 4096 :  4092
specify the memcpy amount between 4096 ~ 8192 :  8188
ok, lets run the experiment with your configuration


experiment 1 : memcpy with buffer size 12
ellapsed CPU cycles for slow_memcpy : 1251
ellapsed CPU cycles for fast_memcpy : 420

experiment 2 : memcpy with buffer size 28
ellapsed CPU cycles for slow_memcpy : 414
ellapsed CPU cycles for fast_memcpy : 405

experiment 3 : memcpy with buffer size 60
ellapsed CPU cycles for slow_memcpy : 795
ellapsed CPU cycles for fast_memcpy : 759

experiment 4 : memcpy with buffer size 124
ellapsed CPU cycles for slow_memcpy : 1539
ellapsed CPU cycles for fast_memcpy : 807

experiment 5 : memcpy with buffer size 252
ellapsed CPU cycles for slow_memcpy : 3054
ellapsed CPU cycles for fast_memcpy : 825

experiment 6 : memcpy with buffer size 508
ellapsed CPU cycles for slow_memcpy : 6147
ellapsed CPU cycles for fast_memcpy : 879

experiment 7 : memcpy with buffer size 1020
ellapsed CPU cycles for slow_memcpy : 12384
ellapsed CPU cycles for fast_memcpy : 999

experiment 8 : memcpy with buffer size 2044
ellapsed CPU cycles for slow_memcpy : 24120
ellapsed CPU cycles for fast_memcpy
: 1389

experiment 9 : memcpy with buffer size 4092
ellapsed CPU cycles for slow_memcpy : 50781
ellapsed CPU cycles for fast_memcpy : 2184

experiment 10 : memcpy with buffer size 8188
ellapsed CPU cycles for slow_memcpy : 105690
ellapsed CPU cycles for fast_memcpy : 3801

thanks for helping my experiment!
flag : 1_w4nn4_br34K_th3_m3m0ry_4lignm3nt


C:\Users\admin\Desktop>
```
# 总结
通过这道题又学习到了新知识。学到了两个命令，以及32位系统上`malloc`函数分配时另加4字节的堆块信息内存8字节对齐。