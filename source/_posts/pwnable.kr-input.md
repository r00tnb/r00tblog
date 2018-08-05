---
title: pwnable.kr-input
date: 2018-01-12 11:01:00
tags: [pwnable.kr,PWN]
categories: CTF
copyright: true
---
## 前言
这道题对于我来说挺麻烦，整个题目分了五个阶段，涉及进程通信，socket等内容。对，就是考察linux基础的，但是我得承认我对这些不熟，所以还是查了半天资料做出来的，最后题目还有个大坑。
## 分析
首先还是分析源码
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}

```
整个程序先是检验main函数传入参数，环境变量。然后读取0和2文件描述符内容进行比较，之后读取`\x0a`这样的看似特殊的文件有进行一番比较，最后设置了一个socket服务端等待连接读取数据再进行比较。
总共五步，我只简要的分析，懂得linux基础的并不难。
对于传入参数和环境变量，可以直接使用`execve`函数来构造，它的原型是
```c
int execve(const char* filepath,char* const argv[],char* const envp[]);
返回值：当执行成功时不返回，失败返回-1
```
对于读取指定文件描述符，可以使用管道与新建进程通信，同时记得使用`dup2`函数重定向到指定文件描述符。
对于特殊文件名文件，直接新建一个就好了并不特殊。
对于socket，自己建一个客户端连上去并发送指定数据。
最后，会发现我写的exp咋不能传上去。是的，你没有权限，但是可以传到`/tmp`文件夹下，这个文件夹默认任何用户可读写。然后还要使用`ln`命令建立一个到`～/flag`的链接，不然读不到`flag`。
最后的最后附上解决代码：
```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>

extern int errno;
int main(){
    //argv
    char* argv[101]={"~/input2",[1 ... 99]="A",NULL};
    argv['A'] = "\x00";
    argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "1314";
    

    //env
    char* env[]={"\xde\xad\xbe\xef=\xca\xfe\xba\xbe",NULL};

    //File
    FILE* fp = fopen("\x0a","w");
    if(!fp){
        puts("file open failed!");
        return 0;
    }
    fwrite("\x00\x00\x00\x00",4,1,fp);
    fclose(fp);

    //stdio.h
    int fd[2];
    pid_t pid;
    if(pipe(fd)<0){
        printf("pipe error!\n");
        return 0;
    }
    write(fd[1],"\x00\x0a\x00\xff\x00\x0a\x02\xff",8);
    pid = fork();
    if(pid<0) return 0;
    if(pid == 0){
        dup2(fd[0],0);
        dup2(fd[0],2);
        printf("exec working!\n");
        if(-1 == execve("/home/input2/input",argv,env)){
            puts("exec error!");
        }
    }
    else{
        sleep(3);
        int sock;
        struct sockaddr_in addr;
        sock = socket(AF_INET,SOCK_STREAM,0);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(atoi(argv['C']));
        connect(sock,(struct sockaddr*)&addr,sizeof(addr));
        write(sock,"\xde\xad\xbe\xef",4);
        close(sock);
        sleep(1);
    }
    return 0;
}
```
## 插曲
按照我的想法，应该就可以高高兴兴的拿到`flag`了啊。可是却出现了意外：
```Powershell
input2@ubuntu:~$ cd /tmp
input2@ubuntu:/tmp$ ln -s ~/flag flag
input2@ubuntu:/tmp$ ./poc
-bash: ./poc: No such file or directory
input2@ubuntu:/tmp$ ./poc
exec working!
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
Stage 5 clear!
input2@ubuntu:/tmp$ 
```
什么？全部通关竟然不给`flag`？这就是我前面提到的大坑了。后来实在想不明白，看了别人的flag，我草，他们竟然在`/tmp/input/`目录里搞得，有着目录吗？还真有
```Powershell
input2@ubuntu:/tmp$ ls input
?  coin1.py  err_file  file  fla  flag	poc  solve.py  $’x0a’
input2@ubuntu:/tmp$ 
```
于是就能getflag了（事先一点线索都没有啊）
```Powershell
input2@ubuntu:/tmp/input$ ./poc
exec working!
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
Stage 5 clear!
Mommy! I learned how to pass various input in Linux :)
input2@ubuntu:/tmp/input$ 
```
## 总结
这道题把linux中基础且重要的东西融合在一起（有点生硬），考的我措手不及马上复习了一下，挺好的。推荐我读的书《UNIX系统编程手册 ((德)Michael Kerrisk) 》