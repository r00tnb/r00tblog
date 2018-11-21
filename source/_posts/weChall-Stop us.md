---
title: weChall-Stop us
date: 2017-12-16 13:50:00
tags: [WEB]
categories: CTF
copyright: true
---
## 前言
好吧，我承认这道题我完全没有任何头绪T_T。看了别人的writeup才做出来的，再次让我佩服php语言的博大精深！！！
## 分析
先贴源码
```php
<?php
/**
 * noothworx proudly presents a secure shop for domain selling!
 */
# Disable output buffering
if (ob_get_level() > 0) ob_end_clean();
apache_setenv('no-gzip', 1);
ini_set('zlib.output_compression', 0);

# The core and init
chdir('../../../');
$_GET['mo'] = 'WeChall';
$_GET['me'] = 'Challenge';
$cwd = getcwd();
require_once 'protected/config.php';
require_once '../gwf3.class.php';
$gwf = new GWF3($cwd, array(
	'website_init' => true,
	'autoload_modules' => true,
	'load_module' => true,
	'get_user' => true,
	'do_logging' => true,
	'blocking' => false,
	'no_session' => false,
	'store_last_url' => true,
	'ignore_user_abort' => false,
));

# Need noothtable!
require_once 'challenge/noother/stop_us/noothtable.php';

# Get challenge
define('GWF_PAGE_TITLE', 'Stop us');
if (false === ($chall = WC_Challenge::getByTitle(GWF_PAGE_TITLE)))
{
	$chall = WC_Challenge::dummyChallenge(GWF_PAGE_TITLE, 3, 'challenge/noother/stop_us/index.php', false);
}

$price = 10.00; # Price for a domain.
$user = GWF_User::getStaticOrGuest();
$sid = GWF_Session::getSession()->getID();
noothtable::initNoothworks($sid); # init domain stuff.
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<title>[WeChall] noother-Domain.com</title>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta http-equiv="Content-Language" content="en" />
	<meta name="robots" content="index, follow" />
	<meta name="keywords" content="wechall, challenge, stopus, stop us, stop_us" />
	<meta name="description" content="noother-domain.com is a fictional service selling .xyz domains. It is a hacking challenge on wechall." />
	<link rel="shortcut icon" href="/favicon.ico" />
	<link rel="stylesheet" type="text/css" href="/tpl/default/css/gwf3.css?v=9" />
	<link rel="stylesheet" type="text/css" href="/tpl/wc4/css/wechall4.css?v=9a" />
</head>
<body>
	<h1><a href="nootherdomain.php">noother-domains.com</a> (powered by <a href="/challenge/noother/stop_us/index.php">WeChall</a>)</h1>
	
<?php
if (Common::getGetString('load') === 'balance')
{
	if (noother_timeout($sid) === false)
	{
		nooth_message('Checking your credit card ...');
		nooth_message('Uploading $10.00 ...');
		# +10 money and +1 funding
		noothtable::increaseMoney($sid, 10);
		nooth_message(sprintf('Your account balance is now $%.02f.<br/>Thank you for using noother-domains.com!', noothtable::getMoney($sid)));
	}
}

if (Common::getGetString('purchase') === 'domain')
{
	if (noother_timeout($sid) === false)
	{
		nooth_message('Checking your balance ...');
		nooth_message(sprintf('Your balance is $%.02f ...', noothtable::getMoney($sid)));
		if (noothtable::getMoney($sid) >= $price)
		{
			nooth_message('Balance ok!');
	
			# TODO: Do checks more checks!
			nooth_message('Checking availability of your domain ...');
			nooth_message('Domain is available ...');
			
			# +1 domain
			if (false === noothtable::purchaseDomain($sid))
			{
				die('Hacking attempt!');
			}
			nooth_message('Purchasing ...');
			nooth_message('Domain purchased.');
			
			# -$10.00
			nooth_message('Reducing your balance ...');
			noothtable::reduceMoney($sid, $price);
			nooth_message('Thank you for your purchase!');
	
			# Done!
			nooth_message('Purchased!');
			
			# Something weird? Oo
			if (noothtable::getFundings($sid) < noothtable::getDomains($sid))
			{
				GWF_Module::loadModuleDB('Forum', true, true);
				# Get here, hacker!
				$chall->onChallengeSolved(GWF_Session::getUserID());
			}
			nooth_message('Thank you for using noother-domains.com!');
		}
		else
		{
			nooth_message('Insufficient funds!');
		}
	}
}

# The page!
?>
<div>
	<div>Username: <?php echo $user->displayUsername(); ?></div>
	<div>Balance: <?php printf('$%.02f', noothtable::getMoney($sid)); ?></div>
	<div>Domains: <?php echo noothtable::getDomains($sid); ?></div>
	<div><a href="nootherdomain.php?load=balance">Upload money</a>(<?php echo noothtable::getFundings($sid); ?>)</div>
	<div><a href="nootherdomain.php?purchase=domain">Purchase domain</a></div>
</div>
</body>
<?php
########################
### Helper functions ###
########################
function noother_timeout($sid)
{
	$wait = noothtable::checkTimeout($sid, time());
	if ($wait >= 0)
	{
		nooth_message(sprintf('Please wait %s until the next transaction.', GWF_Time::humanDuration(45)));
		return true;
	}
	return false;
}

function nooth_message($message, $sleep=2)
{
	echo sprintf('<div>%s</div>', $message).PHP_EOL;
	flush();
	sleep($sleep);
}
?>
```
整个程序的功能就是一个简单的域名购买。开始你是没有钱的，先得用经费充钱一次只有10美元，然后买一个域名也只要10美元。所以使用经费的次数肯定大于或等于购买的域名个数。然而要getflag必须反过来。。。
看了半天程序实在想不出来有啥绕过方法，于是我就知道了肯定这道题触及了我的知识盲区T_T。于是果断搜索别人的writeup。[这是人家的writeup](http://http://blog.csdn.net/qq_35078631/article/details/77512274)
## 知识点
原来是这个`ignore_user_abort`搞的鬼，原来真没见过。
```php
ignore_user_abort(setting);
setting:可选。如果设置为 true，则忽略与用户的断开，如果设置为 false，会导致脚本停止运行。如果未设置该参数，会返回当前的设置。
注释：PHP 不会检测到用户是否已断开连接，直到尝试向客户机发送信息为止。简单地使用 echo 语句无法确保信息发送，参阅 flush() 函数。
```
## 解决
看了知识点，再结合源码中`ignore_user_abort`设置了false（当时真没注意），`nooth_message`函数中有flush函数（当时还纳闷儿调用这个函数干嘛），就知道了解法。由于域名是在购买之后再将手上的钱减少的，所以如果在这两个操作之间用户断开的话，那么脚本终止执行，于是手上的钱就不会扣掉了，于是就能getflag了。