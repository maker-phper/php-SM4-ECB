# php-SM4-ECB
## SM4-ECB for php5.6.27

工作需要与Java对接国密SM4-ECB，由于生产环境是32位php5.6，苦于网上找不到对的轮子，所以按照Java的示例程序实现了一个

***
__需要安装GMP拓展__

***


使用方法

`
composer require maker-phper/sm4ecb
`


```
require dirname(__FILE__) . '/vendor/autoload.php';

$sm4 = new \Sm4ecb\SM4();

$key = 'FECDD61C0BB7C1E291663BE11AA8106A';
$str = "测试urlaaaaaaaa";

$sm4->SetKey($key);
$backData = $sm4->Encrypt($str);
$data = $sm4->Decrypt($backData);
var_dump($backData) ;
echo "<br>";
var_dump($data) ;
```

性能不是很好，有空优化一下
希望能帮助到你

有一份光，发一份热
