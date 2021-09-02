<?php
// Bytes 类
class Bytes
{
    /**
     * 转换一个String字符串为byte数组
     */
    public static function getBytes($str)
    {

        $len = strlen($str);
        $bytes = [];
        for ($i = 0; $i < $len; $i++) {
            if (ord($str[$i]) >= 128) {
                $byte = ord($str[$i]) - 256;
            } else {
                $byte = ord($str[$i]);
            }
            $bytes[] = $byte;
        }
        return $bytes;
    }

    /**
     * 将字节数组转化为String类型的数据
     */
    public static function toStr($bytes)
    {
        $str = '';
        foreach ($bytes as $ch) {
            $str .= chr($ch);
        }
        return $str;
    }

    /**
     * 将数字转换为字节
     */
    public function toByte($num) //$num 可以传数字
    {
        $num = decbin($num);  //decbin 是php自带的函数，可以把十进制数字转换为二进制
        $num = substr($num, -8); //取后8位
        $num = str_pad($num, 8, "0", STR_PAD_LEFT);
        $sign = substr($num, 0, 1); //截取 第一位 也就是高位，用来判断到底是负的还是正的
        if ($sign == 1)  //高位是1 代表是负数 ,则要减去256
        {
            return bindec($num) - 256; //bindec 也是php自带的函数，可以把二进制数转为十进制
        } else {
            return bindec($num);
        }
    }
}
