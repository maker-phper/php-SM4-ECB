<?php
require_once 'F:\PHPStudy\PHPTutorial\WWW/SM4/Bytes.php';

class SM4
{
    private $CK = array(
        '0x00070e15', '0x1c232a31', '0x383f464d', '0x545b6269',
        '0x70777e85', '0x8c939aa1', '0xa8afb6bd', '0xc4cbd2d9',
        '0xe0e7eef5', '0xfc030a11', '0x181f262d', '0x343b4249',
        '0x50575e65', '0x6c737a81', '0x888f969d', '0xa4abb2b9',
        '0xc0c7ced5', '0xdce3eaf1', '0xf8ff060d', '0x141b2229',
        '0x30373e45', '0x4c535a61', '0x686f767d', '0x848b9299',
        '0xa0a7aeb5', '0xbcc3cad1', '0xd8dfe6ed', '0xf4fb0209',
        '0x10171e25', '0x2c333a41', '0x484f565d', '0x646b7279'
    );

    public $SboxTable = [
        [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05],
        [0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
        [0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62],
        [0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6],
        [0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8],
        [0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35],
        [0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87],
        [0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e],
        [0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1],
        [0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3],
        [0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f],
        [0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51],
        [0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8],
        [0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0],
        [0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84],
        [0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]
    ];

    public function __construct(){
        try{
            if(!extension_loaded('gmp')){
                throw new Exception("缺少gmp拓展");
            }
        }catch(Exception $ex){
            echo $ex->getMessage();
            die;
        }
    }

    private $FK = array('0xA3B1BAC6', '0x56AA3350', '0x677D9197', '0xB27022DC');

    //系统参数4：SK，32个32位无符号整数，子密钥
    private $SK;

    //缺省16字节的密钥
    private $KEY;

    /*内部函数*/
    private function BYTE8($x)
    {
        $temp = gmp_and($x, '0xFF');
        return gmp_strval($temp, '10');
    }

    private function rotl($x, $n)
    {

        $r1 = $this->gmp_shiftl($x, $n);
        $r1 = gmp_strval($r1, '10');
        $r2 = $this->gmp_shiftr($x, (32 - $n));
        $r2 = gmp_strval($r2, '10');
        $r = gmp_xor($r1, $r2);
        $r = gmp_strval($r, '10');

        return $r;
    }

    private function gmp_shiftl($x, $n)
    { // shift left
        return (gmp_mul($x, gmp_pow(2, $n)));
    }

    private function gmp_shiftr($x, $n)
    { // shift right
        return (gmp_div($x, gmp_pow(2, $n)));
    }

    private function get_ulong_be($b, $i)
    {
        $temp = array();
        $b[$i] = gmp_and($b[$i], '0xff');
        $b[$i + 1] = gmp_and($b[$i + 1], '0xff');
        $b[$i + 2] = gmp_and($b[$i + 2], '0xff');
        $b[$i + 3] = gmp_and($b[$i + 3], '0xff');

        $temp[0] = $this->gmp_shiftl($b[$i], 24);
        $temp[1] = $this->gmp_shiftl($b[$i + 1], 16);
        $temp[2] = $this->gmp_shiftl($b[$i + 2], 8);
        $temp[3] = $b[$i + 3];

        for ($i = 0; $i < 3; $i++) {
            $temp[$i + 1] = gmp_or($temp[$i], $temp[$i + 1]);
            $result = $temp[$i + 1];
        }

        $result = gmp_strval($temp[3], 10);
        unset($temp);
        return $result;
    }

    private function put_ulong_be($n, $i)
    {
        $temp = gmp_and($n, '0xFFFFFFFF');
        $b[$i] = $this->BYTE8(gmp_strval($this->gmp_shiftr($temp, 24), '10'));
        $b[$i + 1] = $this->BYTE8(gmp_strval($this->gmp_shiftr($temp, 16), '10'));
        $b[$i + 2] = $this->BYTE8(gmp_strval($this->gmp_shiftr($temp, 8), '10'));
        $b[$i + 3] = $this->BYTE8(gmp_strval($temp, '10'));

        return $b;
    }

    private function sm4Sbox($inch)
    {
        $inch = gmp_intval($inch);
        $r = gmp_strval(gmp_and($inch, '0xff'));
        $h = gmp_strval(gmp_and($inch, '0xff'));
        $r = $r / 16;
        $h = $h % 16;
        return $this->SboxTable[$r][$h];
    }

    private function sm4Lt($ka)
    {
        $a = array();
        $b = array();

        $ka = gmp_strval($ka, '10');
        $a = $this->put_ulong_be($ka, 0);
        $b[0] = $this->sm4Sbox($a[0]);
        $b[1] = $this->sm4Sbox($a[1]);
        $b[2] = $this->sm4Sbox($a[2]);
        $b[3] = $this->sm4Sbox($a[3]);

        $bb = $this->get_ulong_be($b, 0);
        $c = gmp_xor($bb, gmp_xor($this->rotl($bb, 2), gmp_xor($this->rotl($bb, 10), gmp_xor($this->rotl($bb, 18), $this->rotl($bb, 24)))));
        return gmp_strval($c, '10');
    }

    private function sm4F($x0, $x1, $x2, $x3, $rk)
    {
        $t1 = gmp_xor($x1, $x2);
        $t2 = gmp_xor($x3, $rk);
        $param_o = gmp_xor($t1, $t2);
        $param_t = gmp_strval($param_o, '10');
        $t = $this->sm4Lt($param_t);
        $result = gmp_strval(gmp_xor($x0, $t), '10');

        return $result;
    }

    private function sm4CalciRK($ka)
    {
        $a = array();
        $b = array();

        $a = $this->put_ulong_be($ka, 0);

        $b[0] = $this->sm4Sbox($a[0]);
        $b[1] = $this->sm4Sbox($a[1]);
        $b[2] = $this->sm4Sbox($a[2]);
        $b[3] = $this->sm4Sbox($a[3]);

        $bb = $this->get_ulong_be($b, 0);
        $f = gmp_xor($bb, $this->rotl($bb, 13));
        $s = gmp_xor($f, $this->rotl($bb, 23));
        $rk = gmp_strval($s, '10');

        return $rk;
    }

    private function sm4_setkey()
    {
        $MK = array();
        $k = array();

        $MK[0] = $this->get_ulong_be($this->KEY, 0);
        $MK[1] = $this->get_ulong_be($this->KEY, 4);
        $MK[2] = $this->get_ulong_be($this->KEY, 8);
        $MK[3] = $this->get_ulong_be($this->KEY, 12);

        $k[0] = gmp_xor((string)$MK[0], (string)(self::c($this->FK[0])));
        $k[0] = gmp_strval($k[0], 10);
        $k[1] = gmp_xor((string)$MK[1], (string)(self::c($this->FK[1])));
        $k[1] = gmp_strval($k[1], 10);
        $k[2] = gmp_xor((string)$MK[2], (string)(self::c($this->FK[2])));
        $k[2] = gmp_strval($k[2], 10);
        $k[3] = gmp_xor((string)$MK[3], (string)(self::c($this->FK[3])));
        $k[3] = gmp_strval($k[3], 10);

        for ($i = 0; $i < 32; $i++) {
            $first = gmp_xor($k[$i + 1], $k[$i + 2]);
            $second = gmp_xor($k[$i + 3], (self::c($this->CK[$i])));
            $RK_gmp = gmp_xor($first, $second);
            $RK_param = gmp_strval($RK_gmp, '10');
            $k[$i + 4] = gmp_xor($k[$i], ($this->sm4CalciRK($RK_param)));
            $k[$i + 4] = gmp_strval($k[$i + 4], '10');
            $this->SK[$i] = $k[$i + 4];
        }
    }

    private static function c($number)
    {
        $signed = unpack("l", pack("l", hexdec("ff$number")));
        return $signed[1];
    }

    //一轮加密：输入16字节，输出16字节
    private function sm4_one_round($input)
    {
        $i = 0;
        $ulbuf = array();
        $output = array();

        $ulbuf[0] = $this->get_ulong_be($input, 0);
        $ulbuf[1] = $this->get_ulong_be($input, 4);
        $ulbuf[2] = $this->get_ulong_be($input, 8);
        $ulbuf[3] = $this->get_ulong_be($input, 12);
        while ($i < 32) {
            $ulbuf[$i + 4] = $this->sm4F($ulbuf[$i], $ulbuf[$i + 1], $ulbuf[$i + 2], $ulbuf[$i + 3], $this->SK[$i]);
            $i++;
        }
        $output[0] = $this->put_ulong_be($ulbuf[35], 0);
        $output[1] = $this->put_ulong_be($ulbuf[34], 4);
        $output[2] = $this->put_ulong_be($ulbuf[33], 8);
        $output[3] = $this->put_ulong_be($ulbuf[32], 12);

        $output = array_merge($output[0], $output[1], $output[2], $output[3]);

        return $output;
    }

    private function sm4_setkey_enc()
    {
        $this->sm4_setkey();
    }

    private function sm4_setkey_dec()
    {
        $this->sm4_setkey();

        for ($i = 0; $i < 16; $i++) {
            $t = $this->SK[$i];
            $this->SK[$i] = $this->SK[31 - $i];
            $this->SK[31 - $i] = $t;
        }
    }

    //input的字节长度必须是16的整数倍
    //output的字节长度必须跟input相同
    private function sm4_crypt_ecb($input, $output)
    {

        $idx = 0;
        $a = array();
        $b = array();
        $ilen = count($input);

        while ($ilen > 1) {
            for ($i = 0; $i < 16; $i++) {
                $a[$i] = $input[$idx + $i];

            }
            $b = $this->sm4_one_round($a);
            for ($i = 0; $i < 16; $i++) {
                $output[$idx + $i] = $b[$i];
            }
            $idx += 16;
            $ilen -= 16;
        }
        return $output;
    }


    /*对外公开的方法*/
    public function SetKey($key)
    {
        try{
            if (strlen($key) != 32) throw new Exception('密钥错误');
            for ($i = 0; $i < 16; $i++) {
                $this->KEY[$i] = hexdec(substr($key, $i * 2, 2));
            }
        }catch (Exception $ex){
            echo $ex->getMessage();
            die;
        }
    }

    //对输入的String字符串进行加密：
    //输入参数：待加密串（UTF-8格式）
    //返回值：加密后的BASE64字符串
    public function Encrypt($str)
    {
        $sRet = "";

        if ($str == null || empty($str)) return $sRet;

        $this->sm4_setkey_enc();
        //1、把输入的str字符串转换成字节数组
        $by = new Bytes();
        $sb = $by->getBytes($str);
        $len = count($sb);
        $left = $len % 16;
        //设置输入缓冲区是16的整数倍，不足16位的补0
        $blen = (int)($len / 16) * 16;
        if ($left > 0) $blen += 16;

        $b = array();

        for ($i = 0; $i < $len; $i++) $b[$i] = (int)$sb[$i];
        for ($i = $len; $i < $blen; $i++) $b[$i] = 0;   //最后补齐0

        $e = array();    //指定密文输出缓冲区
        $e = $this->sm4_crypt_ecb($b, $e);      //SM4加密

        //把密文缓冲区转换成BASE64
        //把密文缓冲区压缩
        $eb = array();

        for ($i = 0; $i < $blen; $i++) $eb[$i] = $by->toByte($e[$i]);
        $sRet = base64_encode($result = $by->toStr($eb));

        return $sRet;
    }


    //对输入的BASE64字符串进行解密：
    //输入参数：待解密串（BASE64格式）
    public function Decrypt($str)
    {

        //设置解密模式
        $this->sm4_setkey_dec();

        //把输入的Base64字符串转换成字节数组
        $by = new Bytes();
        $str = base64_decode($str, true);
        $sb = $by->getBytes($str);
        $len = count($sb);
        $b = array();
        for ($i = 0; $i < $len; $i++) $b[$i] = (int)$sb[$i] & 0xff;
        $e = array();    //指定密文输出缓冲区
        $e = $this->sm4_crypt_ecb($b, $e);      //SM4加密
        $e = array_diff($e, [0]);  //去除数组末尾为0的元素

        return $by->toStr($e);

    }
}

$sm4 = new SM4();
$key = '0123456789abcdeffedcba9876543210';
$str = "测试urlaaaaaaaa";

$sm4->SetKey($key);
$EData = $sm4->Encrypt($str);//加密
$Ddata = $sm4->Decrypt($EData);//解密

echo '明文：',$str,"<br>";
echo '密文：',$EData,"<br>";
echo '解密：',$Ddata,"<br>";

if($str === $Ddata){
    echo '一模一样';
}