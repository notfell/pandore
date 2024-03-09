<?php 

function gen_rdn_str($length = 16) 
{
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}



function random_hex_array($length) 
{
    $result_array = array();

    for ($i = 0; $i < $length; $i++) 
    {
        $hexa = mt_rand(0, 255);
        $hexa_unsigned = sprintf('0x%02X', $hexa);
        $result_array[] = hexdec($hexa_unsigned);
    }

    return $result_array;
}

function str_to_hex_array($hex_str) 
{
    $hex_str = str_replace(' ', '', $hex_str);
    
    $hex_array = explode(',', $hex_str);

    $result_array = [];
    foreach ($hex_array as $hex_value)  { $result_array[] = hexdec($hex_value); }
    
    return $result_array;
}

function rc4($plainArray, $key) 
{
    $keyLength = count($key);
    $s = range(0, 255);
    $j = 0;

    for ($i = 0; $i < 256; $i++)
     {
        $j = ($j + $s[$i] + $key[$i % $keyLength]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $cipherArray = [];
    $i = 0;
    $j = 0;

    foreach ($plainArray as $plainValue) 
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        $cipherValue = $s[($s[$i] + $s[$j]) % 256];

        $cipherArray[] = "0x" . str_pad(dechex($plainValue ^ $cipherValue), 2, "0", STR_PAD_LEFT);
    }

    return $cipherArray;
}

?>