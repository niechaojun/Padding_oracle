<?php
error_reporting(0);
define("SECRET_KEY", "******"); //key不可知
define("METHOD", "aes-128-cbc");
session_start();

function get_random_token(){
    $random_token = '';
    $str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
    for($i = 0; $i < 16; $i++){
        $random_token .= substr($str, rand(1, 61), 1);
    }
    return $random_token;
}

function get_identity(){
    $id = '***'; //原明文不可知
    $token = get_random_token();
    $c = openssl_encrypt($id, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token);
    $_SESSION['id'] = base64_encode($c);
    setcookie("token", base64_encode($token));
    $_SESSION['isadmin'] = false;
}

function test_identity(){
    if (isset($_SESSION['id'])) {
        $c = base64_decode($_SESSION['id']);
        $token = base64_decode($_COOKIE["token"]);
        if($u = openssl_decrypt($c, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $token)){
            if ($u === 'admin') {
                $_SESSION['isadmin'] = true;
            }
        }else
            echo "Error!";
    }
}

if(!isset($_SESSION['id']))
    get_identity();
test_identity();
if ($_SESSION["isadmin"])
    echo "You are admin!";
else
    echo "false";
?>