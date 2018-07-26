# Yubico auth

A modern PHP library for verifying Yubico One-Time Passwords.

## Installation

This library can be found on [Packagist](https://packagist.org/).
The recommended way to install this is through [composer](http://getcomposer.org).

`composer require bulldog/yubico`

## Usage

We include [Guzzle](https://github.com/guzzle/guzzle) by default, but you are
welcome to use any other PHP HTTP client. You will need to create a new adapter
for any other PHP HTTP client and have it implement the `OtpAdapterInterface`.

```php
<?php
include 'vendor/autoload.php';

use Bulldog\Yubico\Yubico;
use Bulldog\Yubico\Adapters\GuzzleAdapter;

$yubico = new Yubico('1234', 'c2VjcmV0X2tleQ==', new GuzzleAdapter());

if($yubico->verify('longonetimepasswordgeneratedfromayubicokey')) {
    echo "That OTP is good!\n";
} else {
    echo "OTP is bad!\n";
    echo $yubico->getReason() . "\n";
}
```
