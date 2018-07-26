<?php

namespace Bulldog\Yubico\Contracts;

interface OtpInterface
{
    public function verify($otp, $multiple = false);
}
