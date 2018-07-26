<?php

namespace Bulldog\Yubico\Contracts;

interface OtpAdapterInterface
{
    public function get($url);
}
