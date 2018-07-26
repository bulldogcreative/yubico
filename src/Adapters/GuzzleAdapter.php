<?php

namespace Bulldog\Yubico\Adapters;

use Bulldog\Yubico\Contracts\OtpAdapterInterface;
use GuzzleHttp\Client;
use Guzzle\Http\ClientInterface;
use Guzzle\Http\Exception\RequestException;
use Guzzle\Http\Message\Response;

class GuzzleAdapter implements OtpAdapterInterface
{
    public function __construct(ClientInterface $client = null)
    {
        $this->client = $client ?: new Client();
    }

    public function get($url)
    {
         return $this->client->get($url);
    }
}
