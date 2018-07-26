<?php

namespace Bulldog\Yubico;

use Bulldog\Yubico\Contracts\OtpInterface;
use Bulldog\Yubico\Contracts\OtpAdapterInterface;
use Psr\Http\Message\ResponseInterface;

class Yubico implements OtpInterface
{
    /**
     * Http Client
     *
     * @var Bulldog\Yubico\Contracts\OtpAdapterInterface
     */
    private $adapter;

    /**
     * API ID
     *
     * @var int
     */
    private $id;

    /**
     * API Key
     *
     * @var string
     */
    private $key;

    /**
     * Reason returned from Yubico
     *
     * @var string
     */
    private $reason;

    /**
     * Yubico API Endpoints
     *
     * @var array
     */
    private $urls = [
        'https://api.yubico.com/wsapi/2.0/verify',
        'https://api2.yubico.com/wsapi/2.0/verify',
        'https://api3.yubico.com/wsapi/2.0/verify',
        'https://api4.yubico.com/wsapi/2.0/verify',
        'https://api5.yubico.com/wsapi/2.0/verify',
    ];

    /**
     * Yubico construct
     *
     * Get a key from https://upgrade.yubico.com/getapikey/
     *
     * @param string              $id      ID Provided by Yubico
     * @param string              $key     API Key provided by Yubico
     * @param OtpAdapterInterface $adapter Adapter to use for http requests
     */
    public function __construct($id, $key, OtpAdapterInterface $adapter)
    {
        $this->id      = $id;
        $this->key     = base64_decode($key);
        $this->adapter = $adapter;
    }

    /**
     * Verify the One-Time Password.
     *
     * If the multiple param is set to true, then it will loop through all of
     * the endpoints Yubico provides. If any of those endpoints return the
     * OTP is bad, it'll return false.
     *
     * @param  string  $otp      One-Time Password provided from a Yubico device
     * @param  boolean $multiple If it should check the OTP against all endpoints
     *
     * @return boolean           True if it's good, and false if it's bad
     */
    public function verify($otp, $multiple = false)
    {
        if($multiple) {
            // Loops through each URL
            foreach($this->urls as $url) {
                // If any of the URLs return false, go ahead and have this
                // methodo return false as well.
                if(!$this->verifyYubicoOtp($otp, $url)) {
                    return false;
                }
            }

            // OTP passed
            return true;
        }

        // $multiple was false, check the first server
        return $this->verifyYubicoOtp($otp, $this->urls[0]);
    }

    /**
     * Go through the verification process.
     *
     * @see https://github.com/Yubico/php-yubico/blob/master/Yubico.php#L281
     *
     * @param  string $otp One-Time Password
     * @param  string $url URL to use for verification
     *
     * @return boolean     True if it's good and false if it's bad
     */
    private function verifyYubicoOtp($otp, $url)
    {
        $ret = $this->parsePasswordOTP($otp);

        if(!$ret) {
            throw new \InvalidArgumentException('Could not parse Yubikey OTP');
        }

        $params = [
            'id'        => $this->id,
            'otp'       => $ret['otp'],
            'nonce'     => md5(uniqid(rand())),
            'timestamp' => 1,
            'sl'        => 0, // This may need adjusted
            'timeout'   => 30,
        ];

        ksort($params);

        $parameters = '';

        foreach($params as $p=>$v) $parameters .= "&" . $p . "=" . $v;

        $parameters = ltrim($parameters, "&");

        /* Generate signature. */
        if($this->key <> "") {
            $signature = base64_encode(hash_hmac('sha1', $parameters,
            $this->key, true));
            $signature = preg_replace('/\+/', '%2B', $signature);
            $parameters .= '&h=' . $signature;
        }

        $res = $this->adapter->get($this->urls[0]."?".$parameters);

        $parsedResponse = $this->parseResponse($res);

        $this->reason = $parsedResponse['status'];

        $status = strtolower(trim($parsedResponse['status']));

        if(!strcmp($status, 'ok') !== 0) {
            return false;
        }

        return true;
    }

    /**
     * Parse the response from Yubico.
     *
     * Yubico sends back a string with multiple lines and on each line, it has
     * a key => value pair separated by an "=" sign. This method will parse
     * the response and return an associative array of data.
     *
     * @param  ResponseInterface $response Adapter Http Response
     *
     * @return array
     */
    private function parseResponse($response)
    {
        $data = [];
        $lines = explode("\n", $response->getBody()->getContents());

        foreach($lines as $line) {
            if(strlen($line) == 0) {
                continue;
            }

            $keyValue = explode("=", $line);

            if(count($keyValue) == 1) {
                continue;
            }

            $data[$keyValue[0]]= $keyValue[1];
        }

        return $data;
    }


    /**
     * Parse input string into password, yubikey prefix,
	 * ciphertext, and OTP.
     *
     * @see https://github.com/Yubico/php-yubico/blob/master/Yubico.php#L213
     *
     * @param  string $str   Input string to parse
     * @param  string $delim Optional delimiter re-class, default is '[:]'
     *
     * @return array         Keyed array with fields
     */
    protected function parsePasswordOTP($str, $delim = '[:]')
	{
        if (!preg_match("/^((.*)" . $delim . ")?" .
            "(([cbdefghijklnrtuv]{0,16})" .
            "([cbdefghijklnrtuv]{32}))$/i",
            $str, $matches)) {
                /* Dvorak? */
                if (!preg_match("/^((.*)" . $delim . ")?" .
                    "(([jxe\.uidchtnbpygk]{0,16})" .
                    "([jxe\.uidchtnbpygk]{32}))$/i",
                    $str, $matches)) {
                return false;
            } else {
                $ret['otp'] = strtr($matches[3], "jxe.uidchtnbpygk", "cbdefghijklnrtuv");
            }
        } else {
            $ret['otp'] = $matches[3];
        }
        $ret['password']   = $matches[2];
        $ret['prefix']     = $matches[4];
        $ret['ciphertext'] = $matches[5];

        return $ret;
	}

    /**
     * Accessor for Yubico reason from response.
     *
     * @return string
     */
    public function getReason()
    {
        return $this->reason;
    }

    /**
     * Set your own array of URLs for verification.
     *
     * @param array $urls
     */
    public function setUrls(array $urls)
    {
        $this->urls = $urls;
    }
}
