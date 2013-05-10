<?php
/*
 * This is a PHP library that handles calling reCAPTCHA.
 *    - Documentation and latest version
 *          http://recaptcha.net/plugins/php/
 *    - Get a reCAPTCHA API Key
 *          https://www.google.com/recaptcha/admin/create
 *    - Discussion group
 *          http://groups.google.com/group/recaptcha
 *
 * Copyright (c) 2007 reCAPTCHA -- http://recaptcha.net
 * AUTHORS:
 *   Mike Crawford
 *   Ben Maurer
 *   Pavlo Sadovyi (made this wrapper for Phalcon Framework)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace Hakaba\Libraries;

class Recaptcha extends \Phalcon\DI\Injectable
{
	/**
     * The reCAPTCHA server URL's
     */
    const RECAPTCHA_API_SERVER = 'http://www.google.com/recaptcha/api';
    const RECAPTCHA_API_SECURE_SERVER = 'https://www.google.com/recaptcha/api';
    const RECAPTCHA_VERIFY_SERVER = 'www.google.com';

    /**
     * The reCAPTCHA error messages
     */
    const RECAPTCHA_ERROR_KEY = 'To use reCAPTCHA you must get an API key from <a href="https://www.google.com/recaptcha/admin/create">https://www.google.com/recaptcha/admin/create</a>';
    const RECAPTCHA_ERROR_REMOTE_IP = 'For security reasons, you must pass the remote IP address to reCAPTCHA';

    
    public static $error = 'incorrect-captcha-sol';
    public static $is_valid = false;

	/**
     * Gets the challenge HTML (javascript and non-javascript version).
     * This is called from the browser, and the resulting reCAPTCHA HTML widget
     * is embedded within the HTML form it was called from.
     *
     * @param string $publicKey A public key for reCAPTCHA (optional, default is false)
     * @param string $error The error given by reCAPTCHA (optional, default is '')
     * @param boolean $useSSL Should the request be made over ssl? (optional, default is false)
     * @return string - The HTML to be embedded in the user's form.
     */
    public static function get($publicKey, $error = '', $useSSL = false)
    {
    	// Merging method arguments with class fileds 
    	$publicKey = $publicKey or die(self::RECAPTCHA_ERROR_KEY);

    	// Choosing a server
        $server = $useSSL ? self::RECAPTCHA_API_SECURE_SERVER : self::RECAPTCHA_API_SERVER;

        // Append an error
        if ($error) $error = "&amp;error=".$error;

        // Return HTML
        return '<script type="text/javascript" src="'.$server.'/challenge?k='.$publicKey.$error.'"></script>
        <noscript>
            <iframe src="'.$server.'/noscript?k='.$publicKey.$error.'" height="300" width="500" frameborder="0"></iframe><br/>
            <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
            <input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>
        </noscript>';
    }

    /**
     * Calls an HTTP POST function to verify if the user's guess was correct
     *
     * @param string $privateKey
     * @param string $remoteip
     * @param string $challenge
     * @param string $response
     * @param array $extra_params An array of extra variables to post to the server
     * @return boolean $this->is_valid property
     */
    public static function check($privateKey, $remoteIP, $challenge, $response, $extra_params = array())
    {
        $privateKey = $privateKey or die(self::RECAPTCHA_ERROR_KEY);
        $remoteIP = $remoteIP or die(self::RECAPTCHA_ERROR_REMOTE_IP);

        // Discard spam submissions
        if (!$challenge or !$response)
            return self::$is_valid;

        $response = self::httpPost(self::RECAPTCHA_VERIFY_SERVER, "/recaptcha/api/verify", array(
            'privatekey' => $privateKey,
            'remoteip' => $remoteIP,
            'challenge' => $challenge,
            'response' => $response
        ) + $extra_params);

        $answers = explode("\n", $response[1]);
        
        if (trim($answers[0]) == 'true') self::$is_valid = true;
        else self::$error = $answers[1];

        return self::$is_valid;
    }

    /**
     * Submits an HTTP POST to a reCAPTCHA server
     *
     * @param string $host
     * @param string $path
     * @param array $data
     * @param int port
     * @return array response
     */
    private static function httpPost($host, $path, $data, $port = 80)
    {
        $req = self::qsEncode($data);

        $http_request  = "POST $path HTTP/1.0\r\n";
        $http_request .= "Host: $host\r\n";
        $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $http_request .= "Content-Length: ".strlen($req)."\r\n";
        $http_request .= "User-Agent: reCAPTCHA/PHP\r\n";
        $http_request .= "\r\n";
        $http_request .= $req;

        $response = '';
        if (!($fs = @fsockopen($host, $port, $errno, $errstr, 10))) {
            die('Could not open socket');
        }

        fwrite($fs, $http_request);

        while (!feof($fs)) $response .= fgets($fs, 1160); // One TCP-IP packet
        fclose($fs);
        $response = explode("\r\n\r\n", $response, 2);

        return $response;
    }

    /**
     * Encodes the given data into a query string format
     *
     * @param array $data Array of string elements to be encoded
     * @return string $req Encoded request
     */
    private static function qsEncode($data)
    {
        $req = '';
        foreach ($data as $key => $value)
            $req .= $key.'='.urlencode(stripslashes($value)).'&';

        // Cut the last '&'
        $req = substr($req, 0, strlen($req) - 1);

        return $req;
    }
}