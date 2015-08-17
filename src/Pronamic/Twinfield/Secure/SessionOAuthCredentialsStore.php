<?php

namespace Pronamic\Twinfield\Secure;

/**
 * Storage / Data Access Object that uses the $_SESSION var for persisting and retrieving the oauth credentials.
 * 
 * @package Pronamic\Twinfield
 * @author Marten Sytema <marten@sytematic.nl>
 * @copyright (c) 2015, Pronamic
 * @version 0.0.1
 */

class SessionOAuthCredentialsStore implements IOAuthCredentialsStore
{

    private $session = array();
    private $sessionName = 'PronamicTwinfieldOauthSession';

    public function __construct() {
        $this->initSession();
    }

    public function saveSession()
    {
        $GLOBALS['_SESSION'][$this->sessionName] = serialize($this->session);
    }

    public function initSession()
    {   
        setcookie($this->sessionName, null, -1, '/');
        $this->session = array(
            'temp_token_secret' => null,
            'accessToken' => null,
            'accessSecret' => null,
        );
        return $this->session;
    }

    public function loadSession() {
        if (isset($GLOBALS['_SESSION'][$this->sessionName])) {
            $this->session = @unserialize($GLOBALS['_SESSION'][$this->sessionName]);
        } else {
            $this->initSession();
        }
        return $this->session;
    }
}
