<?php
namespace Pronamic\Twinfield\Secure;


interface IOAuthCredentialsStore {


    /**
     * Initializes/resets the credentials.
     * Contents should be:
     * array(
            'temp_token'=>null,
            'temp_token_secret' => null,
            'accessToken' => null,
            'accessSecret' => null,
       );
     */
    public function initSession();

    /**
     * Loads the credentials from the session store and returns it.
     * Contents should be:
     * array(
            'temp_token'=>null,
            'temp_token_secret' => null,
            'accessToken' => null,
            'accessSecret' => null,
       );
     */
    public function loadSession();

    /**
     * Persists the supplied session
     *
     * @post a subsequent call to loadSession() and then getSession() retrieves what is persisted
     */
    public function saveSession(array $data);

}
?>
