<?php
/**
 * Class CryptoSJCL
 * 
 * This class provides standard encryption/decryption using
 * php's built-in openssl library, furthermore offers basic
 * decryption support for encrypted data from the javascript
 * sjcl library, in case the encryption had happened from the
 * front-end.\
 * __NOTE__: You can add new entries inside OPENSSL_KEYS array
 * by generating new keys and initialization vectors (IV)
 * using the following format:
 * __base64_encode(openssl_random_pseudo_bytes(32));__
 * 
 * @see https://bitwiseshiftleft.github.io/sjcl/
 * @package https://github.com/sampixel/CryptoSJCL.git
 * @author Samuel Reka <rekasamuel0@gmail.com>
 */
Class CryptoSJCL {

    /**
     * @var string OPENSSL_ALGO
     * The default algorithm if none is used
     */
    const OPENSSL_ALGO = "aes-256-ctr";
    /**
     * @var string OPENSSL_HASH
     * The default hash value for digest
     */
    const OPENSSL_HASH = "sha256";
    /**
     * @var array OPENSSL_KEYS
     * All available string keys
     */
    const OPENSSL_KEYS = [
        "MY_IDENTIFIER" => [
            "key" => "qDQMBZZTFRcdKfdBJ4PDemX16eBfGFgv129Tbgj0OA8=",
            "iv" => "kWXxIYgFztUC7GQypVs3G4yX0TUm8ta5x9kmxWGJMWI="
        ],
    ];

    /**
     * Returns the cipher algorithm from the given param
     *
     * @param string|object $algo The encryption algorithm
     * 
     * @return string The cipher string format
     */
    public static function SSL_ALGO($algo) {
        return (
            gettype($algo === "object") ?
            $algo["cipher"] . "-" . $algo["bytes"] . "-" . $algo["mode"] : (
                !in_array($algo, openssl_get_cipher_methods()) ?
                self::OPENSSL_ALGO : $algo
            )
        );
    }

    /**
     * Returns the hash value from the given param
     * 
     * @param string $hash The hash value
     * 
     * @return string The extracted hash value
     */
    public static function SSL_HASH($hash) {
        return (
            isset($hash) && in_array($hash, hash_algos($hash)) ?
            $hash : self::OPENSSL_HASH
        );
    }

    /**
     * Encrytes a given data object as string
     * 
     * @param string $data  The string to encrypt
     * @param string|object $algo The encryption algorithm
     * - @param string $algo["cipher"] e.g.("aes")
     * - @param string $algo["bytes"] e.g.("128")
     * - @param string $algo["mode"] e.g.("ccm")
     * @param string $key   The phrase key value
     * @param string $hash  The digest hash value
     * @param boolean $flag The option bitwise value
     * 
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     * 
     * @return string The data string encrypted
     */
    public static function SSL_Encrypt($data, $algo, $key, $hash = null, $flag = 0) {
        $algo = CryptoSJCL::SSL_ALGO($algo);
        $hash = CryptoSJCL::SSL_HASH($hash);
        $key  = hash($hash, self::OPENSSL_KEYS[$key]["key"]);
        $flag = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $iv   = substr(hash($hash, self::OPENSSL_KEYS[$key]["iv"]), 0, 16);

        return base64_encode(
            openssl_encrypt($data, $algo, $key, $flag, $iv)
        );
    }

    /**
     * Decrypts a given encrypted string
     * 
     * __NOTE__: If the $json flag is set to true, then
     * a json_decode will be executed, otherwise a plain
     * string text is returned;\
     * if the $array flag is set to true, same with $json flag,
     * then a json_decode will be executed returning an array
     * instead of an object.
     * 
     * @param string $data   The encrypted data to decrypt
     * @param string|object $algo The encryption algorithm
     * - @param string $algo["cipher"] e.g.("aes")
     * - @param string $algo["bytes"] e.g..("128")
     * - @param string $algo["mode"] e.g.("ccm")
     * @param string $key    The phrase key value
     * @param string $hash   The digest hash value
     * @param boolean $flag  The option bitwise value
     * @param boolean $json  The json decode flag
     * @param boolean $array The array flag
     * 
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     * 
     * @return string|array|object The input string decrypted
     */
    public static function SSL_Decrypt($data, $algo, $key, $hash = null, $flag = 0, $json = false, $array = false) {
        $algo = CryptoSJCL::SSL_ALGO($algo);
        $hash = CryptoSJCL::SSL_HASH($hash);
        $key  = hash($hash, self::OPENSSL_KEYS[$key]["key"]);
        $flag = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $iv   = substr(hash($hash, self::OPENSSL_KEYS[$key]["iv"]), 0, 16);

        return (
            $json === false ?
            openssl_decrypt(base64_decode($data), $algo, $key, $flag, $iv) : (
                json_decode(
                    openssl_decrypt(base64_decode($data), $algo, $key, $flag, $iv),
                    $array
                )
            )
        );
    }

    /**
     * Decrypts a given string encrypted using sjcl javascript library
     * 
     * __NOTE__: Only "gcm" mode is supported so when encrypting in javascript, use the following format:\
     * __sjcl.encrypt("password", "secret-data", {mode: "gcm", iv: sjcl.random.randomWords(4, 0)});__
     * 
     * @param string $data  The encrypted object
     * @param string $pass  The password string
     * @param string $hash  The digest hash value
     * @param boolean $flag The option bitwise value
     * 
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     * 
     * @return string The input object decrypted
     */
    public static function SJCL_Decrypt($data, $pass, $hash = null, $flag = 0) {
        $data = json_decode($data, true);
        $hash = hash_pbkdf2(CryptoSJCL::SSL_HASH($hash), $pass, base64_decode($data["salt"]), $data["iter"], 0, true);
        $algo = $data["cipher"] . "-" . $data["ks"] . "-" . $data["mode"];
        $key  = substr(base64_decode($data["ct"]), 0, - $data["ts"] / 8);
        $flag = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $tag  = substr(base64_decode($data["ct"]), - $data["ts"] / 8);
        $iv   = base64_decode($data["iv"]);
        $aad  = $data["adata"];

        return openssl_decrypt($key, $algo, $hash, $flag, $iv, $tag, $aad);
    }
}