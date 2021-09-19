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
 * @see     https://bitwiseshiftleft.github.io/sjcl/
 * @package CryptoSJCL
 * @author  Samuel Reka <rekasamuel0@gmail.com>
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
        "KALEIDO_LINKS" => [
            "key" => "qDQMBZZTFRcdKfdBJ4PDemX16eBfGFgv129Tbgj0OA8=",
            "iv"  => "kWXxIYgFztUC7GQypVs3G4yX0TUm8ta5x9kmxWGJMWI="
        ],
    ];

    /**
     * Extracts the cipher algorithm from the given param
     *
     * @param string|object $algo The encryption algorithm
     * 
     * @return string The cipher string format
     */
    public static function SSL_ExtractAlgo($algo) {
        return (
            gettype($algo === "object") ?
            $algo["cipher"] . "-" . $algo["bytes"] . "-" . $algo["mode"] : (
                !in_array($algo, openssl_get_cipher_methods()) ?
                self::OPENSSL_ALGO : $algo
            )
        );
    }

    /**
     * Encrytes a given data object as string
     * 
     * @param string  $data The string to encrypt
     * @param string|object $algo The encryption algorithm
     *  - @param string $algo["cipher"] e.g.("aes")
     *  - @param string $algo["bytes"] e.g.("128")
     *  - @param string $algo["mode"] e.g.("ccm")
     * @param string  $key  The phrase key value
     * @param string  $hash The digest hash value
     * @param boolean $flag The option bitwise value
     * 
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     * 
     * @return string The data string encrypted
     */
    public static function SSL_Encrypt($data, $algo, $key, $hash = null, $flag = 0) {
        $algo  = CryptoSJCL::SSL_ExtractAlgo($algo);
        $hash  = isset($hash) && in_array($hash, hash_algos($hash)) ? $hash : self::OPENSSL_HASH;
        $key   = hash($hash, self::OPENSSL_KEYS[$key]["key"]);
        $flag  = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $iv    = substr(hash($hash, self::OPENSSL_KEYS[$key]["iv"]), 0, 16);

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
     * @param string  $data  The encrypted data to decrypt
     * @param string|object $algo The encryption algorithm
     *  - @param string $algo["cipher"] e.g.("aes")
     *  - @param string $algo["bytes"] e.g..("128")
     *  - @param string $algo["mode"] e.g.("ccm")
     * @param string  $key   The phrase key value
     * @param string  $hash  The digest hash value
     * @param boolean $flag  The option bitwise value
     * @param boolean $json  The json decode flag
     * @param boolean $array The array flag
     * 
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     * 
     * @return string|array|object The input string decrypted
     */
    public static function SSL_Decrypt($data, $algo, $key, $hash = null, $flag = 0, $json = false, $array = false) {
        $algo  = CryptoSJCL::SSL_ExtractAlgo($algo);
        $hash  = isset($hash) && in_array($hash, hash_algos($hash)) ? $hash : self::OPENSSL_HASH;
        $key   = hash($hash, self::OPENSSL_KEYS[$key]["key"]);
        $flag  = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $iv    = substr(hash($hash, self::OPENSSL_KEYS[$key]["iv"]), 0, 16);

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
     * Decrypts a given string encrypted using sjcl
     * 
     * @param string  $data  The encrypted object
     * @param string  $key   The password key phrase
     * @param boolean $json  The json flag
     * @param boolean $array The array flag
     * 
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     * 
     * @return string The input object decrypted
     */
    public static function SJCL_Decrypt($data, $key, $hash = null, $json = false, $array = false) {
        $algo  = CryptoSJCL::SSL_ExtractAlgo($algo);
        $hash  = isset($hash) && in_array($hash, hash_algos($hash)) ? $hash : self::OPENSSL_HASH;
        $key   = hash($hash, self::OPENSSL_KEYS[$key]["key"]);
        $flag  = $flag === 0 ? OPENSSL_RAW_DATA : OPENSSL_ZERO_PADDING;
        $iv    = substr(hash($hash, self::OPENSSL_KEYS[$key]["iv"]), 0, 16);


        $algo  = $data["cipher"] . "-" . $data["ks"] . "-" . $data["mode"];



        $data = substr(base64_decode($object["ct"]), 0, - $object["ts"] / 8);
        $iv_aad = $object["adata"];
        $iv_dec = base64_decode($object["iv"]);
        $iv_tag = substr(base64_decode($object["ct"]), - $object["ts"] / 8);
        $iv_key = base64_decode(hash_pbkdf2("sha256", $passwd, base64_decode($object["salt"]), $object["iter"], 0, true));

        $ssl_decrypted = openssl_decrypt($data, $cipher, $iv_key, OPENSSL_RAW_DATA, $iv_dec, $iv_tag, $iv_aad);
        $ssl_decrypted = $bool === true ? json_decode($ssl_decrypted, true) : $ssl_decrypted;

        return $ssl_decrypted;
    }

}