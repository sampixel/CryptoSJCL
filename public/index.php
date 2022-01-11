<?php
require_once(dirname(__DIR__) . "/CryptoSJCL.php");

$phpEncryption = "This is my php secret key";
$jsEncryption  = '{"iv":"wCwsBmPH9vKWbDiaKIH8LA==","v":1,"iter":10000,"ks":128,"ts":64,"mode":"gcm","adata":"","cipher":"aes","salt":"+nmM2V22tdw=","ct":"Hrtfrw9tCz8Kt0vt0MUA9upMe2gdMpsVgD+oewsTFIc="}';

$SSL_ALGO = [
    "cipher" => "aes",
    "bytes"  => "128",
    "mode"   => "ctr"
];

$SSL_Encrypted  = CryptoSJCL::SSL_Encrypt($phpEncryption, "MY-IDENTIFIER", $SSL_ALGO);
$SSL_Decrypted  = CryptoSJCL::SSL_Decrypt($SSL_Encrypted, "MY-IDENTIFIER", $SSL_ALGO);
$SJCL_Decrypted = CryptoSJCL::SJCL_Decrypt($jsEncryption, "private_passwd");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoSJCL</title>
    <link rel="shortcut icon" type="image/ico" href="favicon.ico" />
    <link rel="stylesheet" type="text/css" href="css/index.css" />
    <script type="text/javascript" src="https://bitwiseshiftleft.github.io/sjcl/sjcl.js" crossorigin></script>
</head>
<body>
    <div class="php-crypto">
        <h1>From PHP</h1>
        <div class="php-encrypt-data inner-data">
            <div class="data-type">
                <span class="type-title">OPENSSL_ENCRYPT</span>
                <span class="type-item"><?= strtolower(gettype($SSL_Encrypted)) ?></span>
            </div>
            <div class="data-code">
                <code class="data-encrypted">
                    <?= $SSL_Encrypted ?>
                </code>
            </div>
        </div>
        <div class="php-decrypt-data inner-data">
            <div class="data-decryption">
                <div class="decryption-ssl">
                    <div class="data-type">
                        <span class="type-title">OPENSSL_DECRYPT</span>
                        <span class="type-item"><?= strtolower(gettype($SSL_Decrypted)) ?></span>
                    </div>
                    <div class="data-code">
                        <code class="data-encrypted">
                            <?= $SSL_Decrypted ?>
                        </code>
                    </div>
                </div>
                <div class="decryption-sjcl">
                    <div class="data-type">
                        <span class="type-title">SJCL_DECRYPT</span>
                        <span class="type-item"><?= strtolower(gettype($SJCL_Decrypted)) ?></span>
                    </div>
                    <div class="data-code">
                        <code class="data-encrypted">
                            <?= $SJCL_Decrypted ?>
                        </code>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="js-crypto">
        <h1>From JS</h1>
        <div class="js-encrypt-data inner-data">
            <div class="data-type">
                <span class="type-title">SJCL.encrypt</h3>
                <span class="type-item js-sjcl-encrypt"></span>
            </div>
            <div class="data-code">
                <code class="js-data-encrypted"></code>
            </div>
        </div>
        <div class="js-decrypt-data inner-data">
            <div class="data-type">
                <span class="type-title">SJCL.decrypt</span>
                <span class="type-item js-sjcl-decrypt"></span>
            </div>
            <div class="data-code">
                <code class="js-data-decrypted"></code>
            </div>
        </div>
    </div>
    <script type="text/javascript" src="js/index.js"></script>
</body>
</html>