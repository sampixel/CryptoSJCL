var toEncrypt = "This is my js secret key";
var Encrypted = sjcl.encrypt("private_passwd", toEncrypt);
var Decrypted = sjcl.decrypt("private_passwd", Encrypted);

document.querySelector("code.js-data-encrypted").innerHTML = Encrypted;
document.querySelector("code.js-data-decrypted").innerHTML = Decrypted;

document.querySelector("span.js-sjcl-encrypt").innerHTML = typeof(Encrypted);
document.querySelector("span.js-sjcl-decrypt").innerHTML = typeof(Decrypted);