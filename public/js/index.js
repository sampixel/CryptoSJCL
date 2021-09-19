var toEncrypt = "This is my secret key";
var Encrypted = sjcl.encrypt("kalei.do.cookie", toEncrypt);
var Decrypted = sjcl.decrypt("kalei.do.cookie", Encrypted);

document.querySelector("code.js-data-encrypted").innerHTML = Encrypted;
document.querySelector("code.js-data-decrypted").innerHTML = Decrypted;

document.querySelector("span.js-sjcl-encrypt").innerHTML = typeof(Encrypted);
document.querySelector("span.js-sjcl-decrypt").innerHTML = typeof(Decrypted);