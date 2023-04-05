const {createDecipheriv, createHash} = require("crypto");
const {readFileSync, existsSync} = require("fs");

var fileName='';
if(!process.argv[2] || !existsSync(process.argv[2])) {
    console.log("[ERROR] ARCHIVO NO ENCONTRADO");
    process.exit(1);
} else {
    fileName=process.argv[2]
}

if(fileName.endsWith(".sks")){
    decSks()
}
if(fileName.endsWith(".rez")){
    decRez()
}

function decSks(){
    var path = require("path")

    var file=process.argv[2]
    try { JSON.parse(readFileSync(process.argv[2]).toString()) } catch(e) { console.log("[ERROR] Dados JSON inválidos!"); 
    return;}
    let configFile = JSON.parse(readFileSync(process.argv[2]).toString());
    const configKeys = [
    "662ede816988e58fb6d057d9d85605e0",
    "162exe235948e37ws6d057d9d85324e2", 
    "962exe865948e37ws6d057d4d85604e0", 
    "175exe868648e37wb9x157d4l45604l0", 
    "175exe867948e37wb9d057d4k45604l0",
    ];
    function aesDecrypt(data, key, iv) {
        const aesInstance = createDecipheriv("aes-256-cbc", Buffer.from(key, "base64"), Buffer.from(iv, "base64"));
        let result = aesInstance.update(data, "base64", "utf-8");
        result += aesInstance.final("utf-8");
        return result;
    }
    function md5crypt(data) {
        return createHash("md5").update(data).digest("hex");
    }
    function parseConfig(data) {
        console.log('[-]Script by @DvlJs');
        console.log(`[+]IP: ${data.sshServer}`);
        console.log(`[+]Port: ${data.sshPort}`);
        console.log(`[+]ServerName: ${data.profileSshAuth.sshUser}`);
        if(!!data.profileSshAuth.sshPasswd) { console.log(`[+]Pass: ${data.profileSshAuth.sshPasswd}`); }
        if(!!data.profileSshAuth.sshPublicKey) { console.log(`[+]Public Key:\n${data.profileSshAuth.sshPublicKey}`); }
        if(!!data.enableDataCompression) { console.log(`EDC: ${data.enableDataCompression}`); }
        if(!!data.proxyType) {
            console.log(`[-]Connection type: ${
            data.proxyType == "PROXY_HTTP" ? "SSH + HTTP":
            data.proxyType == "PROXY_SSL" ? "SSH + SSL/TLS": "Undefined"
        }`);
        } else {
            console.log(`Connection type: SSH DIRECT`);
        }
        if(!!data.proxyHttp) {
            if(!!data.proxyHttp.proxyIp) { console.log(`[+]Proxy Host: ${data.proxyHttp.proxyIp}`); }
            if(!!data.proxyHttp.proxyPort) { console.log(`[+]Proxy Port: ${data.proxyHttp.proxyPort}`); }
            if(!!data.proxyHttp.isCustomPayload) { console.log(`[+]Use custom payload for proxy: ${data.proxyHttp.isCustomPayload}`); }
            if(!!data.proxyHttp.customPayload) { console.log(`[+]Proxy Payload:\n${data.proxyHttp.customPayload}`); }
        }
        if(!!data.proxySsl) {
            if(!!data.proxySsl.hostSni) { console.log(`[+]SSL/SNI Value: ${data.proxySsl.hostSni}`); }
            if(!!data.proxySsl.isSSLCustomPayload) { console.log(`[+]Use custom payload for SSL: ${data.proxySsl.isSSLCustomPayload}`); }
            if(!!data.proxySsl.customPayloadSSL) { console.log(`[+]SSL Payload:\n${data.proxySsl.customPayloadSSL}`); }
        }
        if(!!data.proxyDirect) {
            if(!!data.proxyDirect.isCustomPayload) { console.log(`[+]Custom payload: ${data.proxyDirect.isCustomPayload}`); }
            if(!!data.proxyDirect.customPayload) { console.log(`[+]Payload: ${data.proxyDirect.customPayload}`); }
        }
        if(!!data.dnsCustom) { console.log(`[+]Custom DNS Servers: ${JSON.stringify(data.dnsCustom)}`)}
        if(!!data.configProtect) {
            if(!!data.configProtect.blockConfig) { console.log(`[+]Block config: ${data.configProtect.blockConfig}`)}
            if(!!data.configProtect.validity) { console.log(`[+]Expire Date: ${new Date(data.configProtect.validity).toString()}`)}
            if(!!data.configProtect.blockRoot) { console.log(`[+]Block root: ${data.configProtect.blockRoot}`)}
            if(!!data.configProtect.blockAuthEdition) { console.log(`[+]Block PlayStore app: ${data.configProtect.blockAuthEdition}`)}
            if(!!data.configProtect.onlyMobileData) { console.log(`[+]mobile data: ${data.configProtect.onlyMobileData}`)}
            if(!!data.configProtect.blockByPhoneId) { console.log(`[+]Enable HWID: ${data.configProtect.blockByPhoneId}`)}
            if(!!data.configProtect.phoneId) { console.log(`[+]HWID Value: ${data.configProtect.phoneId}`)}
            if(!!data.configProtect.hideMessageServer) { console.log(`[+]SSH Server Message: ${data.configProtect.hideMeyssageServer}`)}
            if(!!data.configProtect.message) { console.log(`[+]Note field:\n${data.configProtect.message}`)}
    console.log('Success!');
    console.log("")

    //not delete please
            console.log("[<|>]Module by @DvlJs
            return;t
        }
    }
    try {
        parseConfig(
            JSON.parse(
                aesDecrypt(
                    configFile.d.split(".")[0],
                    Buffer.from(md5crypt(configKeys[1] + " " + configFile.v)).toString("base64"),
                    configFile.d.split(".")[1]
                )
            )
        );
    } catch(e) { console.log(`[ERROR]${e}`); }
}


function decRez(){
    var Tea = {};  
    Tea.encrypt = function(plaintext, password) {
        if (plaintext.length == 0) return('');  
        var v = Tea.strToLongs(Utf8.encode(plaintext));
        if (v.length <= 1) v[1] = 0;  
        var k = Tea.strToLongs(Utf8.encode(password).slice(0,16)); 
        var n = v.length;
        var z = v[n-1], y = v[0], delta = -0x658C6C4C;
        var mx, e, q = Math.floor(6 + 52/n), sum = 0;
    
        while (q-- > 0) {  
            sum += delta;
            e = sum>>>2 & 3;
            for (var p = 0; p < n; p++) {
                y = v[(p+1)%n];
                mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
                z = v[p] += mx;
            }
        }
    
        var ciphertext = Tea.longsToStr(v);
    
        return Base64.encode(ciphertext);
    }

    Tea.decrypt = function(ciphertext, password) {
        if (ciphertext.length == 0) return('');
        var v = Tea.strToLongs(Base64.decode(ciphertext));
        var k = Tea.strToLongs(Utf8.encode(password).slice(0,16)); 
        var n = v.length;
    
        var z = v[n-1], y = v[0], delta = -0x658C6C4C;
        var mx, e, q = Math.floor(6 + 52/n), sum = q*delta;

        while (sum != 0) {
            e = sum>>>2 & 3;
            for (var p = n-1; p >= 0; p--) {
                z = v[p>0 ? p-1 : n-1];
                mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
                y = v[p] -= mx;
            }
            sum -= delta;
        }
    
        var plaintext = Tea.longsToStr(v);
        plaintext = plaintext.replace(/\0+$/,'');

        return Utf8.decode(plaintext);
    }


    Tea.strToLongs = function(s) {  
        var l = new Array(Math.ceil(s.length/4));
        for (var i=0; i<l.length; i++) {
            l[i] = s.charCodeAt(i*4) + (s.charCodeAt(i*4+1)<<8) + 
               (s.charCodeAt(i*4+2)<<16) + (s.charCodeAt(i*4+3)<<24);
        }
        return l;  

    Tea.longsToStr = function(l) {  
        var a = new Array(l.length);
        for (var i=0; i<l.length; i++) {
            a[i] = String.fromCharCode(l[i] & 0xFF, l[i]>>>8 & 0xFF, 
                                       l[i]>>>16 & 0xFF, l[i]>>>24 & 0xFF);
        }
        return a.join('');
    }

    module.exports = Tea;

    var Base64 = {};  

    Base64.code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    Base64.encode = function(str, utf8encode) {  
      utf8encode =  (typeof utf8encode == 'undefined') ? false : utf8encode;
      var o1, o2, o3, bits, h1, h2, h3, h4, e=[], pad = '', c, plain, coded;
      var b64 = Base64.code;
   
      plain = utf8encode ? Utf8.encode(str) : str;
  
      c = plain.length % 3;  
      if (c > 0) { while (c++ < 3) { pad += '='; plain += '\0'; } }
      
      for (c=0; c<plain.length; c+=3) {  
        o1 = plain.charCodeAt(c);
        o2 = plain.charCodeAt(c+1);
        o3 = plain.charCodeAt(c+2);
        bits = o1<<16 | o2<<8 | o3;
        h1 = bits>>18 & 0x3f;
        h2 = bits>>12 & 0x3f;
        h3 = bits>>6 & 0x3f;
        h4 = bits & 0x3f;

        e[c/3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
      }
      coded = e.join(''); 
      coded = coded.slice(0, coded.length-pad.length) + pad;
   
  return coded;
}

Base64.decode = function(str, utf8decode) {
  utf8decode =  (typeof utf8decode == 'undefined') ? false : utf8decode;
  var o1, o2, o3, h1, h2, h3, h4, bits, d=[], plain, coded;
  var b64 = Base64.code;

  coded = utf8decode ? Utf8.decode(str) : str;
  for (var c=0; c<coded.length; c+=4) {  
    h1 = b64.indexOf(coded.charAt(c));
    h2 = b64.indexOf(coded.charAt(c+1));
    h3 = b64.indexOf(coded.charAt(c+2));
    h4 = b64.indexOf(coded.charAt(c+3));
    bits = h1<<18 | h2<<12 | h3<<6 | h4;
      
    o1 = bits>>>16 & 0xff;
    o2 = bits>>>8 & 0xff;
    o3 = bits & 0xff;
    
    d[c/4] = String.fromCharCode(o1, o2, o3);
    
    if (h4 == 0x40) d[c/4] = String.fromCharCode(o1, o2);
    if (h3 == 0x40) d[c/4] = String.fromCharCode(o1);
  }
  plain = d.join('');   
  return utf8decode ? Utf8.decode(plain) : plain; 
}


var Utf8 = {};  
Utf8.encode = function(strUni) {
  
  var strUtf = strUni.replace(
      /[\u0080-\u07ff]/g,  
      function(c) { 
        var cc = c.charCodeAt(0);
        return String.fromCharCode(0xc0 | cc>>6, 0x80 | cc&0x3f); }
    );
  strUtf = strUtf.replace(
      /[\u0800-\uffff]/g,  
      function(c) { 
        var cc = c.charCodeAt(0); 
        return String.fromCharCode(0xe0 | cc>>12, 0x80 | cc>>6&0x3F, 0x80 | cc&0x3f); }
    );
  return strUtf;
}


Utf8.decode = function(strUtf) {
 
  var strUni = strUtf.replace(
      /[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,  
      function(c) {  
        var cc = ((c.charCodeAt(0)&0x0f)<<12) | ((c.charCodeAt(1)&0x3f)<<6) | ( c.charCodeAt(2)&0x3f); 
        return String.fromCharCode(cc); }
    );
  strUni = strUni.replace(
      /[\u00c0-\u00df][\u0080-\u00bf]/g,                 
      function(c) {  
        var cc = (c.charCodeAt(0)&0x1f)<<6 | c.charCodeAt(1)&0x3f;
        return String.fromCharCode(cc); }
    );
  return strUni;
}


var date = Tea.decrypt(readFileSync(process.argv[2]).toString(),"@DvlJs");

var xd = date.split("}");
var json = (xd[0]+"}");


const data = JSON.parse(json);
console.log('');
console.log("[ > ] PSInstall:>" +data.PSInstall);
console.log("[ > ] DeviceID:>" +data.DeviceID);
console.log("[ > ] RootBlock:>" +data.RootBlock);
console.log("[ > ] MobileData:>" +data.MobileData);
console.log("[ > ] ExpireDate:>" +data.ExpireDate);
console.log("[ > ] Message:>" +data.Message);
console.log("[ > ] Payload:>" +data.Payload);
console.log("[ > ] isDirect:>" +data.isDirect);
console.log("[ > ] isSSL:>" +data.isSSL);
console.log("[ > ] isWS:>" +data.isWS);
console.log("[ > ] DNS:>" +data.isDNS);
console.log("[ > ] Server:>" +data.Server);
console.log('[+]Module by @DvlJs');


}
