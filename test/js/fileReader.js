/*jshint browser: true, strict: true, globalstrict: true, indent: 4, immed: true, latedef: true, undef: true, regexdash: false */
/*global Hex, Base64, ASN1 */
"use strict";

var reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;

function id(elementName) {
    var element = document.getElementById(elementName);
    if (element === undefined)
        throw "Элемент с именем %s не найден", elementName;
    return element;
}

function clearAll() {
    id('pem').value = '';
    //id('tree').innerHTML = '';
    //id('dump').innerHTML = '';
    return false;
}
function decodeBinaryString(str) {
    var der;
    try {
        if (reHex.test(str))
            der = Hex.decode(str);
        else if (Base64.re.test(str))
            der = Base64.unarmor(str);
        else {
            der = [];
            for (var i = 0; i < str.length; ++i)
                der[i] = str.charCodeAt(i);
            return der;
        }
    } catch (e) {
        console.log('Cannot decode file.');
    }
    return false;
}

// this is only used if window.FileReader
function read(f) {
    var pem = id('pem');
    if (pem !== null)
        pem.value = ''; // clear text area, will get hex content
    var r = new FileReader();
    r.onloadend = function() {
        if (r.error) {
            alert("Your browser couldn't read the specified file (error code " + r.error.code + ").");
        } else {
            var str = r.result;
            //alert("File loaded");
            if ("fileLoaded" in window)
                window.fileLoaded(r.result);
            //console.time("CRL");
            //console.log(window.trustedJS.ASN.ASN1.decode(der).toObject("CertificateList"));
            //console.timeEnd("CRL");
            //var pem = r.result;
            //var der = reHex.test(pem) ? Hex.decode(pem) : Base64.unarmor(pem);
            //console.log("Der: %o", der);
        }
    };
    r.readAsBinaryString(f);
}
function load() {
    var file = id('file');
    if (file.files.length === 0) {
        alert("Select a file to load first.");
        return false;
    }
    read(file.files[0]);
    return false;
}
function stop(e) {
    e.stopPropagation();
    e.preventDefault();
}

function dragAccept(e) {
    stop(e);
    if (e.dataTransfer.files.length > 0)
        read(e.dataTransfer.files[0]);
}

window.onload = function() {
    document.ondragover = stop;
    document.ondragleave = stop;
    if ('FileReader' in window) {
        id('file').style.display = 'block';
        id('file').onchange = load;
        document.ondrop = dragAccept;
    }
};
