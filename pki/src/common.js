if (window.trusted === undefined)
    window.trusted = {};

trusted.PKI = {};

function getExtnByOID(extns, oid) {
    if (trusted.isString(oid))
        oid = new trusted.PKI.OID(oid);
    if (!(trusted.isObject(oid)) || oid === undefined)
        throw "Certificate.getExtnByOID: Параметр oid имеет неверное значение";
    var res = null;
    for (var i = 0; i < extns.length; i++) {
        if (extns[i].extnID.value === oid.value)
            return extns[i];
    }
    return res;
}