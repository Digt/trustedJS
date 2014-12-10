if (window.trusted === undefined)
    throw "Модуль trusted не инециализирован";

if (trusted.PKI === undefined)
    throw "Модуль trusted.PKI не инециализирован";

trusted.CMS = {};

/**
 * Возвращает объект полученный из буфера по заданной схеме.
 * @param {type} buf Буфер. Параметр может быть двух типов - бинарная строка и Буфер.
 * @param {type} schemaName Имя схемы.
 * @returns {Object}
 */
function objFromBuffer(buf, schemaName){
    if (trusted.isString(buf))
        buf = new trusted.Buffer(buf, "binary");
    if (buf.type!=="Buffer" && !buf.__proto__.hasOwnProperty("toArrayBuffer"))
        return buf;
    var asn = new trusted.ASN(buf);
    var obj = asn.toObject(schemaName);
    return obj;
}