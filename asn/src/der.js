var Der = {};
Der.toHex = function(der) {
    if (der === undefined || der === null)
        return null;
    var hex = '';
    for (var i = 0; i < der.length; i++) {
        var char = der.charCodeAt(i).toString(16);
        if ((char.length % 2) > 0)
            char = "0" + char;
        hex += char;
    }
    return hex.toUpperCase();
};
Der.fromNumArray = function(numArray) {
    var der = '';
    if (!trusted.isArray(numArray))
        throw "Der.fromNumArray: Параметр должен быть массивом";
    for (var i = 0; i < numArray.length; i++) {
        if (!trusted.isNumber(numArray[i]))
            throw "Der.fromNumArray: Элемент массива дожен быть Числом";
        der += String.fromCharCode(numArray[i]);
    }
    return der;
};
