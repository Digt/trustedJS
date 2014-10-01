/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

if (window.trusted === undefined)
    window.trusted = {};

/**
 * Перебирает все атрибуты Объекта.
 * @param {Object} obj Объект атрибуты которого перебираются.
 * @param {function} call Callback функция. Вызывается при обращении к каждомк атрибуту Объекта.
 */
trusted.objEach = function(obj, call) {
    if (typeof (obj) === "object") {
        var keys = Object.keys(obj);
        for (var i = 0; i < keys.length; i++)
            call(obj[keys[i]], keys[i]);
    }
};

function ASNDeepCount(asn) {
    if (asn.sub !== null)
        return 1 + ASNDeepCount(asn.sub[0]);
    return 0;
}

/**
 * Объединяет два объекта в один. 
 * @param {Object} obj1 
 * Объект 1. Данному объекту присваиваются атрибуты Объекта 2
 * @param {Object} obj2 Объект 2. Атрибуты данного объекта присваиваются Объекту 1.
 * @param {Boolean} replace Логическое значение. Определяет будет ли произведена перезапись совпадающих атрибутов.
 */
trusted.objUnion = function(obj1, obj2, replace) {
    replace = (replace === undefined) ? false : replace;

    trusted.objEach(obj2, function(prop, propName) {
        if ((replace || !obj1.hasOwnProperty(propName)))//||obj1.type!==obj2.type
            obj1[propName] = prop;
    });
};

/**
 * Возвращает значения параметров объекта в виде массива.
 * @param {Object} obj
 * @returns {Array}
 */
trusted.objToArray = function(obj) {
    if (typeof (obj) !== "object")
        return [];

    var arr = [];
    for (var key in obj)
        if (obj.hasOwnProperty(key))
            arr.push(obj[key]);
    return arr;
};

trusted.isArray = function(obj) {
    return obj instanceof Array;
};

trusted.isNumber = function(obj) {
    return typeof (obj) === "number"
};

trusted.isString = function(obj) {
    return typeof (obj) === "string"
};
trusted.isBoolean = function(obj) {
    return typeof (obj) === "boolean";
};
trusted.isObject = function(obj) {
    return typeof (obj) === "object";
};

//Utf8
trusted.Utf8 = {
    toDer: function(string) {
        var der = string;
        // encode DER
        var result = "";
        for (var i = 0; i < der.length; i++) {
            var char = der.charCodeAt(i);
            if (char < 256) {
                result += String.fromCharCode(char);
            }
            else if (char < (256 * 256)) {
                result += String.fromCharCode((char >> 6) | 192); // 1 byte
                result += String.fromCharCode((char & 63) | 128); // 2 byte
            } else if (char < (256 * 256 * 256)) {
                result += String.fromCharCode((char >> 12) | 224); // 1 byte
                result += String.fromCharCode(((char >> 6) & 63) | 128); // 2 byte
                result += String.fromCharCode((char & 63) | 128); // 3 byte
            } else
                throw "Символ состоит более чем из трех байтов. Преобразование еще не реализовано."
        }
        return result;
    },
    fromDer: function(der) {
        var s = "";
        for (var i = 0; i < der.length; ) {
            var c = der.charCodeAt(i++);
            if (c < 128)
                s += String.fromCharCode(c);
            else if ((c > 191) && (c < 224))
                s += String.fromCharCode(((c & 0x1F) << 6) | (der.charCodeAt(i++) & 0x3F));
            else
                s += String.fromCharCode(((c & 0x0F) << 12) | ((der.charCodeAt(i++) & 0x3F) << 6) | (der.charCodeAt(i++) & 0x3F));
        }
        return s;
    }
};