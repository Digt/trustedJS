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

function ASNDeepCount(asn){
    if (asn.sub!==null)
        return 1+ASNDeepCount(asn.sub[0]);
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

trusted.isArray=function(obj){
    if (obj instanceof Array)
        return true;
    return false;
};

trusted.isNumber=function(obj){
    if (typeof(obj)==="number")
        return true;
    return false;
};

trusted.isString=function(obj){
    if (typeof(obj)==="string")
        return true;
    return false;
};
trusted.isBoolean=function(obj){
    if (typeof(obj)==="boolean")
        return true;
    return false;
};
trusted.isObject=function(obj){
    if (typeof(obj)==="object")
        return true;
    return false;
};