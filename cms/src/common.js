if (window.trusted === undefined)
    throw "Модуль trusted не инециализирован";

if (trusted.PKI === undefined)
    throw "Модуль trusted.PKI не инециализирован";

trusted.CMS = {};