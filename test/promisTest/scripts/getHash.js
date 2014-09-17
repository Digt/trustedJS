//Получение Хэша Сертификата
cert1.getHash().then(function (result) {
    var testName = "Проверка хэша сертификата";
    var testCase = "Хэш проверяемого файла";
    var str = Hex.toDer("3e2bf7f2031b96f38ce6c4d8a85d3e2d58476a0f");
    if (result !== str)
        print(testName, "Хэш не совпадает!", "fail", testCase);
}, function (error) {
    var testName = "Проверка хэша сертификата";
    var testCase = "Хэш проверяемого файла";
    print(testName, "Что-то пошло не так: " + error, "error", testCase);
});
cert2.getHash().then(function (result) {
    var testName = "Проверка хэша";
    var testCase = "Хэш другого файла";
    var str = Hex.toDer("3e2bf7f2031b96f38ce6c4d8a85d3e2d58476a0f");
    if (result === str)
        print(testName, "Хэш совпадает!", "fail", testCase);
}, function (error) {
    var testName = "Проверка хэша";
    var testCase = "Хэш проверяемого файла";
    print(testName, "Что-то пошло не так: " + error, "error", testCase);
});

//Получение хэша signeed data
signeedData.getHash().then(function (result) {
    var testName = "Проверка хэша signeed data";
    var testCase = "Хэш проверяемого файла";
    var selfHash = Hex.toDer("B61F43AAE0132C461226ED62A9DB1FF3AD30D723");
    if (result !== selfHash)
        print(testName, "Хэш не совпадает!", "fail", testCase);
}, function (error) {
    var testName = "Проверка хэша signeed data";
    var testCase = "Хэш проверяемого файла";
    print(testName, "Что-то пошло не так: " + error, "error", testCase);
});
signeedData.getHash().then(function (result) {
    var testName = "Проверка хэша signeed data";
    var testCase = "Хэш проверяемого файла";
    var selfHash = Hex.toDer("B61F43AA00132C461226ED62A9DB1FF3AD30D723");
    if (result === selfHash)
        print(testName, "Хэш не совпадает!", "fail", testCase);
}, function (error) {
    var testName = "Проверка хэша signeed data";
    var testCase = "Хэш другого файла";
    print(testName, "Что-то пошло не так: " + error, "error", testCase);
});