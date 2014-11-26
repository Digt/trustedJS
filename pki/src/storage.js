function Store(){
    var _items=[];
    
    this.__proto__={
        get items(){
            return _items;
        }
    };
    
    /**
     * Открывает хранилище в памяти
     * @returns {undefined}
     */
    this.__proto__.open=function(){
        
    };
    
    this.__proto__.add = function(item){
      //check item  
    };
}

//export
trusted.PKI.Store = Store;