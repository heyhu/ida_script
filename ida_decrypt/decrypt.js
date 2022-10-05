function hookInit(){
    var linkername;
    var alreadyHook = false;
    var call_constructor_addr = null;
    var arch = Process.arch;
    if (arch.endsWith("arm")) {
        linkername = "linker";
    } else {
        linkername = "linker64";
    }

    var symbols = Module.enumerateSymbolsSync(linkername);
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("call_constructor") !== -1) {
            call_constructor_addr = symbol.address;
        }
    }

    if (call_constructor_addr.compare(NULL) > 0) {
        console.log("get construct address");
        Interceptor.attach(call_constructor_addr, {
            onEnter: function (args) {
                if(alreadyHook === false){
                    const targetModule = Process.findModuleByName("libmtguard.so");
                    if (targetModule !== null) {
                        alreadyHook = true;
                        inittodo();
                    }
                }
            }
        });
    }
}

function inittodo(){
    hook_sub_5124();
}

function hook_sub_5124(){
    var index = 0
    var base_addr = Module.findBaseAddress("libmtguard.so");
    console.log("enter")
    Interceptor.attach(base_addr.add(0x5125), {
        onEnter(args) {
            index += 1;
            this.buffer = args[0];
            this.length = args[3];
            this.LR = this.context.lr - base_addr - 5;
        },
        onLeave() {
            var decryptAddress = this.buffer - base_addr;
            console.log("index:"+ index + " $&$ decryptAddress:" + decryptAddress.toString(16) + " $&$ length:" +
                this.length + " $&$ decryptStr:"+toHex(this.buffer.readCString()) + " $&$ callAddress:"+this.LR.toString(16))
        }
    });
}

function toHex(str) {
    var result = '';
    for (var i=0; i<str.length; i++) {
        result += str.charCodeAt(i).toString(16);
    }
    return result;
}

function toHex(str) {
    var result = '';
    for (var i=0; i<str.length; i++) {
        result += str.charCodeAt(i).toString(16);
    }
    return result;
}

// 执行 hookinit
hookInit();