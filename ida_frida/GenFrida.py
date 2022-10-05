from string import Template
import ida_lines
import idaapi
import idc
from ida_idaapi import plugin_t

hook_function_template = """
function hook_$functionName(){
    var base_addr = Module.findBaseAddress("$soName");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $functionName");
            $args
        },
        onLeave(retval) {
            $result
            console.log("leave $functionName");
        }
    });
}
"""

inline_hook_template = """
function hook_$offset(){
    var base_addr = Module.findBaseAddress("$soName");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $offset");
            console.log(JSON.stringify(this.context));
        },
    });
}
"""

logTemplate = 'console.log("arg$index:"+args[$index]);\n'

dlopenAfter_template = """
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
if(android_dlopen_ext != null){
    Interceptor.attach(android_dlopen_ext,{
        onEnter: function(args){
            var soName = args[0].readCString();
            if(soName.indexOf("$soName") !== -1){
                this.hook = true;
            }
        },
        onLeave: function(retval){
            if(this.hook) {
                this.hook = false;
                dlopentodo();
            }
        }
    });
}

function dlopentodo(){
    //todo
}
"""

init_template = """
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
                    const targetModule = Process.findModuleByName("$soName");
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
    //todo
}
"""

dump_template = """
// 由ShowFridaCode生成的dump memory
function dump_$offset() {
    var base_addr = Module.findBaseAddress("$soName");
    var dump_addr = base_addr.add($offset);
    console.log(hexdump(dump_addr, {length: $length}));
}
"""


def generate_printArgs(argNum):
    if argNum == 0:
        return "// no args"
    else:
        temp = Template(logTemplate)
        logText = ""
        for i in range(argNum):
            logText += temp.substitute({'index': i})
            logText += "            "
        return logText


def generate_for_func(soName, functionName, address, argNum, hasReturn):
    # 根据参数个数打印
    argsPrint = generate_printArgs(argNum)
    # 根据是否有返回值判断是否打印retval
    retPrint = "// no return"
    if hasReturn:
        retPrint = "console.log(retval);"
    # 使用Python提供的Template字符串模板方法
    temp = Template(hook_function_template)
    offset = getOffset(address)
    result = temp.substitute(
        {'soName': soName, "functionName": functionName, "offset": hex(offset), "args": argsPrint, "result": retPrint})
    print(result)


def getOffset(address):
    if idaapi.get_inf_structure().is_64bit():
        return address
    else:
        return address + idc.get_sreg(address, "T")


def generate_for_inline(soName, address):
    offset = getOffset(address)
    temp = Template(inline_hook_template)
    result = temp.substitute({'soName': soName, "offset": hex(offset)})
    if idaapi.is_call_insn(address):
        callAddr = idaapi.get_name_ea(0, idc.print_operand(address, 0))
        if callAddr != idaapi.BADADDR:
            callAddress = idc.get_operand_value(address, 0)
            argnum, _ = get_argnum_and_ret(callAddress)
            argsPrint = generate_printArgs(argnum)
            print(result.replace("console.log(JSON.stringify(this.context));", argsPrint))
        else:
            print(result)
    else:
        print(result)


def get_argnum_and_ret(address):
    cfun = idaapi.decompile(address)
    argnum = len(cfun.arguments)
    ret = True
    dcl = ida_lines.tag_remove(cfun.print_dcl())
    if (dcl.startswith("void ") is True) & (dcl.startswith("void *") is False):
        ret = False
    return argnum, ret


def generate_for_func_by_address(addr):
    soName = idaapi.get_root_filename()
    functionName = idaapi.get_func_name(addr)
    argnum, ret = get_argnum_and_ret(addr)
    generate_for_func(soName, functionName, addr, argnum, ret)


def generate_for_inline_by_address(addr):
    soName = idaapi.get_root_filename()
    generate_for_inline(soName, addr)


def generate_snippet(addr):
    startAddress = idc.get_func_attr(addr, 0)
    if startAddress == addr:
        generate_for_func_by_address(addr)
    elif startAddress == idc.BADADDR:
        print("不在函数内")
    else:
        generate_for_inline_by_address(addr)


def generateInitCode():
    soName = idaapi.get_root_filename()
    print(Template(dlopenAfter_template).substitute({'soName': soName}))
    print(Template(init_template).substitute({'soName': soName}))


def generate_dump_script(start, length):
    soName = idaapi.get_root_filename()
    print(Template(dump_template).substitute({'soName': soName, "offset" : hex(start), "length" : hex(length)}))


class Hook(idaapi.View_Hooks):
    def view_dblclick(self, view ,event):
        widgetType = idaapi.get_widget_type(view)
        if widgetType == idaapi.BWN_DISASM:
            global initialized
            if not initialized:
                initialized = True
                generateInitCode()
            address = idaapi.get_screen_ea()
            generate_snippet(address)

    def view_click(self, view, event):
        widgetType = idaapi.get_widget_type(view)
        if widgetType == idaapi.BWN_DISASM:
            start = idc.read_selection_start()
            end = idc.read_selection_end()
            if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
                length = end - start
                generate_dump_script(start, length)


class GenFrida_Plugin_t(plugin_t):
    # 关于插件的注释
    # 当鼠标浮于菜单插件上方时，IDA左下角所示
    comment = "A Toy Plugin for Generating Frida Code"
    # 帮助信息，我们选择不填
    help = "unknown"
    # 插件的特性，是一直在内存里，还是运行一下就退出，等等
    flags = idaapi.PLUGIN_KEEP
    # 插件的名字
    wanted_name = "ShowFridaCode"
    # 快捷键，我们选择置空不弄
    wanted_hotkey = ""

    # 插件刚被加载到IDA内存中
    # 这里适合做插件的初始化工作
    def init(self):
        print("ShowFridaCode init")
        return idaapi.PLUGIN_KEEP

    # 插件运行中
    # 这里是主要逻辑
    def run(self, arg):
        print("ShowFridaCode run")
        global myViewHook
        myViewHook = Hook()
        myViewHook.hook()

    # 插件卸载退出的时机
    # 这里适合做资源释放
    def term(self):
        pass


initialized = False
# register IDA plugin
def PLUGIN_ENTRY():
    return GenFrida_Plugin_t()
