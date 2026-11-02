function cppHex(value) {
    return "0x" + (value >>> 0).toString(16).toUpperCase().padStart(8, "0");
}

function cppHeader(client, server, beforeCallScramble) {
    const out = [];
    const define = (name) => "#define " + name.padEnd(33);

    out.push("#pragma once", "", '#include "Helpers.h"', "");
    if (beforeCallScramble) out.push("#define BEFORE_CALL_SCRAMBLE", "");

    out.push("#if defined(CLIENT)", "");

    if (client) {
        out.push('#define MODULE_NAME "client"');
        out.push(define("ADDRESS_LUAVM__LOAD") + "LOCATION(" + cppHex(client.LuaVM__load) + ")");
        out.push(define("ADDRESS_LUAVM__STRING_ASSIGN") + "LOCATION(" + cppHex(client.stringAssign) + ")");

        const tables = (client.tables || []).map((t) => cppHex(t.va));
        if (!tables.length && client.gCoreScripts !== undefined) tables.push(cppHex(client.gCoreScripts));
        out.push("inline constexpr uintptr_t ADDRESS_CORESCRIPTS[] = {" +
                 (tables.length ? " " + tables.join(", ") + " " : "") + "};");
        out.push("#define OFFSET_PROTECTEDSTRING__BYTECODE 0x" +
                 (client.bytecodeOffset >>> 0).toString(16).toUpperCase());
    }

    out.push("", "", "#elif defined(SERVER)", "");

    if (server) {
        out.push('#define MODULE_NAME "server"');
        out.push(define("ADDRESS_LUASERIALIZER__WRITE") + "LOCATION(" + cppHex(server.LuaSerializer__write) + ")");
        out.push(define("ADDRESS_LUAVM__STRING_ASSIGN") + "LOCATION(" + cppHex(server.stringAssign) + ")");
    } else {
        out.push("// server not given");
    }

    out.push("", "", "#else", '#error "define CLIENT or SERVER"', "#endif");

    return out.join("\n");
}
