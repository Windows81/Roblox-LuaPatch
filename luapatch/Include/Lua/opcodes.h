#pragma once

#include <cstdint>

// https://github.com/Melanie0001/Script-Ware/blob/fd8d2f81f02b29a471296da716b68fcbdb924ea6/src/convert.h#L58
// script-ware seems to fuck up with OP_MOD and OP_SUB
inline constexpr uint8_t get_roblox_opcode[38]{
    6,  // OP_MOVE
    4,  // OP_LOADK
    0,  // OP_LOADBOOL
    7,  // OP_LOADNIL
    2,  // OP_GETUPVAL
    8,  // OP_GETGLOBAL
    1,  // OP_GETTABLE
    3,  // OP_SETGLOBAL
    5,  // OP_SETUPVAL
    15, // OP_SETTABLE
    13, // OP_NEWTABLE
    9,  // OP_SELF
    16, // OP_ADD
    11, // OP_SUB
    17, // OP_MUL
    10, // OP_DIV
    12, // OP_MOD
    14, // OP_POW
    24, // OP_UNM
    22, // OP_NOT
    18, // OP_LEN
    25, // OP_CONCAT
    20, // OP_JMP
    26, // OP_EQ
    19, // OP_LT
    21, // OP_LE
    23, // OP_TEST
    33, // OP_TESTSET
    31, // OP_CALL
    27, // OP_TAILCALL
    34, // OP_RETURN
    29, // OP_FORLOOP
    35, // OP_FORPREP
    28, // OP_TFORLOOP
    30, // OP_SETLIST
    32, // OP_CLOSE
    37, // OP_CLOSURE
    36, // OP_VARARG
};

struct opcode
{
    uint8_t value[38] = {};

    constexpr opcode()
    {
        for (int i = 0; i < 38; ++i) value[i] = 0xFF;

        for (int i = 0; i < 38; ++i)
            if (get_roblox_opcode[i] < 38) value[get_roblox_opcode[i]] = static_cast<uint8_t>(i);
    }
};

inline constexpr opcode get_vanilla_opcode{};
