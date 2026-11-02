#pragma once

#include "Helpers.h"

#define BEFORE_CALL_SCRAMBLE

#if defined(CLIENT)

#define MODULE_NAME "client"
#define ADDRESS_LUAVM__LOAD              LOCATION(0x00402B80)
#define ADDRESS_LUAVM__STRING_ASSIGN     LOCATION(0x00406C10)
inline constexpr uintptr_t ADDRESS_CORESCRIPTS[] = { 0x0119F1B0 };
#define OFFSET_PROTECTEDSTRING__BYTECODE 0x18


#elif defined(SERVER)

#define MODULE_NAME "server"
#define ADDRESS_LUASERIALIZER__WRITE     LOCATION(0x0040A740)
#define ADDRESS_LUAVM__STRING_ASSIGN     LOCATION(0x00404010)


#else
#error "define CLIENT or SERVER"
#endif