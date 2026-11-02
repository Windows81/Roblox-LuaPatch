#pragma once

#include "Configuration.h"

struct InstructionEncoder { uint8_t data[32]; };
static_assert(sizeof(InstructionEncoder) == 32 && alignof(InstructionEncoder) <= 4);

#if defined(BEFORE_CALL_SCRAMBLE)

typedef void* (__cdecl* LuaSerializer__write_t)(void* out, void* state, void* source, void* extra);
void* __cdecl LuaSerializer__write_hook(void* out, void* state, void* source, void* extra);

#else

typedef void* (__cdecl* LuaSerializer__write_t)(void* out, void* state, void* source,
    InstructionEncoder encoder, unsigned int ckey);

void* __cdecl LuaSerializer__write_hook(void* out, void* state, void* source,
    InstructionEncoder encoder, unsigned int ckey);

#endif

extern LuaSerializer__write_t LuaSerializer__write;
extern String__assign_t String__assign;
