#pragma once

#include "Configuration.h"

typedef int(__cdecl* LuaVM__load_t)(void* state, void* source, const char* chunkname, unsigned int modkey);

int __cdecl LuaVM__load_hook(void* state, void* source, const char* chunkname, unsigned int modkey);

extern LuaVM__load_t LuaVM__load;
extern String__assign_t String__assign;

void LuaVM__Initialize();
