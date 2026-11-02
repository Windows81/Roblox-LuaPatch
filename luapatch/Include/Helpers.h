#pragma once

#include "pch.h"

typedef void*(__thiscall* String__assign_t)(void* self, const void* data, size_t size);

class Helpers
{
public:
    static bool Inside(uintptr_t address, size_t size);
    static bool Readable(const void* pointer, size_t size);

    static std::string ReadString(const void* string);
    static bool ReadString(const void* string, std::string& out);
};

#define LOCATION(x) (static_cast<uintptr_t>(x) - 0x400000 + reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr)))
