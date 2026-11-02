#include "pch.h"
#include "Helpers.h"

bool Helpers::Readable(const void* pointer, size_t size)
{
    uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
    if (!address)
    {
        return false;
    }

    if (!size)
    {
        return true;
    }

    const uintptr_t lastAddress = address + size - 1;
    if (lastAddress < address)
    {
        return false;
    }

    while (address <= lastAddress)
    {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &info, sizeof(info)) != sizeof(info))
        {
            return false;
        }

        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        {
            return false;
        }

        const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (regionEnd <= address)
        {
            return false;
        }

        address = regionEnd;
    }

    return true;
}

bool Helpers::Inside(uintptr_t address, size_t size)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dosHeader->e_lfanew);
    const uintptr_t end = base + ntHeaders->OptionalHeader.SizeOfImage;

    return address >= base && address < end && size <= end - address
        && Readable(reinterpret_cast<const void*>(address), size);
}

std::string Helpers::ReadString(const void* string)
{
    std::string out;
    ReadString(string, out);
    return out;
}

bool Helpers::ReadString(const void* string, std::string& out)
{
    if (!Readable(string, 24))
    {
        return false;
    }

    const auto* bytes = static_cast<const uint8_t*>(string);
    uint32_t length = 0;
    uint32_t capacity = 0;
    std::memcpy(&length, bytes + 16, sizeof(length));
    std::memcpy(&capacity, bytes + 20, sizeof(capacity));

    if (length > 0x4000000 || length > capacity)
    {
        return false;
    }

    const char* data = static_cast<const char*>(string);
    if (capacity >= 16)
    {
        std::memcpy(&data, bytes, sizeof(data));
    }

    if (!Readable(data, length))
    {
        return false;
    }

    out.assign(data, length);
    return true;
}
