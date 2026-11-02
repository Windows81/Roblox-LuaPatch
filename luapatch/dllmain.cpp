#include "pch.h"

#include "Configuration.h"
#include "Patches.h"

#if defined(CLIENT)
#include "Hooks/LuaVM.h"
#else
#include "Hooks/LuaSerializer.h"
#endif

void __declspec(dllexport) import() {}

static DWORD WINAPI Start(LPVOID)
{
#if defined(CLIENT)
    LuaVM__Initialize();
    const bool applied = Patches::Apply(
        reinterpret_cast<void*>(ADDRESS_LUAVM__LOAD),
        reinterpret_cast<void*>(LuaVM__load_hook),
        reinterpret_cast<void**>(&LuaVM__load));
#else
    const bool applied = Patches::Apply(
        reinterpret_cast<void*>(ADDRESS_LUASERIALIZER__WRITE),
        reinterpret_cast<void*>(LuaSerializer__write_hook),
        reinterpret_cast<void**>(&LuaSerializer__write));
#endif
    if (!applied)
    {
        MessageBoxA(nullptr,
            "luapatch hooks failed.\n\n"
            "possible causes:\n"
            "- you have built for client, and accidentally loaded a client build on the server.\n"
            "- you have built for server, and accidentally loaded a server build on the client.\n"
            "- your addresses are incorrect.",
            "luapatch",
            MB_OK | MB_ICONERROR);

        return ERROR_DLL_INIT_FAILED;
    }

    return ERROR_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        HANDLE thread = CreateThread(nullptr, 0, Start, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
