#include "pch.h"
#include "Patches.h"

#include <MinHook.h>

bool Patches::Apply(void* target, void* hook, void** original)
{
    MH_STATUS status = MH_Initialize();
    if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED)
    {
        status = MH_CreateHook(target, hook, original);
        if (status == MH_OK)
        {
            status = MH_EnableHook(target);
        }
    }

    return status == MH_OK;
}
