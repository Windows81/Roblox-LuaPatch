#if defined(CLIENT)

#include "pch.h"
#include "Helpers.h"
#include "Hooks/LuaVM.h"
#include "Lua/rsb1.h"

LuaVM__load_t LuaVM__load = nullptr;
String__assign_t String__assign =
    reinterpret_cast<String__assign_t>(ADDRESS_LUAVM__STRING_ASSIGN);

namespace
{
    struct CoreScript
    {
        const char* name;
        const char* data;
        uint32_t size;
    };

    std::vector<std::string_view> coreScripts;

    bool Allowed(std::string_view blob)
    {
        for (std::string_view script : coreScripts)
        {
            if (script.size() == blob.size()
                && !std::memcmp(script.data(), blob.data(), blob.size()))
            {
                return true;
            }
        }

        return false;
    }

    uint32_t Inverse(uint32_t value)
    {
        uint32_t x = value;
        for (int i = 0; i < 5; ++i)
        {
            x *= 2u - value * x;
        }

        return x;
    }

    uint32_t SessionKey(void* state)
    {
        const uintptr_t at = reinterpret_cast<uintptr_t>(state) + 8;
        if (!Helpers::Readable(reinterpret_cast<const void*>(at), sizeof(uint32_t)))
        {
            return 0;
        }

        const uint32_t encoded = *reinterpret_cast<const uint32_t*>(at);
        const uintptr_t object = at + encoded;
        const uintptr_t slot = object + 28;
        if (!Helpers::Readable(reinterpret_cast<const void*>(slot), sizeof(uint32_t)))
        {
            return 0;
        }

        return *reinterpret_cast<const uint32_t*>(slot) + static_cast<uint32_t>(slot);
    }

    bool Convert(void* state, std::string_view blob,
                 std::vector<uint8_t>& out, std::string& error)
    {
        std::vector<uint8_t> stream;
        std::string text;

        if (!rsb1::decode_blob(blob.data(), blob.size(), stream, error))
        {
            return false;
        }

        if (!rsb1::extract_source(stream, &text))
        {
            error = "no source";
            return false;
        }

        static uint32_t sessionEncode = 0;
        if (!sessionEncode)
        {
            const uint32_t decode = SessionKey(state);
            if (!decode)
            {
                error = "session key unavailable";
                return false;
            }

            sessionEncode = Inverse(decode);
        }

        if (!rsb1::build_stream(text, "=script", sessionEncode, stream, error))
        {
            return false;
        }

        rsb1::embed_source(stream, text);
        out = rsb1::wrap_stream(stream);
        return true;
    }
}

int __cdecl LuaVM__load_hook(void* state, void* source, const char* chunkname, unsigned int modkey)
{
    if (source)
    {
        void* slot = static_cast<uint8_t*>(source) + OFFSET_PROTECTEDSTRING__BYTECODE;

        std::string blob;
        if (!Helpers::ReadString(slot, blob))
        {
            String__assign(slot, "", 0);
            return LuaVM__load(state, source, chunkname, modkey);
        }

        if (blob.size() >= 12 && !Allowed(blob))
        {
            std::vector<uint8_t> wire;
            std::string error;
            bool converted = false;

            try
            {
                converted = Convert(state, blob, wire, error);
            }
            catch (...)
            {
                error = "exception";
            }

            if (converted)
            {
                String__assign(slot, wire.data(), wire.size());
            }
            else
            {
                String__assign(slot, "", 0);
            }
        }
    }

    return LuaVM__load(state, source, chunkname, modkey);
}

void LuaVM__Initialize()
{
    coreScripts.clear();

    for (uintptr_t address : ADDRESS_CORESCRIPTS)
    {
        for (uintptr_t at = LOCATION(address); Helpers::Inside(at, sizeof(CoreScript));
             at += sizeof(CoreScript))
        {
            const auto& script = *reinterpret_cast<const CoreScript*>(at);

            if (!script.size || script.size > 0x4000000
                || !Helpers::Inside(reinterpret_cast<uintptr_t>(script.data), script.size)
                || !Helpers::Inside(reinterpret_cast<uintptr_t>(script.name), 128))
            {
                break;
            }

            size_t length = 0;
            while (length < 128 && script.name[length] >= 0x20 && script.name[length] <= 0x7E)
            {
                ++length;
            }

            if (!length || length == 128 || script.name[length] != '\0')
            {
                break;
            }

            coreScripts.emplace_back(script.data, script.size);
        }
    }
}

#endif
