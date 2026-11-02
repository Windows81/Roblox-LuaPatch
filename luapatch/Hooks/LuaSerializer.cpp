#if defined(SERVER)

#include "pch.h"
#include "Helpers.h"
#include "Lua/rsb1.h"
#include "Hooks/LuaSerializer.h"

LuaSerializer__write_t LuaSerializer__write =
    reinterpret_cast<LuaSerializer__write_t>(ADDRESS_LUASERIALIZER__WRITE);
String__assign_t String__assign =
    reinterpret_cast<String__assign_t>(ADDRESS_LUAVM__STRING_ASSIGN);

namespace
{
    void* Finish(void* out, const std::string& text)
    {
        const std::string blob = Helpers::ReadString(out);
        std::vector<uint8_t> stream;
        std::string error;

        if (!blob.empty() && !rsb1::decode_blob(blob.data(), blob.size(), stream, error))
        {
            stream.clear();
        }

        rsb1::embed_source(stream, text);
        const std::vector<uint8_t> wire = rsb1::wrap_stream(stream);

        String__assign(out, wire.data(), wire.size());
        return out;
    }
}

#if defined(BEFORE_CALL_SCRAMBLE)

void* __cdecl LuaSerializer__write_hook(void* out, void* state, void* source, void* extra)
{
    const std::string text = Helpers::ReadString(source);
    LuaSerializer__write(out, state, source, extra);
    return Finish(out, text);
}

#else

void* __cdecl LuaSerializer__write_hook(void* out, void* state, void* source,
                                       InstructionEncoder encoder, unsigned int ckey)
{
    const std::string text = Helpers::ReadString(source);
    LuaSerializer__write(out, state, source, encoder, ckey);
    return Finish(out, text);
}

#endif

#endif
