#include "Lua/rsb1.h"

#include "Configuration.h"
#include "Lua/opcodes.h"
#include "Lua/scramble.h"

#include <lz4.h>
#include <xxhash.h>

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(CLIENT)
extern "C"
{
#include "lua.h"
#include "lauxlib.h"
#include "lobject.h"
#include "lstate.h"
}
#endif

namespace rsb1
{
    namespace
    {
        uint32_t Hash(const void* data, size_t len)
        {
            return XXH32(data, len, 42);
        }

        void ApplyXor(std::vector<uint8_t>& bytes, const uint8_t* hash_bytes)
        {
            for (size_t i = 0; i < bytes.size(); ++i)
            {
                bytes[i] = static_cast<uint8_t>(bytes[i] ^
                    (hash_bytes[i % 4] + static_cast<uint8_t>(i * 41)));
            }
        }

        std::vector<uint8_t> EncodeLiteralBlock(const std::vector<uint8_t>& input)
        {
            std::vector<uint8_t> output;
            const size_t literal_size = input.size();

            output.push_back(static_cast<uint8_t>((literal_size < 15 ? literal_size : 15) << 4));
            if (literal_size >= 15)
            {
                size_t remaining = literal_size - 15;
                while (remaining >= 255)
                {
                    output.push_back(255);
                    remaining -= 255;
                }
                output.push_back(static_cast<uint8_t>(remaining));
            }

            output.insert(output.end(), input.begin(), input.end());
            return output;
        }
    }

#if defined(CLIENT)
    namespace
    {
        bool HasWideOperand(uint32_t opcode)
        {
            switch (opcode)
            {
            case 1:
            case 5:
            case 7:
            case 36:
            case 22:
            case 31:
            case 32:
                return true;
            default:
                return false;
            }
        }

        uint32_t EncodeInstruction(uint32_t value, uint32_t pc)
        {
            (void)pc;
            const uint32_t opcode = value & 0x3F;
            const uint32_t operand_a = (value >> 6) & 0xFF;
            const uint32_t secure_opcode = opcode < 38 ? get_roblox_opcode[opcode] : opcode;

            uint32_t encoded;
            if (!HasWideOperand(opcode))
            {
                const uint32_t operand_b = (value >> 23) & 0x1FF;
                const uint32_t operand_c = (value >> 14) & 0x1FF;
                encoded = (secure_opcode << 26) | (operand_a << 18) | (operand_c << 9) | operand_b;
            }
            else
            {
                encoded = (secure_opcode << 26) | (operand_a << 18) | ((value >> 14) & 0x3FFFF);
            }

#ifndef BEFORE_CALL_SCRAMBLE
            if (secure_opcode == 6)
            {
                return scramble::MoveBits(encoded, pc);
            }

            if (secure_opcode == 27 || secure_opcode == 31 || secure_opcode == 34 || secure_opcode == 37)
            {
                uint32_t operands = 0;
                for (uint32_t bit = 1; bit; bit <<= 1)
                {
                    if ((bit & scramble::MixForward(operands, pc)) != (encoded & bit))
                    {
                        operands |= bit;
                    }
                }
                return (secure_opcode << 26) | (operands & 0x3FFFFFFu);
            }
#endif

            return encoded;
        }

        struct Writer
        {
            std::vector<uint8_t> bytes;

            void u8(uint8_t value)
            {
                bytes.push_back(value);
            }

            void u32(uint32_t value)
            {
                uint8_t encoded[4];
                std::memcpy(encoded, &value, 4);
                bytes.insert(bytes.end(), encoded, encoded + 4);
            }

            void u64(uint64_t value)
            {
                uint8_t encoded[8];
                std::memcpy(encoded, &value, 8);
                bytes.insert(bytes.end(), encoded, encoded + 8);
            }
        };

        struct StringTable
        {
            std::vector<std::string> order;
            std::unordered_map<std::string, uint32_t> indices;

            uint32_t add(const TString* string)
            {
                if (!string)
                {
                    return 0;
                }

                const std::string text(getstr(string), static_cast<size_t>(string->tsv.len));
                auto found = indices.find(text);
                if (found != indices.end())
                {
                    return found->second;
                }

                order.push_back(text);
                indices.emplace(order.back(), static_cast<uint32_t>(order.size()));
                return static_cast<uint32_t>(order.size());
            }
        };

        bool WritePrototype(Writer& writer, StringTable& strings, const Proto* proto, uint32_t encoding_key)
        {
            writer.u32(proto->sizep);
            writer.u32(proto->sizek);
            writer.u32(proto->sizecode);
            writer.u32(proto->sizelocvars);
            writer.u32(proto->sizelineinfo);
            writer.u32(proto->sizeupvalues);
            writer.u8(proto->maxstacksize);
            writer.u8(proto->is_vararg);
            writer.u8(proto->nups);
            writer.u8(proto->numparams);

            for (int i = 0; i < proto->sizek; ++i)
            {
                const TValue* constant = &proto->k[i];
                if (ttisnil(constant))
                {
                    writer.u8(0);
                }
                else if (ttisboolean(constant))
                {
                    writer.u8(bvalue(constant) ? 2 : 1);
                }
                else if (ttisnumber(constant))
                {
                    writer.u8(3);
                    const lua_Number number = nvalue(constant);
                    uint64_t bits;
                    std::memcpy(&bits, &number, 8);
                    writer.u64(bits);
                }
                else if (ttisstring(constant))
                {
                    writer.u8(4);
                    writer.u32(strings.add(rawtsvalue(constant)));
                }
                else
                {
                    return false;
                }
            }

            int previous = 0;
            for (int i = 0; i < proto->sizelineinfo; ++i)
            {
                const int current = proto->lineinfo[i] ^ (i << 8);
                writer.u32(static_cast<uint32_t>(current - previous));
                previous = current;
            }

            for (int i = 0; i < proto->sizelocvars; ++i)
            {
                writer.u32(static_cast<uint32_t>(proto->locvars[i].startpc));
                writer.u32(static_cast<uint32_t>(proto->locvars[i].endpc));
                writer.u32(strings.add(proto->locvars[i].varname));
            }

            for (int i = 0; i < proto->sizeupvalues; ++i)
            {
                writer.u32(strings.add(proto->upvalues[i]));
            }

            for (int i = 0; i < proto->sizecode; ++i)
            {
                writer.u32(EncodeInstruction(static_cast<uint32_t>(proto->code[i]), static_cast<uint32_t>(i)) * encoding_key);
            }

            for (int i = 0; i < proto->sizep; ++i)
            {
                if (!WritePrototype(writer, strings, proto->p[i], encoding_key))
                {
                    return false;
                }
            }

            return true;
        }
    }

    bool build_stream(const std::string& source, const std::string& name,
                      uint32_t encoding_key, std::vector<uint8_t>& output, std::string& error)
    {
        output.clear();

        if (!source.empty() && static_cast<uint8_t>(source[0]) == 0x1B)
        {
            error = "binary chunk on the source path";
            return false;
        }

        lua_State* state = luaL_newstate();
        if (!state)
        {
            error = "luaL_newstate";
            return false;
        }

        const char* chunkname = name.empty() ? "=script" : name.c_str();

        lua_pushlstring(state, chunkname, std::strlen(chunkname));

        if (luaL_loadbuffer(state, source.data(), source.size(), chunkname) != 0)
        {
            const char* message = lua_tostring(state, -1);
            error = message ? message : "compile error";
            lua_close(state);
            return false;
        }

        const Proto* proto = clvalue(state->top - 1)->l.p;

        Writer writer;
        StringTable strings;
        writer.u32(0);
        const bool written = WritePrototype(writer, strings, proto, encoding_key);
        const uint32_t string_table_offset = static_cast<uint32_t>(writer.bytes.size());

        writer.u32(static_cast<uint32_t>(strings.order.size()));
        for (const std::string& text : strings.order)
        {
            writer.u32(static_cast<uint32_t>(text.size()));
        }
        for (const std::string& text : strings.order)
        {
            writer.bytes.insert(writer.bytes.end(), text.begin(), text.end());
        }
        std::memcpy(&writer.bytes[0], &string_table_offset, 4);

        output.push_back(0);
        output.insert(output.end(), writer.bytes.begin(), writer.bytes.end());

        lua_close(state);

        if (!written)
        {
            error = "unsupported constant type";
            output.clear();
            return false;
        }
        return true;
    }
#endif

    std::vector<uint8_t> wrap_stream(const std::vector<uint8_t>& stream)
    {
        std::vector<uint8_t> output;
        output.reserve(stream.size() + 64);
        for (char c : std::string("RSB1"))
        {
            output.push_back(static_cast<uint8_t>(c));
        }

        const int32_t data_size = static_cast<int32_t>(stream.size());
        uint8_t size_bytes[4];
        std::memcpy(size_bytes, &data_size, 4);
        output.insert(output.end(), size_bytes, size_bytes + 4);

        const std::vector<uint8_t> compressed = EncodeLiteralBlock(stream);
        output.insert(output.end(), compressed.begin(), compressed.end());

        const uint32_t hash = Hash(output.data(), output.size());
        uint8_t hash_bytes[4];
        std::memcpy(hash_bytes, &hash, 4);

        ApplyXor(output, hash_bytes);

        return output;
    }

    bool decode_blob(const void* blob, size_t size, std::vector<uint8_t>& stream,
                     std::string& error)
    {
        static const char magic[] = "RSB1";
        if (!blob || size < 12)
        {
            error = "blob too small";
            return false;
        }

        const uint8_t* bytes = static_cast<const uint8_t*>(blob);
        uint8_t hash_bytes[4];
        std::memcpy(hash_bytes, bytes, 4);
        for (int i = 0; i < 4; ++i)
        {
            hash_bytes[i] = static_cast<uint8_t>(hash_bytes[i] ^ magic[i]);
            hash_bytes[i] = static_cast<uint8_t>(hash_bytes[i] - i * 41);
        }

        std::vector<uint8_t> plain(bytes, bytes + size);
        ApplyXor(plain, hash_bytes);

        if (std::memcmp(plain.data(), magic, 4) != 0)
        {
            error = "magic mismatch";
            return false;
        }

        uint32_t stored;
        std::memcpy(&stored, hash_bytes, 4);
        if (stored != Hash(plain.data(), plain.size()))
        {
            error = "xxh32 mismatch";
            return false;
        }

        int32_t data_size;
        std::memcpy(&data_size, plain.data() + 4, 4);
        if (data_size <= 0 || data_size > 0x4000000)
        {
            error = "bad dataSize";
            return false;
        }

        stream.resize(static_cast<size_t>(data_size));
        if (LZ4_decompress_safe(
                reinterpret_cast<const char*>(plain.data() + 8),
                reinterpret_cast<char*>(stream.data()),
                static_cast<int>(plain.size() - 8), data_size) != data_size)
        {
            error = "lz4";
            stream.clear();
            return false;
        }
        return true;
    }

    void embed_source(std::vector<uint8_t>& stream, const std::string& source)
    {
        stream.insert(stream.end(), source.begin(), source.end());

        uint8_t tail[4];
        const uint32_t length = static_cast<uint32_t>(source.size());
        std::memcpy(tail, &length, 4);
        stream.insert(stream.end(), tail, tail + 4);
        stream.insert(stream.end(), { 'S', 'R', 'C', '2' });
    }

    bool extract_source(const std::vector<uint8_t>& stream, std::string* source)
    {
        const size_t size = stream.size();

        if (size < 8 || std::memcmp(&stream[size - 4], "SRC2", 4) != 0)
        {
            return false;
        }

        uint32_t length = 0;
        std::memcpy(&length, &stream[size - 8], 4);
        if (length > size - 8)
        {
            return false;
        }

        source->assign(reinterpret_cast<const char*>(&stream[size - 8 - length]), length);
        return true;
    }
}
