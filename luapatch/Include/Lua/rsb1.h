#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rsb1
{
    bool decode_blob(const void* blob, size_t size, std::vector<uint8_t>& stream,
                     std::string& error);
    std::vector<uint8_t> wrap_stream(const std::vector<uint8_t>& stream);

    void embed_source(std::vector<uint8_t>& stream, const std::string& source);
    bool extract_source(const std::vector<uint8_t>& stream, std::string* source);

    bool build_stream(const std::string& source, const std::string& name,
                      uint32_t encoding_key, std::vector<uint8_t>& stream, std::string& error);
}
