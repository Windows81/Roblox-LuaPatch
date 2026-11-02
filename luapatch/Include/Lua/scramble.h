#pragma once

#include <cstdint>

namespace scramble
{
    // dealing w/ LUAVM_DAX
    inline uint32_t MixForward(uint32_t operands, uint32_t pc)
    {
        return (0x29451AFBu * operands + 0x46582A8Bu) ^ (0x72394BC8u * operands + pc);
    }

    inline uint32_t MoveBits(uint32_t encoded, uint32_t pc)
    {
        return (((encoded ^ (pc << 9)) & 0x3FC00u) ^ encoded) | 0x200u;
    }
}
