#pragma once

#include <cstdint>
#include <experimental/simd>

namespace simd_ns = std::experimental;

using simd_u8 = simd_ns::native_simd<std::uint8_t>;
using mask_t = typename simd_u8::mask_type;