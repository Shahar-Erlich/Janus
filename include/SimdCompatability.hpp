#pragma once

#include <cstdint>

#if __has_include(<simd>)
#include <simd>
namespace simd_ns = std;
#elif __has_include(<experimental/simd>)
#include <experimental/simd>
namespace simd_ns = std::experimental;
#else
#error "SIMD not supported"
#endif

using simd_u8 = simd_ns::simd<std::uint8_t>;