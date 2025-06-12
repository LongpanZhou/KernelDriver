#ifndef WDK_UTILS_HPP
#define WDK_UTILS_HPP

#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <functional>

#define ALWAYS_INLINE __attribute__((always_inline)) inline

#define BEGIN_INTEL_SYNTAX ".intel_syntax noprefix;"
#define END_INTEL_SYNTAX ".att_syntax;"

// i have to admit, i don't like this.
// enables implicit conversions between a trivial struct and a scalar type
#define MAKE_SCALAR_CONVERTIBLE(THIS, TYPE)                                                                                                                    \
    constexpr THIS() = default;                                                                                                                                \
    constexpr THIS(const THIS&) = default;                                                                                                                     \
    constexpr THIS& operator=(const THIS&) = default;                                                                                                          \
                                                                                                                                                               \
    constexpr THIS(TYPE value) {                                                                                                                               \
        *this = std::bit_cast<THIS>(value);                                                                                                                    \
    }                                                                                                                                                          \
                                                                                                                                                               \
    constexpr THIS& operator=(TYPE value) {                                                                                                                    \
        *this = std::bit_cast<THIS>(value);                                                                                                                    \
        return *this;                                                                                                                                          \
    }                                                                                                                                                          \
                                                                                                                                                               \
    constexpr operator TYPE() const {                                                                                                                          \
        return std::bit_cast<TYPE>(*this);                                                                                                                     \
    }


#endif // WDK_UTILS_HPP
