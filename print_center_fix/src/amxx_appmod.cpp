/*
 *  Copyright (c) 2021 the_hunter
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include "amxx_appmod.h"
#include <cstdint>

namespace print_center_fix
{
    TrampHook* AmxxAppMod::HookClientPrint(const ClientPrintFunc tramp)
    {
#ifdef _WIN32
        constexpr auto* pattern = "\xFF\x73\x08\xFF\x37\xE8\x00\x00\x00\x00\x83";
        constexpr auto* mask = "xxxxxx????x";
        constexpr auto extra_offset = 0x5;
#else
        constexpr auto* pattern = "\x83\xEC\x04\x56\x8B\x4C\x24\x2C\xFF\x71\x08\xFF\x30\xE8\x00\x00\x00\x00\x83\xC4\x10";
        constexpr auto* mask    = "xxxxxxxxxxxxx????xxxx";
        constexpr auto extra_offset = 0xd;
#endif
        auto* const hook = CreateHookOpcodeCall(pattern, mask, extra_offset, reinterpret_cast<std::uintptr_t>(tramp));

        if (!hook) {
            error_ = "Failed to hook UTIL_ClientPrint: " + error_;
        }

        return hook;
    }

    TrampHook* AmxxAppMod::HookClientSayText(const ClientSayTextFunc tramp)
    {
#ifdef _WIN32
        constexpr auto* pattern = "\x56\xC6\x04\x08\x00\xFF\x37\xE8\x00\x00\x00\x00\x83\xC4\x0C";
        constexpr auto* mask = "xxxxxxxx????xxx";
        constexpr auto extra_offset = 0x7;
#else
        constexpr auto* pattern = "\x0F\x44\xC3\x83\xEC\x04\x56\x50\xFF\x37\xE8";
        constexpr auto* mask = "xxxxxxxxxxx";
        constexpr auto extra_offset = 0xA;
#endif
        auto* const hook = CreateHookOpcodeCall(pattern, mask, extra_offset, reinterpret_cast<std::uintptr_t>(tramp));

        if (!hook) {
            error_ = "Failed to hook UTIL_ClientSayText: " + error_;
        }

        return hook;
    }
}
