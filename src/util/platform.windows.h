#pragma once

#include <functional>
#include <locale>
#include <memory>
#include <string>
#include <vector>

// These have to remain in this order or the build fails.
// clang-format off
#include <WinSock2.h>
#include <Windows.h>
#include <WbemCli.h>
// clang-format on

namespace zeek::agent::platform::windows {

using bstr_ptr = std::unique_ptr<OLECHAR, std::function<void(BSTR)>>;

inline bstr_ptr make_bstr(const wchar_t* str) {
    return {::SysAllocString(str), [](BSTR b) { ::SysFreeString(b); }};
}

inline bstr_ptr make_bstr(const std::wstring& str) {
    return {::SysAllocString(str.c_str()), [](BSTR b) { ::SysFreeString(b); }};
}

inline int64_t combine_high_low(DWORD high, DWORD low) {
    LARGE_INTEGER li{.LowPart = low, .HighPart = static_cast<LONG>(high)};
    return li.QuadPart;
}

/**
 * Windows time values in FILETIME objects are the number of 100-nanosecond intervals
 * since January 1, 1601 (UTC). This method converts it to the number of seconds
 * since POSIX epoch.
 */
inline int64_t convert_filetime(const FILETIME& t) {
    constexpr int64_t TICKS_PER_SECOND = 10000000;
    constexpr int64_t EPOCH_DIFFERENCE = 11644473600LL;

    LARGE_INTEGER date{.LowPart = t.dwLowDateTime, .HighPart = static_cast<LONG>(t.dwHighDateTime)};

    // This is the adjustment for the epoch difference between Windows and POSIX, in
    // microseconds.
    LARGE_INTEGER adjust{.QuadPart = EPOCH_DIFFERENCE * 10000};

    date.QuadPart -= adjust.QuadPart;
    return date.QuadPart / TICKS_PER_SECOND;
}

inline std::string narrow_wstring(const std::wstring& str) {
    const wchar_t* from = str.c_str();
    std::size_t len = str.size();

    std::locale loc("");
    std::vector<char> buffer(len + 1);
    std::use_facet<std::ctype<wchar_t>>(loc).narrow(from, from + len, '_', &buffer[0]);
    return {&buffer[0], &buffer[len]};
}

struct AccountInfo {
    std::string name;
    std::string full_name;
    std::string sid;
    std::string home_directory;
    bool is_admin = false;
    bool is_system_acct = false;
};

struct HandleCloser {
    void operator()(HANDLE h) const { CloseHandle(h); }
};
using HandlePtr = std::unique_ptr<std::remove_pointer<HANDLE>::type, HandleCloser>;

class WMIManager {
public:
    static WMIManager& Get();

    ~WMIManager();

    WMIManager(const WMIManager&) = delete;
    WMIManager(WMIManager&&) = delete;
    WMIManager& operator=(const WMIManager&) = delete;
    WMIManager& operator=(WMIManager&&) = delete;

    void Shutdown();

    std::string GetOSVersion() const;
    std::vector<AccountInfo> GetUserData() const;

private:
    struct WMIDeleter {
        void operator()(IWbemLocator* l) const { l->Release(); }
        void operator()(IWbemServices* s) const { s->Release(); }
        void operator()(IEnumWbemClassObject* o) const { o->Release(); }
        void operator()(IWbemClassObject* o) const { o->Release(); }
    };

    using IWbemServicesPtr = std::unique_ptr<IWbemServices, WMIDeleter>;
    using IWbemLocatorPtr = std::unique_ptr<IWbemLocator, WMIDeleter>;
    using IEnumWbemClassObjectPtr = std::unique_ptr<IEnumWbemClassObject, WMIDeleter>;
    using IWbemClassObjectPtr = std::unique_ptr<IWbemClassObject, WMIDeleter>;

    WMIManager();

    IEnumWbemClassObjectPtr GetQueryEnumerator(const std::wstring& query) const;

    void GetUserData(const std::wstring& key, bool system_accounts, std::vector<AccountInfo>& out) const;

    IWbemLocatorPtr locator = nullptr;
    IWbemServicesPtr cimv2_service = nullptr;

    bstr_ptr cimv2_root = nullptr;
    bstr_ptr wql = nullptr;
    bstr_ptr stdregprov = nullptr;
};

} // namespace zeek::agent::platform::windows
