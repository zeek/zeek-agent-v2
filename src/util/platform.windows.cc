#include "./platform.windows.h"

#include "core/logger.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <ztd/out_ptr/out_ptr.hpp>

using namespace zeek::agent::platform::windows;
using namespace ztd::out_ptr;

WMIManager& WMIManager::Get() {
    static WMIManager wmi;
    return wmi;
}

WMIManager::WMIManager() {
    HRESULT res = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if ( FAILED(res) )
        return;

    res = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL,
                               EOAC_NONE, 0);
    if ( FAILED(res) )
        return;

    IWbemLocatorPtr loc{nullptr};
    res = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                           out_ptr<IWbemLocatorPtr::pointer>(loc));
    if ( FAILED(res) || ! loc )
        return;

    IWbemServicesPtr cimv2{nullptr};
    cimv2_root = make_bstr(L"root\\CIMV2");
    res = loc->ConnectServer(cimv2_root.get(), NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL,
                             out_ptr<IWbemServicesPtr::pointer>(cimv2));
    if ( FAILED(res) || ! cimv2 )
        return;

    wql = make_bstr(L"WQL");
    stdregprov = make_bstr(L"StdRegProv");

    locator = std::move(loc);
    cimv2_service = std::move(cimv2);
}

WMIManager::~WMIManager() { Shutdown(); }

void WMIManager::Shutdown() {
    cimv2_service.reset();
    locator.reset();
}

WMIManager::IEnumWbemClassObjectPtr WMIManager::GetQueryEnumerator(const std::wstring& query) const {
    auto b_query = make_bstr(query);
    IEnumWbemClassObjectPtr enumerator = nullptr;
    HRESULT res = cimv2_service->ExecQuery(wql.get(), b_query.get(), WBEM_FLAG_FORWARD_ONLY, NULL,
                                           out_ptr<IEnumWbemClassObject*>(enumerator));
    if ( FAILED(res) ) {
        IErrorInfo* error;
        auto result = GetErrorInfo(0, &error);
        if ( SUCCEEDED(result) && error ) {
            BSTR description = NULL;
            result = error->GetDescription(&description);
            if ( SUCCEEDED(result) && description ) {
                logger()->debug(format("Failed to fetch WMI data: {}", narrow_wstring(description)));
            }
        }

        return nullptr;
    }

    return std::move(enumerator);
}

std::string WMIManager::GetOSVersion() const {
    std::wstring version;

    IEnumWbemClassObjectPtr enumerator = GetQueryEnumerator(L"SELECT * from Win32_OperatingSystem");
    if ( ! enumerator )
        return "";

    HRESULT res;
    IWbemClassObjectPtr obj = nullptr;
    int num_elems = 0;
    while ( (res = enumerator->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObjectPtr::pointer>(obj),
                                    reinterpret_cast<ULONG*>(&num_elems))) != WBEM_S_FALSE ) {
        if ( FAILED(res) )
            break;

        VARIANT var;
        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Caption", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            version += var.bstrVal;

        if ( ! version.empty() )
            version += L" ";

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Version", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            version += var.bstrVal;
    }

    return narrow_wstring(version);
}

std::vector<AccountInfo> WMIManager::GetUserData() const {
    std::vector<AccountInfo> out;

    GetUserData(L"Win32_UserAccount", false, out);
    GetUserData(L"Win32_SystemAccount", true, out);

    return out;
}

void WMIManager::GetUserData(const std::wstring& key, bool system_accounts, std::vector<AccountInfo>& out) const {
    std::wstring query = L"SELECT Caption, Name, SID from " + key;
    auto enumerator = GetQueryEnumerator(query);
    if ( ! enumerator )
        return;

    HRESULT res;
    IWbemClassObjectPtr obj = nullptr;
    int num_elems = 0;
    while ( (res = enumerator->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObject*>(obj),
                                    reinterpret_cast<ULONG*>(&num_elems))) != WBEM_S_FALSE ) {
        if ( FAILED(res) )
            break;

        AccountInfo info;
        info.is_system_acct = system_accounts;

        // I'm not sure the repeated calls to VariantClear() are needed below but I can't find any
        // documentation for repeatedly using VARIANT object. I assume that as long as Init is
        // because it's used and Clear is called afterwards, we're fine here.

        VARIANT var;
        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Caption", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.name = narrow_wstring(var.bstrVal);
        VariantClear(&var);

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Name", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.full_name = narrow_wstring(var.bstrVal);
        VariantClear(&var);

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"SID", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.sid = narrow_wstring(var.bstrVal);
        VariantClear(&var);

        std::wstring path_query = format(L"SELECT LocalPath from Win32_UserProfile WHERE SID = \"{}\"", var.bstrVal);

        if ( auto user_enum = GetQueryEnumerator(path_query) ) {
            IWbemClassObjectPtr user_obj = nullptr;
            int num_user_elems = 0;
            if ( user_enum->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObject*>(user_obj),
                                 reinterpret_cast<ULONG*>(&num_elems)) != WBEM_S_FALSE ) {
                VariantInit(&var);
                if ( SUCCEEDED(user_obj->Get(L"LocalPath", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
                    info.home_directory = narrow_wstring(var.bstrVal);
                VariantClear(&var);
            }
        }

        // Adapted from
        // https://devblogs.microsoft.com/scripting/how-can-i-determine-if-the-local-administrator-account-has-been-renamed-on-a-computer/
        if ( startsWith(info.sid, "S-1-5") && endsWith(info.sid, "-500") )
            info.is_admin = true;

        out.push_back(std::move(info));
    }
}
