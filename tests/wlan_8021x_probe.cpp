#include "desktop/wlan_8021x.hpp"
#include <objbase.h>
#include <iostream>

int main() {
    const auto com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    try {
        scau::desktop::Wlan8021xOptions options;options.profile_id=std::string(32,'d');
        // Constructor only: enumerate physical adapters, open the caller's WLAN
        // handle, register ACM/ONEX and close it. No credential read, scan,
        // current_connection/BSSID query, prepare, connect or disconnect call.
        auto port=scau::desktop::make_native_wlan_8021x_port(options);
        port.reset();
        std::cout<<"{\"nativeClientOpened\":true,\"acmOnexRegistration\":true,\"credentialsRead\":false,\"profileMutations\":0,\"connectionRequests\":0,\"disconnectionRequests\":0,\"locationOrBssidQueries\":0}\n";
        if(SUCCEEDED(com))CoUninitialize();return 0;
    }catch(...) {
        std::cout<<"{\"nativeClientOpened\":false,\"profileMutations\":0,\"connectionRequests\":0,\"disconnectionRequests\":0}\n";
        if(SUCCEEDED(com))CoUninitialize();return 1;
    }
}
