#include "failure.hpp"
#include <iostream>
#include <stdexcept>
#include <windows.h>

scau::Bytes rejection(std::string_view text) {
    scau::Bytes frame{4, 7, 0, 0, 0, 0, 0x13, 0x11, 0, 0};
    const auto length = text.size() + frame.size();
    frame[2] = scau::Byte(length >> 8); frame[3] = scau::Byte(length);
    frame[8] = scau::Byte(text.size() >> 8); frame[9] = scau::Byte(text.size());
    frame.insert(frame.end(), text.begin(), text.end());
    return frame;
}

int main() {
    using namespace scau;
    auto require=[](bool ok){if(!ok)throw std::runtime_error("Failure classification regression");};
    try {
        require(failure_reason(Bytes{4,7,0,4})==FailureReason::empty);
        require(failure_reason(Bytes{4,7,0,10,0,0,0x13,0x11,0,0})==FailureReason::empty);
        require(failure_reason(Bytes{4,7,0,13,0,0,0x13,0x11,0,3,'b','a','d'})==FailureReason::present);
        require(failure_reason(Bytes{4,7,0,10,0,0,0x13,0x11,0,3})==FailureReason::malformed);
        require(failure_reason(Bytes{4,7,0,8,0,0,0x13,0x11})==FailureReason::malformed);
        require(failure_reason(Bytes{4,7,0,5,0x42})==FailureReason::unrecognized);
        require(failure_reason(Bytes{4,7,0,4,1,2,3,4})==FailureReason::empty); // Ignore Ethernet/EAPOL padding.
        require(failure_reason(Bytes{4,7,0,12,0,0,0x13,0x11,0,0,1,2})==FailureReason::empty);
        require(failure_reason(Bytes{4,7,0,14})==FailureReason::malformed);
        require(failure_reason(Bytes{3,7,0,4})==FailureReason::malformed);
        require(failure_message(Bytes{4,7,0,4})=="unknown");
        require(failure_message(Bytes{4,7,0,10,0,0,0x13,0x11,0,3})=="unknown");
        require(failure_message(Bytes{4,7,0,5,0x42})=="unknown");
        require(failure_message(rejection("已达到同时在线用户数量上限"))=="已达到同时在线用户数量上限");
        require(failure_message(rejection("\xb2\xbb\xd4\xda\xc8\xcf\xd6\xa4\xca\xb1\xb6\xce\xc4\xda"))=="不在认证时段内");
        require(failure_message(rejection("\xff"))=="unknown");
        require(failure_message(rejection(std::string_view("bad\0reason",10)))=="unknown");
        require(failure_message(rejection(" \r\n\t "))=="unknown");
        require(failure_message(rejection("\r\n密码错误\t 请重试\n"))=="密码错误 请重试");
        require(failure_message(rejection("账号 20260088 密码 synthetic-secret 无效"),"20260088","synthetic-secret")
                =="账号 *** 密码 *** 无效");
        require(failure_message(rejection("2026\xe2\x80\x8b" "0088 无效"),"20260088")=="*** 无效");
        auto padded=rejection("invalid"); padded.insert(padded.end(), {'s','e','c','r','e','t'});
        require(failure_message(padded)=="invalid");
        std::string long_text;
        for(unsigned i=0;i<600;++i)long_text+="错";
        const auto bounded=failure_message(rejection(long_text));
        require(bounded.size()<=failure_message_limit && bounded.ends_with("..."));
        require(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bounded.data(),int(bounded.size()),nullptr,0)>0);
        require(failure_message(rejection(std::string(4097,'x')))=="unknown");
        std::cout<<"PASS: standard/empty/private reason; bounds; unknown format; declared EAP length\n";
        std::cout<<"PASS: UTF-8/GBK reasons, unknown fallback, redaction, control normalization and UTF-8 truncation\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
