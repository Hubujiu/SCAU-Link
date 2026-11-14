#include "exchange.hpp"
#include "failure.hpp"
#include "recovery.hpp"
#include <iostream>
#include <stdexcept>

namespace {
using namespace scau;
constexpr Mac local{2,0,0,0,0,1},server{2,0,0,0,0,2};
void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
Bytes packet(Byte code,Byte id) {
    auto bytes=make_simple(server,local,0);
    bytes.insert(bytes.end(),{code,id,0,4});bytes[17]=4;
    if(code==1){bytes[17]=22;bytes[21]=22;bytes.push_back(4);bytes.push_back(16);bytes.insert(bytes.end(),16,0x5a);}
    return bytes;
}
}
int main() {
    using namespace scau;
    try {
        ExchangeTracker exchange;RecoveryController controller;
        controller.start(0,true);
        auto request=packet(1,7);auto frame=parse_frame(request);
        controller.request(1,true);exchange.record_response(frame,Bytes{2,7});
        auto success=packet(3,7);auto accepted=parse_frame(success);
        require(exchange.accepts_success(accepted),"Success must match the pending MD5");
        controller.success(2,0);exchange.completed();
        require(!exchange.accepts_success(accepted),"A bare duplicate Success cannot refresh session parameters");
        auto padded=request;padded.insert(padded.end(),16,0xa5);
        auto same=parse_frame(padded);
        require(exchange.duplicate_request(same),"Padding must not change request identity");
        controller.request(100,true);exchange.repeated_request_answered(same);
        require(controller.reauth_pending() && exchange.accepts_success(accepted),"A repeated request after Success must manage pending reauth and accept fresh parameters");
        const auto deadline=controller.next_deadline_ms();
        controller.request(200,true);exchange.repeated_request_answered(same);
        require(controller.next_deadline_ms()==deadline,"A duplicate cannot postpone the response timeout");
        auto wrong=success;wrong[19]=8;
        require(!exchange.accepts_success(parse_frame(wrong)),"A stale identifier cannot complete this exchange");
        wrong=success;wrong[11]=3;
        require(!exchange.accepts_success(parse_frame(wrong)),"An unrelated peer cannot complete this exchange");
        controller.tick(*deadline,0);exchange.expire_pending();
        require(!exchange.accepts_success(accepted),"A timed-out Success must not refresh a key");
        auto failure=packet(4,7);
        failure.insert(failure.end(),{0,0,0x13,0x11,0,1,'x'});failure[17]=11;failure[21]=11;
        const auto rejected=parse_frame(failure);
        require(exchange.accepts_failure(rejected,false) && failure_reason(rejected.eap)==FailureReason::present,"A late failure retains its peer and identifier association");
        controller.failure(*deadline+1,true);
        require(controller.state()==RecoveryState::Rejected,"A late explicit reason must cancel the pending retry");
        exchange.reset();
        require(!exchange.accepts_failure(rejected,false) && !exchange.accepts_success(accepted),"A new generation cannot reuse old reply association");
        std::cout<<"PASS: repeated requests/key refresh; duplicate Success; padding; peer/id binding; late rejection cancels retry\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
