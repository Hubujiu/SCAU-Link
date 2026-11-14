#pragma once
#include "protocol.hpp"
#include <algorithm>
#include <optional>
#include <stdexcept>

namespace scau {
// Associates replies with a current request. Transport padding/VLAN changes do
// not create a new request; a repeated request can still begin a new pending
// phase after Success. A bare duplicate Success never does.
class ExchangeTracker {
    Mac peer_{};
    std::optional<Byte> identifier_;
    bool md5_pending_{};
    Bytes request_,response_;
    static std::span<const Byte> request_key(const Frame& frame) {
        if(frame.code!=1 || frame.eap.size()<5)throw std::runtime_error("Missing EAP request");
        const auto length=(std::size_t(frame.eap[2])<<8)|frame.eap[3];
        if(length<5 || length>frame.eap.size())throw std::runtime_error("Invalid EAP request length");
        return frame.eap.first(length);
    }
public:
    ExchangeTracker()=default;
    ~ExchangeTracker(){reset();}
    ExchangeTracker(const ExchangeTracker&)=delete;
    ExchangeTracker& operator=(const ExchangeTracker&)=delete;
    void reset() noexcept {
        // Cached responses include identifiers and a password-derived digest.
        auto* data=static_cast<volatile Byte*>(response_.data());
        for(std::size_t i=0;i<response_.size();++i)data[i]=0;
        response_.clear();request_.clear();identifier_.reset();md5_pending_=false;
    }
    bool accepts_peer(const Frame& frame) const noexcept {return !identifier_ || frame.source==peer_;}
    bool duplicate_request(const Frame& frame) const {
        if(!identifier_ || frame.source!=peer_)return false;
        const auto key=request_key(frame);
        return std::equal(key.begin(),key.end(),request_.begin(),request_.end());
    }
    void record_response(const Frame& request,Bytes response) {
        const auto key=request_key(request);
        reset();request_.assign(key.begin(),key.end());response_=std::move(response);
        peer_=request.source;identifier_=request.identifier;md5_pending_=request.method==4;
    }
    void repeated_request_answered(const Frame& request) {
        if(!duplicate_request(request))throw std::runtime_error("Cached response does not match this request");
        md5_pending_=request.method==4;
    }
    const Bytes& cached_response() const noexcept {return response_;}
    bool accepts_success(const Frame& frame) const noexcept {
        return md5_pending_ && identifier_ && frame.code==3 && frame.source==peer_ && frame.identifier==*identifier_;
    }
    bool accepts_failure(const Frame& frame,bool connected) const noexcept {
        return identifier_ && frame.code==4 && frame.source==peer_ && (connected || frame.identifier==*identifier_);
    }
    // Preserve the peer/identifier during a brief failure backoff, so a late
    // explicit rejection can cancel a queued retry. Success cannot arrive late.
    void expire_pending() noexcept {md5_pending_=false;}
    void completed() noexcept {md5_pending_=false;}
};
}
