#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>

namespace scau {
// A recovered worker adds a new PCAPNG section. Complete earlier packets are
// retained; only an interrupted final block may be shortened before appending.
class Capture {
    std::ofstream file_;
    std::uint64_t recovered_bytes_{};
    static std::uint32_t little(const std::array<unsigned char,8>& bytes,unsigned at) {
        return std::uint32_t(bytes[at])|(std::uint32_t(bytes[at+1])<<8)|
               (std::uint32_t(bytes[at+2])<<16)|(std::uint32_t(bytes[at+3])<<24);
    }
    void recover_tail(const std::filesystem::path& path) {
        if(!std::filesystem::exists(path))return;
        const auto size=std::filesystem::file_size(path);
        if(!size)return;
        std::ifstream input(path,std::ios::binary);
        if(!input)throw std::runtime_error("Cannot read the existing authentication capture");
        constexpr std::array<unsigned char,4> magic{0x0a,0x0d,0x0d,0x0a};
        std::array<unsigned char,8> header{};
        input.read(reinterpret_cast<char*>(header.data()),static_cast<std::streamsize>(size<4?size:4));
        for(std::size_t i=0;i<(size<4?size:4);++i)
            if(header[i]!=magic[i])throw std::runtime_error("Recovery capture is not PCAPNG");
        input.clear();std::uint64_t offset=0;
        while(offset<size) {
            if(size-offset<8)break;
            input.seekg(static_cast<std::streamoff>(offset));input.read(reinterpret_cast<char*>(header.data()),8);
            if(!input)throw std::runtime_error("Cannot inspect the recovery capture");
            const auto kind=little(header,0),length=little(header,4);
            if(length<12 || length%4)throw std::runtime_error("Invalid recovery capture block");
            if(length>size-offset)break;
            if(kind==0x0a0d0d0a) {
                if(length<28)throw std::runtime_error("Invalid recovery capture section");
                input.read(reinterpret_cast<char*>(header.data()),4);
                if(!input || little(header,0)!=0x1a2b3c4d)throw std::runtime_error("Unsupported recovery capture byte order");
            }else if(!offset)throw std::runtime_error("Missing recovery capture section");
            input.seekg(static_cast<std::streamoff>(offset+length-4));input.read(reinterpret_cast<char*>(header.data()),4);
            if(!input || little(header,0)!=length)throw std::runtime_error("Corrupt recovery capture block footer");
            offset+=length;
        }
        input.close();
        if(offset<size){recovered_bytes_=size-offset;std::filesystem::resize_file(path,offset);}
    }
    void word(std::uint32_t value) {
        const std::array<unsigned char,4> bytes{static_cast<unsigned char>(value),static_cast<unsigned char>(value>>8),static_cast<unsigned char>(value>>16),static_cast<unsigned char>(value>>24)};
        file_.write(reinterpret_cast<const char*>(bytes.data()),4);
    }
public:
    explicit Capture(const std::filesystem::path& path,bool recovery=false) {
        if(path.empty())return;
        if(recovery)recover_tail(path);
        file_.open(path,std::ios::binary|(recovery?std::ios::app:std::ios::trunc));
        if(!file_)throw std::runtime_error("Cannot create authentication capture");
        for(auto value:{0x0a0d0d0au,28u,0x1a2b3c4du,1u,0xffffffffu,0xffffffffu,28u,1u,20u,1u,65535u,20u})word(value);
        file_.flush();
        if(!file_)throw std::runtime_error("Cannot write authentication capture section");
    }
    std::uint64_t recovered_bytes() const noexcept {return recovered_bytes_;}
    void packet(std::span<const std::uint8_t> frame) {
        if(!file_.is_open())return;
        if(frame.size()>65535)throw std::runtime_error("Authentication capture frame is too large");
        const auto elapsed=std::chrono::system_clock::now().time_since_epoch();
        const auto ticks=std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
        const auto size=std::uint32_t(32+((frame.size()+3)/4)*4);
        for(auto value:{6u,size,0u,std::uint32_t(ticks>>32),std::uint32_t(ticks),std::uint32_t(frame.size()),std::uint32_t(frame.size())})word(value);
        file_.write(reinterpret_cast<const char*>(frame.data()),static_cast<std::streamsize>(frame.size()));
        for(std::size_t i=0;i<((4-(frame.size()%4))%4);++i)file_.put(0);
        word(size);file_.flush();
        if(!file_)throw std::runtime_error("Cannot write authentication capture packet");
    }
};
}
