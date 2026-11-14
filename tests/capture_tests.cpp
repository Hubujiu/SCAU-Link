#include "pcap_capture.hpp"
#include <windows.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <vector>

using namespace scau;
void require(bool ok,const char* text){if(!ok)throw std::runtime_error(text);}
std::vector<char> read(const std::filesystem::path& p){std::ifstream in(p,std::ios::binary);return {std::istreambuf_iterator<char>(in),{}};}
int main() {
    wchar_t directory[MAX_PATH]{},name[MAX_PATH]{};
    if(!GetTempPathW(MAX_PATH,directory) || !GetTempFileNameW(directory,L"sca",0,name))return 1;
    const std::filesystem::path path(name);
    try {
        const std::array<std::uint8_t,18> frame{2,0,0,0,0,1,2,0,0,0,0,2,0x88,0x8e,1,1,0,0};
        {Capture first(path);first.packet(frame);}
        const auto first=read(path);require(first.size()==100,"First packet block must be complete");
        {Capture recovered(path,true);require(recovered.recovered_bytes()==0,"Complete captures need no repair");recovered.packet(frame);}
        const auto second=read(path);require(second.size()==200 && std::equal(first.begin(),first.end(),second.begin()),"Recovery must preserve the first section and packet");
        {std::ofstream tail(path,std::ios::binary|std::ios::app);const char partial[]{6,0,0,0,0,4,0,0,0,0,0,0};tail.write(partial,sizeof(partial));}
        {Capture recovered(path,true);require(recovered.recovered_bytes()==12,"Only the incomplete final block may be discarded");recovered.packet(frame);}
        const auto repaired=read(path);require(repaired.size()==300 && std::equal(second.begin(),second.end(),repaired.begin()),"All complete pre-crash records must survive");
        {std::fstream corrupt(path,std::ios::binary|std::ios::in|std::ios::out);corrupt.seekp(96);corrupt.put(0);}
        const auto corrupt=read(path);bool rejected=false;
        try{Capture refused(path,true);}catch(const std::runtime_error&){rejected=true;}
        require(rejected && read(path)==corrupt,"A corrupt complete block must be refused without modifying data");
        std::filesystem::remove(path);
        std::cout<<"PASS: worker recovery appends sections; complete records retained; partial tail repaired; corruption refused\n";
        return 0;
    }catch(const std::exception& e){std::filesystem::remove(path);std::cerr<<e.what()<<'\n';return 1;}
}
