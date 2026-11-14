#include "observation.hpp"
#include <chrono>
#include <iostream>
#include <stdexcept>

void require(bool value,const char* message) {if(!value)throw std::runtime_error(message);}
int main() {
    using namespace std::chrono;
    try {
        scau::ObservationWindow regular(1800);
        unsigned reports=0;
        for(int second=0;second<=8*60*60;++second) {
            const auto action=regular.advance(seconds(second));
            require(!action.disconnect,"A normal observation deadline must never disconnect the session");
            if(action.report_result) {
                ++reports;
                require(second==1800,"The result must be reported at the observation boundary");
            }
        }
        require(regular.reported() && reports==1,"A retained session reports its observation exactly once");
        scau::ObservationWindow finite(1800,true);
        require(!finite.advance(seconds(1799)).disconnect,"Explicit finite mode must wait for the full duration");
        const auto finish=finite.advance(seconds(1800));
        require(finish.report_result && finish.disconnect,"Finite mode disconnects only when explicitly selected");
        require(!finite.advance(seconds(1801)).report_result,"Completion cannot be reported twice");
        scau::ObservationWindow delayed(1800);
        const auto overdue=delayed.advance(seconds(1805));
        require(overdue.report_result && !overdue.disconnect,"A delayed scheduler must also retain the session");
        std::cout<<"PASS: observation completion retains the session; explicit finite mode; delayed timer; one result\n";
        return 0;
    } catch(const std::exception& error) {std::cerr<<error.what()<<'\n';return 1;}
}
