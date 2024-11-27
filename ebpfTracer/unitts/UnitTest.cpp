#include "../Utiliy.h"
#include "../eBPFMonitor.h"
#include "../eBPFTraceEngine.h"
#include "../TaskHandler.h"

#include <iostream>

void sighandler(int) {
    // clear
    SingleeBPFTraceEngine::instance()->StopRestrack();
    SingleeBPFMonitor::instance()->StopMonitor(nullptr);
    SingleTaskHandler::instance()->StopTaskThread();
    exit(0);
}

// Unit test bpf trace montior
int main(int argc, char** argv)
{
    // regsiter signal clear bpf
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    TraceEnginConfiguration engincfg;
    engincfg.bEnableBPF = true;
    engincfg.ProcessId = getpid();
    
    // start bpf
    const bool bLoad = SingleeBPFTraceEngine::instance()->RunRestrack(&engincfg);
    if (!bLoad)
        return 0;

    // start task handle thread
    SingleTaskHandler::instance()->IntiTaskThread();
    
    // start read perf buffer  thread
    SingleeBPFMonitor::instance()->StartMonitor(&engincfg);

    // wait exit
    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // clear
    SingleeBPFTraceEngine::instance()->StopRestrack();
    SingleeBPFMonitor::instance()->StopMonitor(&engincfg);
    SingleTaskHandler::instance()->StopTaskThread();
    return 0;
}