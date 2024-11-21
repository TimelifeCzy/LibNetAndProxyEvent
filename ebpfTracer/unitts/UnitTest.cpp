#include "../Utiliy.h"
#include "../eBPFMonitor.h"
#include "../eBPFTraceEngine.h"
#include "../TaskHandler.h"

// Unit test bpf trace montior
int main(int argc, char** argv)
{
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
    pause();

    // clear
    SingleeBPFTraceEngine::instance()->StopRestrack();
    SingleeBPFMonitor::instance()->StopMonitor(&engincfg);
    SingleTaskHandler::instance()->StopTaskThread();
    return 0;
}