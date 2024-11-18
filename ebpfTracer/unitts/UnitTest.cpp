#include "../Utiliy.h"
#include "../eBPFMonitor.h"
#include "../eBPFTraceEngine.h"

// Unit test bpf trace montior
int main(int argc, char** argv)
{
    TraceEnginConfiguration engincfg;
    engincfg.bEnableBPF = true;
    engincfg.ProcessId = getpid();
    
    // start bpf
    traceEngin* pTrace = SingleeBPFTraceEngine::instance()->RunRestrack(&engincfg);
    if (!pTrace || (pTrace == nullptr))
        return 0;

    // start event thread
    SingleeBPFMonitor::instance()->StartMonitor(&engincfg);
    return 0;
}