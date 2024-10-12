#include "Utiliy.h"
#include "Monitor.h"
#include "EbpfTraceEngine.h"

// Unit test bpf trace montior
int main(int argc, char** argv)
{
    TraceEnginConfiguration engincfg;
    engincfg.bEnablebpf = true;
    engincfg.ProcessId = getpid();

    // start bpf
    traceEngin* pTrace = SingleEbpfTraceEngine::instance()->RunRestrack(&engincfg);
    if (pTrace == nullptr)
        return 0;

    // start event thread
    SingleEbpfMonitor::instance()->StartMonitor(&engincfg);
    return 0;
}