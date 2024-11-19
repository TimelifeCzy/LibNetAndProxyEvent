#include "Utiliy.h"
#include "traceEngin.skel.h"

#include "eBPFMonitor.h"
#include "eBPFTraceEngine.h"
#include "eBPFHlpr.h"

eBPFTraceEngine::eBPFTraceEngine(/* args */)
{
}

eBPFTraceEngine::~eBPFTraceEngine()
{
}

void eBPFTraceEngine::SetMaxRLimit()
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    setrlimit(RLIMIT_MEMLOCK, &lim);
}

void eBPFTraceEngine::StopRestrack(struct traceEngin* skel)
{
    if (skel) {
        traceEngin__destroy(skel);
        skel = nullptr;
    }
}

struct traceEngin* const eBPFTraceEngine::RunRestrack(struct TraceEnginConfiguration* config)
{
    if (!config)
        return nullptr;
    
    if (config->bEnableBPF == false)
        return nullptr;
    
    int ret = -1;
    struct traceEngin* skel = nullptr;

    libbpf_set_print(libbpf_print_fn);

    SetMaxRLimit();

    // Open the eBPF program
    skel = traceEngin__open();
    if (!skel || (nullptr == skel))
        return nullptr;
        
    ret = traceEngin__load(skel);
    if (ret)
        return nullptr;

    ret = traceEngin__attach(skel);
    if (ret)
    {
        traceEngin__destroy(skel);
        return nullptr;
    }

    return skel;
}