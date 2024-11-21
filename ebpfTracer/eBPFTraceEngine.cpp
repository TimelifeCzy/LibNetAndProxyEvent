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

void eBPFTraceEngine::StopRestrack()
{
    if (m_skel) {
        traceEngin__destroy(m_skel);
        m_skel = nullptr;
    }
}

const bool eBPFTraceEngine::RunRestrack(struct TraceEnginConfiguration* config)
{
    if (!config)
        return false;
    
    if (config->bEnableBPF == false)
        return false;
    
    libbpf_set_print(libbpf_print_fn);

    SetMaxRLimit();

    // Open the eBPF program
    m_skel = traceEngin__open();
    if (!m_skel || (nullptr == m_skel))
        return false;

    int ret = -1;
    ret = traceEngin__load(m_skel);
    if (ret) {
        traceEngin__destroy(m_skel);
        return false;
    }
    
    ret = traceEngin__attach(m_skel);
    if (ret)
    {
        traceEngin__destroy(m_skel);
        return false;
    }

    return true;
}