#include "Utiliy.h"

#include <bpf/libbpf.h>

#include "Monitor.h"
#include "traceEngin.skel.h"
#include "EbpfTraceEngine.h"

EbpfTraceEngine::EbpfTraceEngine(/* args */)
{
}

EbpfTraceEngine::~EbpfTraceEngine()
{
}

void EbpfTraceEngine::SetMaxRLimit()
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    setrlimit(RLIMIT_MEMLOCK, &lim);
}

void EbpfTraceEngine::StopRestrack(struct traceEngin* skel)
{
    if (skel) {
        traceEngin__destroy(skel);
        skel = nullptr;
    }
}

struct traceEngin* const EbpfTraceEngine::RunRestrack(struct TraceEnginConfiguration* config)
{
    int ret = -1;
    struct traceEngin* skel = nullptr;

    if (!config)
        return nullptr;

    SetMaxRLimit();

    //
    // Setup extended error logging
    //
    if (config->bEnablebpf == false)
    {
        libbpf_set_print(libbpf_print_fn);
    }

    //
    // Open the eBPF program
    //
    skel = traceEngin__open();
    if (!skel)
    {
        return skel;
    }

    //
    // Set eBPF program globals
    //
    std::string path = "/proc/" + std::to_string(config->ProcessId) + "/ns/pid";
    // struct stat sb = { 0, };
    // if (stat(path.c_str(), &sb) == -1)
    // {
    //     //Trace("Failed to stat %s (%s)\n", path.c_str(), strerror(errno));
    //     return nullptr;
    // }

    // skel->bss->dev = sb.st_dev;
    // skel->bss->inode = sb.st_ino;
    // skel->bss->target_PID = config->ProcessId;
    // skel->bss->sampleRate = config->SampleRate;
    // skel->bss->currentSampleCount = 1;
    // if(config->DiagnosticsLoggingEnabled != none)
    // {
    //     skel->bss->isLoggingEnabled = true;
    // }

    ret = traceEngin__load(skel);
    if (ret)
    {
        return nullptr;
    }

    ret = traceEngin__attach(skel);
    if (ret)
    {
        traceEngin__destroy(skel);
        return nullptr;
    }

    return skel;
}