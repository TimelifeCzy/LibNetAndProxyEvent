#include "Utiliy.h"
#include "Monitor.h"
#include "EbpfTraceEngine.h"

EbpfTraceEngine::EbpfTraceEngine(/* args */)
{
}

EbpfTraceEngine::~EbpfTraceEngine()
{
}

int EbpfTraceEngine::CreateThread(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*monitorThread) (void*), void* arg)
{
    int rc = -1;

    if (self->nThreads < MAX_TRIGGERS)
    {
        if ((rc = pthread_create(&self->Threads[self->nThreads].thread, nullptr, monitorThread, arg)) != 0)
        {
            return rc;
        }

        self->Threads[self->nThreads].trigger = triggerType;
        self->nThreads++;

    }
    else
    {
        //Trace("CreateThread: max number of triggers reached.");
    }

    return rc;
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
    traceEngin__destroy(skel);
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