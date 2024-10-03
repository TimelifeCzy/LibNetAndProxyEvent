#include "Utiliy.h"
#include "traceEngin.skel.h"

#define MAX_TRIGGERS 10

enum TriggerType
{
    Processor,
    Commit,
    Timer,
    Signal,
    ThreadCount,
    FileDescriptorCount,
    Exception,
    GCThreshold,
    GCGeneration,
    Restrack
};

struct TriggerThread
{
    pthread_t thread;
    enum TriggerType trigger;
};

struct TraceEnginConfiguration
{
    // Enable
    bool bEnablebpf;

    // Process and System info
    pid_t ProcessId;
    pid_t ProcessGroup;         // -pgid
    bool bProcessGroup;         // -pgid

    // multithreading
    // set max number of concurrent dumps on init (default to 1)
    int nThreads;
    struct TriggerThread Threads[MAX_TRIGGERS];
    pthread_mutex_t ptrace_mutex;
    pthread_cond_t dotnetCond;
    pthread_mutex_t dotnetMutex;
    bool bSocketInitialized;
};

int CreateThread(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*monitorThread) (void*), void* arg)
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
        //Trace("CreateMonitorThread: max number of triggers reached.");
    }

    return rc;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
    return vfprintf(stderr, format, args);
    return 0;
}

void SetMaxRLimit()
{
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    setrlimit(RLIMIT_MEMLOCK, &lim);
}

void StopRestrack(struct traceEngin* skel)
{
    traceEngin__destroy(skel);
}

struct traceEngin* RunRestrack(struct TraceEnginConfiguration *config)
{
    int ret = -1;
    struct traceEngin *skel = nullptr;

    if (!config)
        return nullptr;

    SetMaxRLimit();

    //
    // Setup extended error logging
    //
    if(config->bEnablebpf == false)
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

void* EbpfTraceEventThread(void* thread_args /* struct ProcDumpConfiguration* */)
{
    struct TraceEnginConfiguration* config = (struct TraceEnginConfiguration*)thread_args;
    if (!config || (config == nullptr))
        return nullptr;
    
    int rc = 0;

    return nullptr;
}

// Unit test bpf trace montior
int main(int argc, char** argv)
{
    TraceEnginConfiguration engincfg;
    engincfg.bEnablebpf = true;
    engincfg.ProcessId = getpid();

    // start bpf
    traceEngin* pTrace = RunRestrack(&engincfg);
    if (pTrace == nullptr)
        return 0;

    // start event thread
    CreateThread(&engincfg, Processor, EbpfTraceEventThread, nullptr);

    return 0;
}