#include "Utiliy.h"
#include "traceEngin.skel.h"

struct TraceEnginConfiguration
{
    // Enable
    bool bEnablebpf;

    // Process and System info
    pid_t ProcessId;
    pid_t ProcessGroup;         // -pgid
    bool bProcessGroup;         // -pgid
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
    return 0;
}

void StopRestrack(struct traceEngin* skel)
{
    traceEngin__destroy(skel);
}

struct traceEngin* RunRestrack(struct TraceEnginConfiguration *config)
{
    int ret = -1;
    struct traceEngin *skel = nullptr;

    //SetMaxRLimit();

    //
    // Setup extended error logging
    //
    if(config->bEnablebpf == false)
    {
        return nullptr;
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

int main(int argc, char** argv)
{
    RunRestrack(nullptr);
    return 0;
}