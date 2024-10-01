#include "Utiliy.h"
#include "traceEngin.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if(g_config.DiagnosticsLoggingEnabled != none)
    {
        return vfprintf(stderr, format, args);
    }

    return 0;
}

void StopRestrack(struct procdump_ebpf* skel)
{
    traceEngin__destroy(skel);
}

struct procdump_ebpf* RunRestrack(struct ProcDumpConfiguration *config)
{
    int ret = -1;
    struct procdump_ebpf *skel = NULL;

    //SetMaxRLimit();

    //
    // Setup extended error logging
    //
    if(config->DiagnosticsLoggingEnabled != none)
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
    struct stat sb = {};
    if (stat(path.c_str(), &sb) == -1)
    {
        Trace("Failed to stat %s (%s)\n", path.c_str(), strerror(errno));
        return NULL;
    }

    skel->bss->dev = sb.st_dev;
    skel->bss->inode = sb.st_ino;
    skel->bss->target_PID = config->ProcessId;
    skel->bss->sampleRate = config->SampleRate;
    skel->bss->currentSampleCount = 1;
    if(config->DiagnosticsLoggingEnabled != none)
    {
        skel->bss->isLoggingEnabled = true;
    }

    ret = traceEngin__load(skel);
    if (ret)
    {
        return NULL;
    }

    ret = traceEngin__attach(skel);
    if (ret)
    {
        traceEngin__destroy(skel);
        return NULL;
    }

    return skel;
}

int main(int argc, char** argv)
{
    return 0;
}