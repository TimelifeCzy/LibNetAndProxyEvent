#include "Utiliy.h"
#include "Monitor.h"

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
    return vfprintf(stderr, format, args);
    return 0;
}

void* EbpfTraceEventThread(void* thread_args)
{
    struct TraceEnginConfiguration* config = (struct TraceEnginConfiguration*)thread_args;
    if (!config || (config == nullptr))
        return nullptr;

    int rc = 0;

    return nullptr;
}