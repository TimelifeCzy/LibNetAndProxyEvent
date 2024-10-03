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

    return nullptr;
}

int CreateThreadEx(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*Thread) (void*), void* arg)
{
    int rc = -1;

    if (self->nThreads < MAX_TRIGGERS)
    {
        if ((rc = pthread_create(&self->Threads[self->nThreads].thread, NULL, Thread, arg)) != 0)
        {
            return rc;
        }

        self->Threads[self->nThreads].trigger = triggerType;
        self->nThreads++;

    }
    else
    {
        //Trace("CreateThreadEx: max number of triggers reached.");
    }

    return rc;
}

int CreateMonitorThread(struct TraceEnginConfiguration* self)
{
    int rc = -1;
    if (!self || (self == nullptr))
        return rc;

    
    rc = CreateThreadEx(self, Processor, EbpfTraceEventThread, nullptr);
    return rc;
}

int StartMonitor(struct TraceEnginConfiguration* monitorConfig)
{
    int rc = -1;
    if (!monitorConfig || (monitorConfig == nullptr))
        return rc;
    
    rc = CreateMonitorThread(monitorConfig);
    return rc;
}
