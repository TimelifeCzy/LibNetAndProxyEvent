#include "Utiliy.h"

#include "traceEngin.skel.h"
#include "eBPFMonitor.h"

void* EbpfTraceEventThread(void* thread_args)
{
    struct TraceEnginConfiguration* config = (struct TraceEnginConfiguration*)thread_args;
    if (!config || (config == nullptr))
        return nullptr;
        
    return nullptr;
}

eBPFMonitor::eBPFMonitor() {
}

eBPFMonitor::~eBPFMonitor() {
}

int eBPFMonitor::CreateThreadEx(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*Thread) (void*), void* arg)
{
    int rc = -1;

    if (self->nThreads < MAX_TRIGGERS)
    {
        if ((rc = pthread_create(&self->Threads[self->nThreads].thread, nullptr, Thread, arg)) != 0)
        {
            return rc;
        }

        self->Threads[self->nThreads].trigger = triggerType;
        self->nThreads++;

    }
    else
    {
    }

    return rc;
}

int eBPFMonitor::CreateMonitorThread(struct TraceEnginConfiguration* self)
{
    int rc = -1;
    if (!self || (self == nullptr))
        return rc;

    
    rc = CreateThreadEx(self, Processor, EbpfTraceEventThread, nullptr);
    return rc;
}

int eBPFMonitor::StartMonitor(struct TraceEnginConfiguration* monitorConfig)
{
    int rc = -1;
    if (!monitorConfig || (monitorConfig == nullptr))
        return rc;
    
    rc = CreateMonitorThread(monitorConfig);
    return rc;
}
