#include "Utiliy.h"

#include "traceEngin.skel.h"
#include "eBPFMonitor.h"
#include "TaskHandler.h"

#include <thread>

void* eBPFMonitor::EbpfTraceEventThread(void* thread_args)
{
    // struct TraceEnginConfiguration* config = (struct TraceEnginConfiguration*)thread_args;
    // if (!config || (config == nullptr))
    //     return nullptr;
    while (1) {
        if (SingleeBPFMonitor::instance()->GetStopStu())
            break;

        
        // sleep thread for 10ms
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
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

    
    rc = CreateThreadEx(self, Processor, eBPFMonitor::EbpfTraceEventThread, nullptr);
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

void eBPFMonitor::StopMonitor(struct TraceEnginConfiguration* monitorConfig) {
    if (!monitorConfig || (nullptr == monitorConfig))
        return;
    
    m_tStop = true;
    for (int i = 0; i < monitorConfig->nThreads; ++i) {
        const int tids = monitorConfig->Threads[i].thread;
        const int pState = pthread_kill(monitorConfig->Threads[i].thread, 0);
        if (pState == 0 && tids) {
            pthread_detach(tids);
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            pthread_cancel(tids);
        }
    }
}