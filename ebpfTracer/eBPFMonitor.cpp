#include "Utiliy.h"
#include "bpf/libbpf.h"
#include "traceEngin.skel.h"

#include "eBPFTraceEngine.h"
#include "TaskHandler.h"
#include "eBPFMonitor.h"

#include <thread>

struct perf_buffer* eBPFMonitor::m_pb = nullptr;

void perf_event(void* ctx, int cpu, void* data, __u32 data_sz)
{
    // const struct event* e = data;
    // if (!e)
    //     return;
    
    // int fd, err;
    // int sps_cnt;
    // time_t t;
    // char ts[32] = { 0, };

    // /* name filtering is currently done in user space */
    // e->comm;

    // /* prepare fields */
    // struct tm* tm = nullptr;
    // time(&t);
    // tm = localtime(&t);
    // strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    // if (e->ret >= 0) {
    //     fd = e->ret;
    //     err = 0;
    // }
    // else {
    //     fd = -1;
    //     err = -e->ret;
    // }

    // /* print output */
    // sps_cnt = 0;
    // if (env.timestamp) {
    //     printf("%-8s ", ts);
    //     sps_cnt += 9;
    // }
    // if (env.print_uid) {
    //     printf("%-7d ", e->uid);
    //     sps_cnt += 8;
    // }
    // printf("%-6d %-16s %3d %3d ", e->pid, e->comm, fd, err);
    // sps_cnt += 7 + 17 + 4 + 4;
    // if (env.extended) {
    //     printf("%08o ", e->flags);
    //     sps_cnt += 9;
    // }
    // printf("%s\n", e->fname);
}

void perf_lost_events(void* ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void* eBPFMonitor::EbpfTraceEventThread(void* thread_args)
{
    // struct TraceEnginConfiguration* config = (struct TraceEnginConfiguration*)thread_args;
    // if (!config || (config == nullptr))
    //     return nullptr;

    traceEngin* skel = (traceEngin*)SingleeBPFTraceEngine::instance()->GetSkel();
    if (!skel || (skel == nullptr)) {
        return nullptr;
    }

    eBPFMonitor::m_pb = perf_buffer__new(
        bpf_map__fd(skel->maps.net_events),
        PERF_BUFFER_PAGES,
        perf_event,
        perf_lost_events,
        NULL,
        NULL
    );

    if (!eBPFMonitor::m_pb || (nullptr == eBPFMonitor::m_pb)) {
        return nullptr;
    }
    
    int err = 0;
    while (1) {
        if (SingleeBPFMonitor::instance()->GetStopStu())
            break;

        if (!eBPFMonitor::m_pb || (nullptr == eBPFMonitor::m_pb))
            break;

        err = perf_buffer__poll(eBPFMonitor::m_pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR)
            break;
        err = 0;
    }

    if (eBPFMonitor::m_pb) {
        perf_buffer__free(eBPFMonitor::m_pb);
        eBPFMonitor::m_pb = nullptr;
    }

    // send single
    const int pid = getpid();
    kill(pid, SIGINT);

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