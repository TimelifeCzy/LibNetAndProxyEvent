#pragma once

class eBPFMonitor
{
public:
    eBPFMonitor(/* args */);
    ~eBPFMonitor();

public:
    static struct perf_buffer* m_pb;
    static void* EbpfTraceEventThread(void* thread_args);

public:
    int CreateMonitorThread(struct TraceEnginConfiguration* self);
    int StartMonitor(struct TraceEnginConfiguration* monitorConfig);
    void StopMonitor(struct TraceEnginConfiguration* monitorConfig);

    const bool GetStopStu() { return m_tStop; }

private:
    int CreateThreadEx(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*Thread) (void*), void* arg);

private:
    bool m_tStop = false;
};

using SingleeBPFMonitor = ustdex::Singleton<eBPFMonitor>;