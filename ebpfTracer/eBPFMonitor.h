#pragma once

class eBPFMonitor
{
public:
    eBPFMonitor(/* args */);
    ~eBPFMonitor();

public:
    int CreateMonitorThread(struct TraceEnginConfiguration* self);
    int StartMonitor(struct TraceEnginConfiguration* monitorConfig);

private:
    int CreateThreadEx(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*Thread) (void*), void* arg);
};

using SingleeBPFMonitor = ustdex::Singleton<eBPFMonitor>;