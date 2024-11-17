#pragma once

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);

class EbpfMonitor
{
public:
    EbpfMonitor(/* args */);
    ~EbpfMonitor();

public:
    int CreateMonitorThread(struct TraceEnginConfiguration* self);
    int StartMonitor(struct TraceEnginConfiguration* monitorConfig);

private:
    int CreateThreadEx(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*Thread) (void*), void* arg);
};

using SingleEbpfMonitor = ustdex::Singleton<EbpfMonitor>;