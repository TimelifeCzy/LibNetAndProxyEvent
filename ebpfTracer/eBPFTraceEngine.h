#pragma once

class eBPFTraceEngine
{
private:
    /* data */
public:
    eBPFTraceEngine(/* args */);
    ~eBPFTraceEngine();

public:
    void SetMaxRLimit();
    void StopRestrack(struct traceEngin* skel);
    struct traceEngin* const RunRestrack(struct TraceEnginConfiguration* config);
};

using SingleeBPFTraceEngine = ustdex::Singleton<eBPFTraceEngine>;