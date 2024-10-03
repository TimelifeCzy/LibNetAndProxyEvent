#pragma once

class EbpfTraceEngine
{
private:
    /* data */
public:
    EbpfTraceEngine(/* args */);
    ~EbpfTraceEngine();

public:
    void SetMaxRLimit();
    void StopRestrack(struct traceEngin* skel);
    struct traceEngin* const RunRestrack(struct TraceEnginConfiguration* config);
};

using SingleEbpfTraceEngine = ustdex::Singleton<EbpfTraceEngine>;