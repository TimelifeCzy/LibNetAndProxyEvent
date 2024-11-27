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
    void StopRestrack();
    const bool RunRestrack(struct TraceEnginConfiguration* config);

    void* GetSkel() { return (void*)m_skel; }

private:
    struct traceEngin* m_skel = nullptr;
};

using SingleeBPFTraceEngine = ustdex::Singleton<eBPFTraceEngine>;