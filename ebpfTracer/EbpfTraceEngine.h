#pragma one

#define MAX_TRIGGERS 10

enum TriggerType
{
    Processor,
    Commit,
    Timer,
    Signal,
    ThreadCount,
    FileDescriptorCount,
    Exception,
    GCThreshold,
    GCGeneration,
    Restrack
};

struct TriggerThread
{
    pthread_t thread;
    enum TriggerType trigger;
};

struct TraceEnginConfiguration
{
    // Enable
    bool bEnablebpf;

    // Process and System info
    pid_t ProcessId;
    pid_t ProcessGroup;         // -pgid
    bool bProcessGroup;         // -pgid

    // multithreading
    // set max number of concurrent dumps on init (default to 1)
    int nThreads;
    struct TriggerThread Threads[MAX_TRIGGERS];
    pthread_mutex_t ptrace_mutex;
    pthread_cond_t dotnetCond;
    pthread_mutex_t dotnetMutex;
    bool bSocketInitialized;
};

class EbpfTraceEngine
{
private:
    /* data */
public:
    EbpfTraceEngine(/* args */);
    ~EbpfTraceEngine();

public:
    int CreateThread(struct TraceEnginConfiguration* self, enum TriggerType triggerType, void* (*monitorThread) (void*), void* arg);
    void SetMaxRLimit();
    void StopRestrack(struct traceEngin* skel);
    struct traceEngin* const RunRestrack(struct TraceEnginConfiguration* config);
};

using SingleEbpfTraceEngine = ustdex::Singleton<EbpfTraceEngine>;