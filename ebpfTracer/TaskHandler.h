#pragma once
#include <queue>
#include <thread>
#include <condition_variable>

typedef struct _TaskHandlerNode
{
    // eBPF perf iid
    eBPFPerfEvent taskid;

    void clear()
    {
        taskid = eBPFPerfEvent::eBPFStart;
    }
}TaskHandlerNode, * PTaskHandlerNode;

class TaskHandler
{
public:
    TaskHandler();
    ~TaskHandler();

public:
    void IntiTaskThread();
    void StopTaskThread();

    void DispatchTaskHandle(const eBPFPerfEvent taskid, TaskHandlerNode& taskNode);

    void PushTaskMsg(void* pTaskHandlerNode);
    void PopTaskMsg();

private:
    bool m_bExit = false;
    bool m_btaskinit = false;

    std::mutex m_taskmtx;
    std::queue<TaskHandlerNode> m_taskqueu;

    std::thread m_write_thread;
    std::condition_variable m_write_cv;
};

using SingleTaskHandler = ustdex::Singleton<TaskHandler>;