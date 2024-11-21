#include "Utiliy.h"

#include "TaskHandler.h"

TaskHandler::TaskHandler()
{
}

TaskHandler::~TaskHandler()
{
}

void TaskHandler::IntiTaskThread()
{
    //LOG4CPLUS_DEBUG(g_logger, "IntiTaskThread start.");
    
    m_btaskinit = true;

    // bind loop
    m_write_thread = std::thread{ std::bind(&TaskHandler::PopTaskMsg, this) };

    //LOG4CPLUS_DEBUG(g_logger, "IntiTaskThread end, m_btaskinit  " << ((m_btaskinit == true) ? 1 : 0));
}

void TaskHandler::StopTaskThread()
{
    //LOG4CPLUS_DEBUG(g_logger, "CloseTask start.");
    m_bExit = true;
    m_write_cv.notify_one();
    if (m_write_thread.joinable())
        m_write_thread.join();
    //LOG4CPLUS_DEBUG(g_logger, "CloseTask end.");
}

void TaskHandler::DispatchTaskHandle(const eBPFPerfEvent taskid, TaskHandlerNode& taskNode) {
    //LOG4CPLUS_DEBUG(g_logger, "work exec taskid " << taskid);
}

void TaskHandler::PushTaskMsg(void* pTaskHandlerNode)
{
    //LOG4CPLUS_DEBUG(g_logger, "pushtaskmsg start.");
    if (!m_btaskinit)
    {
        //LOG4CPLUS_ERROR(g_logger, "PushTaskMsg m_btaskinit false Error.");
        return;
    }

    PTaskHandlerNode pTaskInfo = (PTaskHandlerNode)pTaskHandlerNode;
    if (!pTaskInfo || (pTaskInfo == nullptr))
    {
        //LOG4CPLUS_ERROR(g_logger, "PushTaskMsg pTaskInfo Error.");
        return;
    }

    // write task
    int taskid = 0;
    {
        std::unique_lock<std::mutex> lock(m_taskmtx);
        TaskHandlerNode taskNode;
        taskNode.taskid = pTaskInfo->taskid;
        taskid = taskNode.taskid;
        m_taskqueu.emplace(taskNode);
        m_write_cv.notify_one();
        //m_write_cv.notify_all();
    }
    //LOG4CPLUS_DEBUG(g_logger, "pushtaskmsg end taskid " << taskid);
}

void TaskHandler::PopTaskMsg()
{
    //LOG4CPLUS_DEBUG(g_logger, "poptaskmsg thread start.");
    if (!m_btaskinit)
    {
        //LOG4CPLUS_ERROR(g_logger, "m_btaskinit false, PopTaskMsg Exit.");
        return;
    }

    std::unique_lock<std::mutex> lock(m_taskmtx);
    while (true) {

        if (m_bExit)
            break;
        
        // wait task 
        m_write_cv.wait(lock);
        if (m_bExit)
            break;
        
        // pop task info
        TaskHandlerNode taskNode;
        while (!m_taskqueu.empty()) {
            taskNode.clear();
            taskNode = m_taskqueu.front();
            m_taskqueu.pop();

            if (m_bExit)
                break;
            
            if (taskNode.taskid >= eBPFPerfEvent::eBPFEnd)
                continue;

            // Dispatch
            DispatchTaskHandle(taskNode.taskid, taskNode);
        }
    }
    //LOG4CPLUS_DEBUG(g_logger, "poptaskmsg thread end.");
}