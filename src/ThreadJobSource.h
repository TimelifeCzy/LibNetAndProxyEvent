#pragma once
#include <Windows.h>

class ThreadJobSource
{
public:
	virtual void execute() = 0;
	virtual void threadStarted() = 0;
	virtual void threadStopped() = 0;
};

