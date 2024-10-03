#pragma once

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);

void* EbpfTraceEventThread(void* thread_args);

int CreateMonitorThread(struct TraceEnginConfiguration* self);
int StartMonitor(struct TraceEnginConfiguration* monitorConfig);