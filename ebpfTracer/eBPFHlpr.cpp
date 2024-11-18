#include "Utiliy.h"
#include <bpf/libbpf.h>

#include "eBPFHlpr.h"

int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
    return vfprintf(stderr, format, args);
}