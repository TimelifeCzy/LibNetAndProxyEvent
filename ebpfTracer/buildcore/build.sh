directory="/project/LibNetAndProxyEvent/ebpfTracer/core/"
clang -O2 -g -I "../../include" -target bpf -D__KERNEL__ -D__TARGET_ARCH_x86_64 -D__BPF_TRACING__ -D__linux__ -fno-stack-protector -c "${directory}traceEngin.c" -o "traceEngin.ebpf.o"
# bpftool gen object traceEngin.ebpf.o traceEngin.o
bpftool gen skeleton "traceEngin.ebpf.o" name "traceEngin" > "traceEngin.skel.h"
cp traceEngin.skel.h ../../include
cp traceEngin.ebpf.o ../../lib