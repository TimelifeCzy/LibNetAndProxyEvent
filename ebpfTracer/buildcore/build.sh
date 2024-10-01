directory="/project/LibNetAndProxyEvent/ebpfTracer/core/"
clang -O2 -g -I "../../include" -target bpf -fno-stack-protector -c "${directory}traceEngin.c" -o "traceEngin.ebpf.o"
# bpftool gen object traceEngin.ebpf.o traceEngin.o
bpftool gen skeleton "traceEngin.ebpf.o" name "traceEngin" > "traceEngin.skel.h"
cp traceEngin.skel.h ../../include
cp traceEngin.ebpf.o ../../lib