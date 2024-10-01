directory=/project/LibNetAndProxyEvent/ebpfTracer/core/
clang -O2 -g -I "../../include" -target bpf -fno-stack-protector -c "${directory}traceEngin.c" -o "${directory}traceEngin.ebpf.o"
bpftool gen skeleton "${directory}traceEngin.ebpf.o" name "${directory}traceEngin" > "${directory}traceEngin.skel.h"