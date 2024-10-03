```
branch dev-ebpf
```

### LinuxNet:
```
基于Asio实现Tcp_Server/Udp_Server，基于Ebpf实现包捕获，重注。
```

#### sys environment
```
Centos 7.6
Linux version 6.8.1-1.el7.elrepo.x86_64 (gcc (GCC) 9.3.1 20200408 (Red Hat 9.3.1-2), GNU ld version 2.32-16.el7) #1 SMP

Ubuntu 24.0
6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

#### devlopment environment
```
1. gcc version 11.2.1 20220127 (Red Hat 11.2.1-9) (GCC) or gcc version 13.2.0 (Ubuntu 13.2.0-23ubuntu4) 
2. GNU Make 3.82 or GNU Make 4.3
3. cmake version 3.29.0 or 4.x
4. clang Ubuntu clang version 18.1.3 (1ubuntu1)
5. bpftool v7.4.0, using libbpf v1.4
```

#### Source Tree
```
config: 
    desc: rule
ebpfTracer: 
    desc: bpf tc hook c++ .so .a
    - buildcore:
        desc: build bpf *.c to traceEngin.skel.h
    - core:
        desc: src bpf *.c
    - unitts
        desc: unit test bpf debug exec
include:
lib:
logging:
    desc: log
src:
    desc: C++ Proxy src
```

##### build ebpfTracer
```
cd ebpfTracer/build
cmake ..
make
```

#### build proxy
```
cd build
cmake ..
make
```