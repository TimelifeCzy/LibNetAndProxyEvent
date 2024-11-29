```
branch dev-ebpf
```

### LinuxNet:
```
基于Asio实现Tcp_Server/Udp_Server，基于eBPF实现包捕获，重注。
```

#### sys environment
```
Centos 7.6
Linux version 6.8.1-1.el7.elrepo.x86_64 (gcc (GCC) 9.3.1 20200408 (Red Hat 9.3.1-2), GNU ld version 2.32-16.el7) #1 SMP

Ubuntu 22.0
5.15.0-125-generic #135-Ubuntu SMP Fri Sep 27 13:53:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

#### devlopment environment
```
1. gcc version 11.2.1 20220127 (Red Hat 11.2.1-9) (GCC) or gcc version 13.2.0 (Ubuntu 13.2.0-23ubuntu4) 
2. GNU Make 3.22 or up or GNU Make 4.3
3. cmake version 3.29.0 or 4.x
4. clang Ubuntu clang version 18.1.3 (1ubuntu1)
5. bpftool v7.4.0, using libbpf v1.4
```

#### apt
```
apt-get install libelf-dev
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

##### build eBPF Tracer
eBPF core build, create traceEngin.skel.h & traceEngin.ebpf.o 
```
cd ebpfTracer/buildcore
./build.sh
```

libebpftrace: Compile first, Build create file to libebpftrace.so or libebpftrace.a or unit exe
```
cd ebpfTracer/build
./build.sh
```

unitts: build to exec file, test libebpftrace.so or libebpftrace.a
```
cd ebpfTracer/unitts
测试请unitts请到ebpfTracer/build执行./build.sh
cmake .不可用
```

#### build proxy
```
cd build
cmake ..
make
```