# antiPtrace
过常见的反调试引起的调试器无法attach到进程的问题

还有一种情况，收集crash的sigaction函数可能会与lldb的异常处理机制冲突，导致lldb无法正常工作。
因此当寻找无果时，最好尝试关闭app的崩溃收集的SDK的初始化方法

## rootless compile
make clean && make package  FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless

## rootful compile
make clean && make package  FINALPACKAGE=1

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.