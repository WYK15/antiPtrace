# antiPtrace
过常见的反调试引起的调试器无法attach到进程的问题

## rootless compile
make clean && make package  FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless

## rootful compile
make clean && make package  FINALPACKAGE=1