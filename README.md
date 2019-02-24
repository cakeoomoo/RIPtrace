# RIPtrace

TIPtrace is a very simple RIP(64bit instruction pointer) tracer in less than 0.5-kilo lines of code, And does not depend on other library.

Usage: RIPtrace --trace <filename>

All Usage:
 ./RIPtrace --check <log-file>    : check rip
 ./RIPtrace --trace <exec-file>   : trace exec
 ./RIPtrace --help                : show help


Demo:  

![](https://media.giphy.com/media/vFKqnCdLPNOKc/giphy.gif)

![](http://i.imgur.com/60bts.gif)


All program have a IP(intruction pointer) otherwise PC(program counter) that the runnning process indicate at the next.
RIPtracer can record all RIP(64bit) of the process from entry-point to exit-point and can out the logfile.
In addition to reacording, It can search RIP, And You can check the program-flow of your program with some reversing tool like objdump or IDA.
However, It doesnot attach and dettach to runnning process:)


MIT License

