# RIPtrace

TIPtrace is a very simple RIP(64bit instruction pointer) tracer of CLI tool in less than 0.5-kilo lines of code, And does not depend on other library.

## Usage

```
./RIPtrace --trace [exec-file]
./RIPtrace --check [log-filename
```
  
##Demo:  

![](https://github.com/cakeoomoo/RIPtrace/blob/master/demo.gif)



## Build

```
make  
```

## Description

All runnning process have a IP(intruction pointer) otherwise PC(program counter) that the runnning process indicate at the next.
RIPtracer can record all RIP(64bit) of the process from entry-point to exit-point and can out the logfile on the linux machine.
  
In addition to reacording, It can search RIP, So You can check the program-flow of your program with some reversing tool like objdump or IDA.
However, It still does not attach and dettach to runnning process:)
  

## LICENSE

[MIT](http://b4b4r07.mit-license.org)

