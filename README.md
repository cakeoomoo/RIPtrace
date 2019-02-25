# RIPtrace

RIPtrace is a very SIMPLE RIP(Instruction pointer) tracer of CLI tool in less than 0.5-kilo lines of code, And does not depend on other library.

## Usage

```bash
./RIPtrace -t [exec-file] "--trace
./RIPtrace -c [log-filename] "--check
./RIPtrace -a [PID] [breakpoint-address] "--attach
./RIPtrace -h "--help
```
  

 
##Demo

![](https://github.com/cakeoomoo/RIPtrace/blob/master/demo.gif)



## Build

```
make  
```

## Description

All runnning process have a IP(intruction pointer) otherwise PC(program counter) that the runnning process indicate at the next.
RIPtracer can record all RIP(64bit) of the process from entry-point to exit-point and can out the logfile on the linux machine.
  
In addition to reacording, It can search RIP, So You can check the program-flow of your program with some reversing tool like objdump or IDA.
And, It can attach and trace for running process on the linux.
  

## LICENSE

[MIT](http://b4b4r07.mit-license.org)

