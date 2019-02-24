/*
 * TIPtrace -- A very simple RIP(64bit instruction pointer) tracer in less than 0.5-kilo lines of code, And does not depend on other library.
 *
 *
 * The MIT License (MIT)
 *
 *
 * Copyright (C) 2019 yuma masubuchi <poo_eix at protonmail dot com>
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/ptrace.h> 
#include <sys/reg.h>    
#include <sys/types.h>  
#include <sys/wait.h>   
#include <errno.h>
#include <sys/user.h>   
#include <sys/stat.h>   
#include <unistd.h>     
#include <sys/syscall.h>
#include <time.h>
#include <sys/time.h>
#include <elf.h>        

/* print color character at stdout. */
#define beRED(string) "\x1B[0;31m" string "\x1B[0m"
#define beGRN(string) "\x1B[0;32m" string "\x1B[0m"
#define beYEL(string) "\x1B[0;33m" string "\x1B[0m"
#define beBLU(string) "\x1B[0;34m" string "\x1B[0m"
#define beMAG(string) "\x1B[0;35m" string "\x1B[0m"
#define beCYN(string) "\x1B[0;36m" string "\x1B[0m"
#define beWHT(string) "\x1B[0;37m" string "\x1B[0m"
#define beRED_B(string) "\x1B[1;31m" string "\x1B[0m"
#define beGRN_B(string) "\x1B[1;32m" string "\x1B[0m"
#define beYEL_B(string) "\x1B[1;33m" string "\x1B[0m"
#define beBLU_B(string) "\x1B[1;34m" string "\x1B[0m"
#define beMAG_B(string) "\x1B[1;35m" string "\x1B[0m"
#define beCYN_B(string) "\x1B[1;36m" string "\x1B[0m"
#define beWHT_B(string) "\x1B[1;37m" string "\x1B[0m"
#define IPtrace_VERSION "0.0.1"

/* debug option on gcc: -LDEBUG   */
#ifdef DEBUG
    #define debug_printf printf
#else
    #define debug_printf 1 ? (void) 0 : printf
#endif

enum STATUS_CONST_NUM{
    BIT32 = 1,
    BIT64 = 2,
    CMDTEXT_SIZE = 256,
    OUTPUT_STR_BUF = 128,
    COMMAND_LENGTH = 128,
    GET_TIMEOFDAY_MALLOC_SIZE = 64,
    GREP_CMD_TEXT_SIZE = 128,
    GET_ELFFILE_BIT = 4,
    MALLOC_SIZE_BUF_BEFORE_WRITE = 512,
    BUF_THRESHOLD_BEFORE_WRITE = 128,
    LOGFILE_NAME_BUF = 128,
    TRACERFILE_NAME_BUF = 128,
};
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/*  define elf header of target file */
/* ------------------------------------------------------------------------- */
Elf64_Ehdr tracee_elfheader;

/* other status of tracee */
typedef struct status_exec {
    int bit;
    long entry_p;
} status_exec;
status_exec GV_tracee_status;


/* status of tracer */
typedef struct status_file {
    char tracerfilename[TRACERFILE_NAME_BUF];
    char logfilename[LOGFILE_NAME_BUF];
} status_file;
status_file GV_tracer_info;





/* ------------------------------------------------------------------------- */




/* ------------------------------------------------------------------------- */
/*  It is to call tracee process as child by tracer process as parent  */
/* ------------------------------------------------------------------------- */
void call_pipe(const char * restrict str) {
    char cpy_str[COMMAND_LENGTH];
    strncpy( cpy_str, str,COMMAND_LENGTH);
    *(cpy_str + COMMAND_LENGTH - 1) = '\0';
   
    if( cpy_str != NULL)
        system(cpy_str);
    else
        puts("your argment of argments_pipe() is wrong!!!");
}

void ps_attach(pid_t pid) {
    int status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "failed to attach\n");
        fprintf(stderr,"not attach to %i\n", pid);
        exit(1);
    }
    printf("attach to %i\n", pid);

    waitpid(pid, &status, 0);
}

void ps_dettach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
    fprintf(stderr, "failed to dettach\n");
        exit(1);
    }
    printf("dettach to %i\n", pid);
}


/* ------------------------------------------------------------------------- */
/*  how to use 
        1. need to do free(); !!! ,because getline include malloc()
        2. argument2 of check_except_lf
            = 0: except linefeed
            = 1: not except linefeed
        exp)
            char * input_str = input_string_simple();
            printf("input_str is %s" ,input_str);
            free (input_str);                                           */
/* ------------------------------------------------------------------------- */
char * input_string_simple (char * text_msg, int check_except_lf){
    char *line = NULL;
    size_t len = 0;
    ssize_t read_str;
    char * message_input = ", quit:[ctrl + d] >>>> ";

    /* stdout message */
    printf(beGRN("\n%s, or %s"), text_msg, message_input);

    /* if you input ctrl + d, break while-loop */
    while ((read_str = getline(&line, &len, stdin)) != -1) {
        if (read_str > 0)
            debug_printf (beBLU("\n  read %zd chars from stdin, allocated %zd bytes for line : %s"), read_str, len, line);

        printf(beGRN("\n%s, or %s"), text_msg, message_input);
    }
    printf("\n");

    /* strip character */
    if(check_except_lf == 0){
        /*  except last char '\n' */
        int i = 1;
        while(line[i]!='\0') {
            i++;
        }
        line[i-1] = '\0';
    }

    return line;
}

char * input_string_simple_more (char * text_msg, int check_except_lf){
    char *line = (char*)malloc(GREP_CMD_TEXT_SIZE);
    size_t len = 0;

    printf(beGRN("\n%s"), text_msg);
    getline(&line, &len, stdin);

    /* strip character */
    if(check_except_lf == 0){
        /*  except last char '\n' */
        int i = 1;
        while(line[i]!='\0') {
            i++;
        }
        line[i-1] = '\0';
    }

    return line;
}

/* ------------------------------------------------------------------------- */
/*  how to use 
        exp)
            char * text_msg = "your input >>>";
            char input_char = input_character_simple(text_msg);  */
/* ------------------------------------------------------------------------- */
char input_character_simple (char * text_msg) {
    printf(beGRN("%s"),text_msg);
    setbuf(stdin, NULL);
    char a = getchar ();
    getchar();  /* to escape linefeed as [\n] */
    return a;
}

char * get_string_gettimeofday() {
    
    char * buffer = (char *)malloc(GET_TIMEOFDAY_MALLOC_SIZE);
    struct timeval t1;    

    gettimeofday(&t1, 0);
    time_t curtime=t1.tv_sec;

    strftime(buffer, GET_TIMEOFDAY_MALLOC_SIZE, "%Y%m%d_%H%M", localtime(&curtime));
    debug_printf("time string is %s\n", buffer);

    return buffer;
}

int make_new_logfile() {
    FILE * fp;

    /* get current time */
    char * time_str = get_string_gettimeofday();
    debug_printf("time_str is %s\n", time_str);

    srand(time(NULL));
    int rand4name = rand()%100;

    snprintf(GV_tracer_info.logfilename, sizeof(GV_tracer_info.logfilename), "LOG_TRACE_%s_%d.log", time_str,rand4name);
    free(time_str);


    debug_printf("%s\n", GV_tracer_info.logfilename);

    fp = fopen(GV_tracer_info.logfilename, "wx");
    if (fp == NULL) {
        puts(beRED("file not created...")"\n");
        return 1;
    }
    printf(beBLU("make logile: %s\n"), GV_tracer_info.logfilename);

    fclose(fp);
    return 0;
}

int append_logfile(const char * restrict w_strings) {
    FILE * fp;

    /*  for logfile    */
    static long count = 0;
    count++;

    fp = fopen(GV_tracer_info.logfilename, "a");
    if (fp == NULL) {
        puts(beRED("file not created...")"\n");
        return 1;
    }

    /* write(append) string  */
    fprintf(fp, "%ld: %s\n", count, w_strings); 

    fclose(fp);
    return 0;
}

int append_logfile_ver2(const char * w_strings) {
    FILE * fp;
    fp = fopen(GV_tracer_info.logfilename, "a");

    if (fp == NULL) {
        fprintf(stderr,beRED("file not created...")"\n");
        return 1;
    }

    /* write down(append) string  */
    fprintf(fp, "%s\n", w_strings); 

    fclose(fp);
    return 0;
}


/* ------------------------------------------------------------------------- */
/*  to convert for little endian and 64bit
        1. convert to vice order from current byte
        2. exp) 12345678  ==>> 78563412          */
/* ------------------------------------------------------------------------- */
long convertNum_endian(long input) {
    long out = 0;
    out += (input & 0x00000000000000ff) << (7*8);
    out += (input & 0x000000000000ff00) << (5*8);
    out += (input & 0x0000000000ff0000) << (3*8);
    out += (input & 0x00000000ff000000) << (1*8);
    out += (input & 0x000000ff00000000) >> (1*8);
    out += (input & 0x0000ff0000000000) >> (3*8);
    out += (input & 0x00ff000000000000) >> (5*8);
    out += (input & 0xff00000000000000) >> (7*8);
    return out;
}

void ps_continue_stop_by_status(pid_t pid) {
    int status = 0;

    /* only continuing process */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    debug_printf("Continuing.\n");

    /*  get pid status  */
    waitpid(pid, &status, 0);

    //status check (exit routine)
    if (WIFEXITED(status)) {
        debug_printf("Program exited normally.\n");
        debug_printf("status: %d",status);
        exit(0);
    }
    //status check (breakpoint routine)
    if (WIFSTOPPED(status))
        debug_printf("Breakpoint.\n");
    else
        exit(1);
}

int ps_continue_stop_by_status_ver2(pid_t pid) {
    int status = 0;

    /* only continuing process */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    debug_printf("Continuing.\n");

    /*  get pid status  */
    waitpid(pid, &status, 0);

    //status check (exit routine)
    if (WIFEXITED(status)) {
        debug_printf("Program exited normally.\n");
        debug_printf("status: %d",status);
        return 1;
    }
    //status check (breakpoint routine)
    if (WIFSTOPPED(status)) {
        debug_printf("Breakpoint.\n");
        return 0;
    } else{
        return 1;
    }

}

/* ------------------------------------------------------------------------- */
/*   writet original_text on addr(address) */
/* ------------------------------------------------------------------------- */
void ps_deleteBP_switch_original(pid_t pid, void *addr, long original_text) {

    /* define struct */
    struct user_regs_struct regs;
    regs.rip = 0;

    /*  get register of struct */
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    /*  change rip(instruction pointer) to any address(is breakpoint)  */
    regs.rip = (unsigned long) addr;

    /*  set register of struct */
    ptrace(PTRACE_SETREGS, pid, 0, &regs);

    /*  set text(instruction) at any address  */
    ptrace(PTRACE_POKETEXT, pid, addr, original_text);
}


void ps_stepi(pid_t pid) {
    int status = 0;
    /* step run */
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    /* get pid status just in case  */
    waitpid(pid, &status, 0);
}


long ps_set_breakpoint_for_addrOfpid(pid_t pid, void * addr) {
    long original_text;

    /* temporary save instruction of pointer by addr(argument) */
    original_text = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

    debug_printf("original_text:%lx(hex)\n", convertNum_endian(original_text));

    /* write 0xCC(INT 3 = intrusion) to addr(become breakpoint address)   */
    ptrace(PTRACE_POKETEXT, pid, addr, ((original_text & 0xFFFFFFFFFFFFFF00) | 0xCC));
    debug_printf("Breakpoint at %p.\n", addr);

    return original_text;
}

char input_wait() {
    printf(beGRN("0(quit) 1(step) 2(next) 3(record RIP)>>"));
    setbuf(stdin, NULL);
    char a = getchar ();
    getchar();  /* escape linefeed as [\n] */
    return a;
}

unsigned long get_next_rip_address(pid_t pid) {

    /* define struct */
    struct user_regs_struct regs;
    regs.rip = 0;

    /*  get register of struct and print this register */ 
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    debug_printf("RIP:%p\n", (void*)regs.rip);

    return (unsigned long)regs.rip;
}

long get_next_text(pid_t pid, void * next_addr){
    long next_text;
    next_text = ptrace(PTRACE_PEEKTEXT, pid, next_addr, NULL);

    return next_text;
}

/* return 0(error) or 1(success) */
long read_elfheader(const char* elfFilename){
    FILE* file = fopen(elfFilename, "rb");
    long return_value = 0;// set error code 

    if(file) {
        fread(&tracee_elfheader, 1, sizeof(tracee_elfheader), file);

        if (memcmp(tracee_elfheader.e_ident, ELFMAG, SELFMAG) == 0) {
            return_value = 1;
        }
        fclose(file);
    }
    return return_value;
}






/*  input: 0xXXXXXXXXXXXXXXXXX
    cpubit: 32, 64
    right_left: 0(right) ro 1(left)        */
int call_trace_rip(int argc, char ** argv,char ** envp) {
    printf(beGRN("start call_trace_rip()")"\n");
    long original_text;
    long next_text;
    void * next_addr;

    debug_printf(beRED("argv[0]:%s\nargv[1]:%s\nargv[2]:%s\nargv[3]:%s\n"),argv[0],argv[1],argv[2],argv[3]);

    /* control arguments */
    if (argc < 2) {
        printf(beGRN("Usage:sudo ./%s [pid] [address]\n    quit: '$ touch quit'"),argv[0]);
        printf(beRED("      or, did you forget sudo?\n"));
        exit(1);
    }


    pid_t pid = atoi(argv[1]);
    void * addr = (void *)strtol(argv[2], NULL, 0);


    /* make record file   */
    make_new_logfile();

    /* process attach  */
    ps_attach(pid);

    /* 
    *   main loop routine 
    */
    debug_printf(beBLU("-----auto record RIP-----"));
    while(1){
        /* set break point */
        original_text = ps_set_breakpoint_for_addrOfpid(pid, addr);

        /* continue and stop routine */   
        ps_continue_stop_by_status(pid);

        /* delete breakpint instruction(0xCC) and switch original address */   
        ps_deleteBP_switch_original(pid, addr, original_text);

        /* step run */
        ps_stepi(pid);
        
        /* get next rip address */
        next_addr = (void*)get_next_rip_address(pid);

        debug_printf("next addr = %p\n", next_addr);
        addr = next_addr;


        /*  write down  */
        char out_string[OUTPUT_STR_BUF];
        //printf("%d",addr);
        debug_printf("------------next addr =  %p\n", addr);
        sprintf(out_string, "%p", addr);
        debug_printf("out_string = %s\n", out_string);
        append_logfile(out_string);

        
        /* get next text */
        next_text = get_next_text(pid, next_addr);
        debug_printf("next_text:%lx(hex)\n",convertNum_endian(next_text));
    }

    /* process dettach  */
    ps_dettach(pid);
    puts("exit routine");
    return 0;
}





/* 
 *  1. grep rip address from traceRIP.log
 */
int call_check_rip(int argc, char ** argv, char ** envp) {

    const char * filename = argv[1];

    /* check record RIP  */
    debug_printf(beBLU("-----check record RIP-----"));
    debug_printf(beRED("argv[0]:%s\nargv[1]:%s\nargv[2]:%s\nargv[3]:%s\n"),argv[0],argv[1],argv[2],argv[3]);

    char * input_text = input_string_simple_more("Address >>>", 0);

    if(input_text[0] == '\0') {
        printf(beRED("ERROR: input is empty!\n"));
        return 0;
    }
 
    char cmd_text[GREP_CMD_TEXT_SIZE];

    snprintf(cmd_text, sizeof(cmd_text), "grep %s %s", input_text, filename);
    debug_printf("cmd_text = %s\n",cmd_text);
    
    printf(beGRN("\n------------------- result -------------------\n"));
    call_pipe(cmd_text);

    free(input_text);
    
    return 0;
}






int func_hook(pid_t pid) {
    struct user_regs_struct regs;
    int syscall = 0;
    //int socketcall;
    int result = 0;

    result = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (result) {
        fprintf(stderr, "%5d: GETREGS failed\n", pid);
        return 1;
    }

    syscall = regs.orig_rax;
    fprintf(stderr, "%5d: sys%4s(%3d): XXX\n", pid,
            (regs.rax == -ENOSYS) ? "in" : "out", syscall);

    int log_rip = regs.rip;
    printf(beGRN("rip = %d"),log_rip);

    return 0;
}


int parent_main_tracer(const char *filename, char ** argv, int child_pid) {
    
    int status = 0;
    void * addr = NULL;
    char out_string[COMMAND_LENGTH];
    long original_text = 0;
    long next_text = 0;
    void * next_addr = NULL;
    pid_t child = 0;

    /*  elf header information into global struct.
        ,So after this function call, It can use elf header information. */
    if(read_elfheader(filename) == 0){
        fprintf(stderr,"Error: do not access elf-file");
        exit(1);
    }
    GV_tracee_status.entry_p = tracee_elfheader.e_entry;
    GV_tracee_status.bit = tracee_elfheader.e_ident[4];

    debug_printf(beRED("directry child_bit:%d\n"), GV_tracee_status.bit);


    addr = (void*)GV_tracee_status.entry_p;
    if(addr == NULL){
        fprintf(stderr,"Error: addr is wrong.\n");
        return 1;
    }
    /* out stirngs is initialize  */
    memset( &out_string[0] , 0x00 , sizeof(out_string));



    /* 
     *   same as  int call_trace_rip without routine of getting child process ID.
     */
    /* error check  */
    child = waitpid(-1, &status, WUNTRACED | WCONTINUED);
    debug_printf(beRED("child = %d\n"),child);
    if (child == -1) {
        perror("waitpid");
        return 1;
    }
    make_new_logfile();


    debug_printf(beBLU("-----auto record RIP-----"));
    while(1){

        /* set break point */
        original_text = ps_set_breakpoint_for_addrOfpid(child, addr);

        /* continue and stop routine */   
        ps_continue_stop_by_status(child);

        /* delete breakpint instruction(0xCC) and switch original address */   
        ps_deleteBP_switch_original(child, addr, original_text);

        /* step run */
        ps_stepi(child);
        
        /* get next rip address */
        next_addr = (void*)get_next_rip_address(child);
        debug_printf("next addr = %p\n", next_addr);
        addr = next_addr;


        /*  write down  */
        snprintf(out_string, sizeof(out_string),"%p", addr);
        debug_printf("out_string = %s\n", out_string);
        append_logfile(out_string);

        
        /* get next text */
        next_text = get_next_text(child, next_addr);
        debug_printf("next_text:%lx(hex)\n",convertNum_endian(next_text));
    }

    return 0;
}

int parent_main_tracer_ver2(const char *filename, char ** argv, int child_pid) {
    
    int status = 0;
    void * addr = NULL;
    char out_string[COMMAND_LENGTH];
    memset( &out_string[0] , 0x00 , sizeof(out_string));
    long original_text = 0;
    long next_text = 0;
    void * next_addr = NULL;
    pid_t child = 0;
    char temp_str[OUTPUT_STR_BUF];
    memset(temp_str, 0, OUTPUT_STR_BUF); 
    unsigned long countloop = 0;

    /*  elf header information into global struct.
        ,So after this function call, It can use elf header information. */
    if(read_elfheader(filename) == 0){
        fprintf(stderr,"Error: do not access elf-file");
        exit(1);
    }
    GV_tracee_status.entry_p = tracee_elfheader.e_entry;
    GV_tracee_status.bit = tracee_elfheader.e_ident[GET_ELFFILE_BIT];

    debug_printf(beRED("directry child_bit:%d\n"), GV_tracee_status.bit);


    addr = (void*)GV_tracee_status.entry_p;
    if(addr == NULL){
        fprintf(stderr,"Error: addr is wrong.\n");
        return 1;
    }


    /* 
     *   same as  int call_trace_rip without routine of getting child process ID.
     */
    /* error check  */
    child = waitpid(-1, &status, WUNTRACED | WCONTINUED);
    debug_printf(beRED("child = %d\n"),child);
    if (child == -1) {
        perror("waitpid");
        return 1;
    }
    make_new_logfile();


    /* make buffer */
    char * out_string2 = (char*)calloc(MALLOC_SIZE_BUF_BEFORE_WRITE, sizeof(char)); 
    if(out_string2 == NULL){
        fprintf(stderr,"Error: malloc()");      
        exit(1);
    }

    debug_printf(beBLU("-----auto record RIP-----"));
    while(1){

        /* set break point */
        original_text = ps_set_breakpoint_for_addrOfpid(child, addr);

        /* continue and stop routine */   
        if(ps_continue_stop_by_status_ver2(child) != 0){
            append_logfile_ver2(out_string2);
            free(out_string2);
            printf(beGRN("\nFinish!\n Search: [ %s --check %s ]\n"), GV_tracer_info.tracerfilename, GV_tracer_info.logfilename);
            exit(1);
        }
   

        /* delete breakpint instruction(0xCC) and switch original address */   
        ps_deleteBP_switch_original(child, addr, original_text);



        if( strlen(out_string2) > (MALLOC_SIZE_BUF_BEFORE_WRITE-BUF_THRESHOLD_BEFORE_WRITE)) {
        
            /*  except '\n' at last elements  */
            int i = 1;
            while(out_string2[i]!='\0')
                i++;
            out_string2[i-1] = '\0';

            append_logfile_ver2(out_string2);
            memset(out_string2, 0, MALLOC_SIZE_BUF_BEFORE_WRITE); 

            if ( (countloop%100) == 1)
                printf(beGRN("|"));
        }

        /* step run */
        ps_stepi(child);
        
        /* get next rip address */
        next_addr = (void*)get_next_rip_address(child);
        debug_printf("next addr = %p\n", next_addr);
        addr = next_addr;


        /*  add string  */
        snprintf(temp_str, sizeof(temp_str), "%ld: %p\n", countloop, addr); 
        strncat(out_string2, temp_str, sizeof(temp_str));

        
        /* get next text */
        next_text = get_next_text(child, next_addr);
        debug_printf("next_text:%lx(hex)\n",convertNum_endian(next_text));

        countloop++;
    }

    free(out_string2);
    return 0;
}


int child_main(const char *filename, char ** argv) {

    /* run tracee ps */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    int result = execvp(filename, argv);

    /*  check error */
    if (result) {
        perror(beRED("error execvp"));
        return result;
    }
    printf(beRED("[bug] never reached here.\n"));

    return 0;
}

void call_fork(int argc, char ** argv, char ** envp){
        
    debug_printf(beBLU("-----call_fork()-----"));
    debug_printf(beRED("argv[0]:%s\nargv[1]:%s\nargv[2]:%s\nargv[3]:%s\n"),argv[0],argv[1],argv[2],argv[3]);
    const char * filename = argv[1];

    int pid = fork();
    if (pid) {
        parent_main_tracer_ver2(filename, &argv[1], pid);
    } else {
        debug_printf("child proces ID is %d", getpid()); /* why does not it run? */
        child_main(filename, &argv[1]);
    }
}


void usage(char * cmd) {
    fprintf(stderr, beGRN("Usage: \n"));
    fprintf(stderr, beGRN(" %s --help                : show help\n"), cmd);
    //fprintf(stderr, beGRN(" %s --attach [pid] [addr] : attach\n"), cmd);
    fprintf(stderr, beGRN(" %s --check [log-file]    : check rip\n"), cmd);
    fprintf(stderr, beGRN(" %s --trace [exec-file]   : trace exec\n"), cmd);
}

int main(int argc, char ** argv, char ** envp) {

    strncpy(GV_tracer_info.tracerfilename, argv[0], TRACERFILE_NAME_BUF);
    debug_printf("GV_tracer_info.tracerfilename:%s\n",GV_tracer_info.tracerfilename);

    /* purse argument for option  */
    struct option long_options[] = {
        //{"attach", 0, NULL, 'a'},
        {"check", 0, NULL, 'c'},
        {"trace", 0, NULL, 't'},
        {"help", 0, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int option_index = 0;
    char opt = getopt_long(argc, argv, "acth", long_options, &option_index);

    debug_printf(beRED("opt is %d\nargv[0]:%s\nargv[1]:%s\nargv[2]:%s\nargv[3]:%s\n"), opt,argv[0],argv[1],argv[2],argv[3]);

    switch(opt) {
        case 'a':
            call_trace_rip(argc-1, argv+1, envp);
            break;
        case 'c':
            call_check_rip(argc-1, argv+1, envp);
            break;
        case 't':
            call_fork(argc-1, argv+1, envp);
            break;
        case 'h':
            usage(argv[0]);
            break;
        default:
            usage(argv[0]);
            break;
    }
    return 0;
}

