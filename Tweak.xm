// See http://iphonedevwiki.net/index.php/Logos

#import <Foundation/Foundation.h>
#include <substrate.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>

#define slog(fmt, ...) NSLog(@"antiPtrace: " fmt, ##__VA_ARGS__)


extern "C" int isatty(int code);
extern "C" void exit(int code);
extern "C" int ioctl(int, unsigned long, ...);

extern "C" int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);
extern "C" void* dlsym(void* __handle, const char* __symbol);
extern "C" int sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize);
extern "C" int syscall(int, ...);
extern "C" pid_t getppid(void);


static int (*origin_isatty)(int code);
static void (*origin_exit)(int code);
static int (*origin_ioctl)(int code,unsigned long code2,...);
static int (*origin_ptrace)(int _request, pid_t _pid, caddr_t _addr, int _data);
static void* (*origin_dlsym)(void* __handle, const char* __symbol);
static int (*origin_sysctl)(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize);
static int (*origin_syscall)(int code, va_list args);
static pid_t (*origin_getppid)(void);


int new_isatty(int code) {
    
    NSLog(@"Leocontent tweak : isatty(ptrace)");
    
    return 0;
}

void new_exit(int code) {
    
    NSLog(@"hook exit to nop");
}

int my_ptrace(int _request, pid_t _pid, caddr_t _addr, int _data){
    
    if(_request != 31){
        return origin_ptrace(_request,_pid,_addr,_data);
    }
    
    NSLog(@"Leocontent tweak : [AntiAntiDebug] - ptrace request is PT_DENY_ATTACH");
    
    return 0;
}

void* my_dlsym(void* __handle, const char* __symbol){

    if(strcmp(__symbol, "ptrace") != 0){
        return origin_dlsym(__handle, __symbol);
    }
    NSLog(@"Leocontent tweak : [AntiAntiDebug] - dlsym get ptrace symbol");
    
    return (void*)my_ptrace;
}

typedef struct kinfo_proc _kinfo_proc;

// 修改不稳定？
int my_sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize){
   if(namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info && infosize && ((int)*infosize == sizeof(_kinfo_proc))){
        
        return -1;
        /*
        if(name[3] != getpid()){
            name[3] = 1;
        }

        for(int i = 0; i < namelen; i++){
            slog(@"name[%d] = %d", i, name[i]);
        }
        slog(@"info = %p, infosize = %d", info, (int)*infosize);
        // print sizeof(_kinfo_proc)
        slog(@"sizeof(_kinfo_proc) = %zd", sizeof(_kinfo_proc));

        int ret = origin_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
        struct kinfo_proc *info_ptr = (struct kinfo_proc *)info;

        slog(@"kp_proc.p_flag = %d", info_ptr->kp_proc.p_flag);

        if(info_ptr && (info_ptr->kp_proc.p_flag & P_TRACED) != 0){
            slog(@"[AntiAntiDebug] - sysctl query trace status.");
            info_ptr->kp_proc.p_flag &= ~P_TRACED;
            if((info_ptr->kp_proc.p_flag & P_TRACED) == 0){
                slog(@"trace status reomve success!");
            }
        }
        
        return ret;
        */
    }
    return origin_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
}

int my_syscall(int code, va_list args){

    int request;
    va_list newArgs;
    va_copy(newArgs, args);
    if(code == 26){
#ifdef __LP64__
        __asm__(
                "ldr %w[result], [fp, #0x10]\n"
                : [result] "=r" (request)
                :
                :
                );
#else
        request = va_arg(args, int);
#endif
        if(request == 31){
            NSLog(@"Leocontent tweak :[AntiAntiDebug] - syscall call ptrace, and request is PT_DENY_ATTACH");
            return 0;
        }
    }
    return origin_syscall(code, newArgs);
}

int new_ioctl(int code,unsigned long code2,...) {
    NSLog(@"ioctl, code : %d, (check Debugging?)",code);
    return 1;
}

pid_t new_getppid(void){
    slog(@"[AntiAntiDebug] - getppid called, return 1");
    return 1;
}


void* search_bytes64(void* start, size_t size, const uint8_t* pattern, size_t pattern_size) {
    uint8_t *sta = (uint8_t*) start;
    for (size_t i = 0; i <= size - pattern_size; i++) {
        if (memcmp(sta + i, pattern, pattern_size) == 0) {
            return (void*)(sta + i);
        }
    }
    return NULL;
}


void getTextSectionInfo(const struct mach_header *base, uint64_t *textStart, uint64_t *textSize) {
    if (!base || !textStart || !textSize) {
        return;
    }
    
    const struct load_command *loadCommand = (struct load_command *)((uintptr_t)base + sizeof(struct mach_header_64));
    
    for (uint32_t i = 0; i < base->ncmds; i++) {
        if (loadCommand->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segmentCommand = (struct segment_command_64 *)loadCommand;
            
            if (strcmp(segmentCommand->segname, "__TEXT") == 0) {
                const struct section_64 *section = (struct section_64 *)((uintptr_t)segmentCommand + sizeof(struct segment_command_64));
                
                for (uint32_t j = 0; j < segmentCommand->nsects; j++) {
                    if (strcmp(section->sectname, "__text") == 0) {
                        *textStart = section->addr;
                        *textSize = section->size;
                        return;
                    }
                    section = (struct section_64 *)((uintptr_t)section + sizeof(struct section_64));
                }
            }
        }
        loadCommand = (struct load_command *)((uintptr_t)loadCommand + loadCommand->cmdsize);
    }
}

/*
 搜索可执行文件下的__TEXT__.__text__端下的 'movz x16, #0x1a, svc  #0x80'，将其替换为nop
 */
void patchSVC(){

    NSString *binaryFilepath = [[NSBundle mainBundle] executablePath];
    NSString *executeName = [binaryFilepath lastPathComponent];
    // MSImageRef image = MSGetImageByName([binaryFilepath UTF8String]);
    // const MSImageHeader *base = MSImageAddress(image); // rootless找不到MSImageAddress这个符号，报错：_dyld_missing_symbol_abort()

    NSLog(@"executeName : %@", executeName);

    struct mach_header* executeHeader = NULL;
    int64_t executeSlide = 0;
    for(int i = 0; i < _dyld_image_count(); i++) {
        const char *image_name = _dyld_get_image_name(i);
        NSString *image_name_str = [@(image_name) lastPathComponent];
        
        if ([image_name_str isEqualToString:executeName]) {
            NSLog(@"image_name_str1 : %@", image_name_str);
            executeHeader = (struct mach_header*)_dyld_get_image_header(i);
            executeSlide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    if (!executeHeader) {
        NSLog(@"this is impossible!");
        return;
    }
    
    uint64_t textStart = 0;
    uint64_t textSize = 0;
    getTextSectionInfo(executeHeader, &textStart, &textSize);
    
    textStart += executeSlide;

    /*
    movz x16, #0x1a
    svc  #0x80
     */
    uint8_t pattern[] = {0x50, 0x03, 0x80, 0xD2, 0x01, 0x10, 0x00, 0xD4};
    size_t pattern_size = sizeof(pattern);
    void* n2p2 = search_bytes64((void *)textStart, (size_t)textSize, pattern, pattern_size);
    if(n2p2) {
        NSLog(@"svc ptrace(DENY_ATTACH) called 26!!!");
    }else {
        return;
    }
    
    const uint8_t hack[] = {
        0x1f, 0x20, 0x03, 0xd5,
    };
    
    MSHookMemory((void*)n2p2, hack, sizeof(hack));
}


%ctor
{
    slog(@"antiPtrace tweak loaded");

    patchSVC();
    
    MSHookFunction((void*)&isatty,(void*)&new_isatty,(void**)&origin_isatty);
    MSHookFunction((void*)&exit,(void*)&new_exit,(void**)&origin_exit);
    MSHookFunction((void*)&ioctl,(void*)&new_ioctl,(void**)&origin_ioctl);
    

    MSHookFunction((void*)&ptrace,(void*)&my_ptrace,(void**)&origin_ptrace);
    MSHookFunction((void*)&dlsym,(void*)&my_dlsym,(void**)&origin_dlsym);
    MSHookFunction((void*)&sysctl,(void*)&my_sysctl,(void**)&origin_sysctl);
    MSHookFunction((void*)&syscall,(void*)&my_syscall,(void**)&origin_syscall);
    MSHookFunction((void*)&getppid,(void*)&new_getppid,(void**)&origin_getppid);
}
