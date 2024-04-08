// system lib
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <elf.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

// user lib
#include <PtraceUtils.h>
#include <logUtils.h>
#include <android/dlext.h>

extern "C" {
#include <pmparser.h>

}
#define MEMORY_SIZE 1024
// so注入所需要的一些核心数据 组成一个数据结构
struct process_inject {
    pid_t pid;
    char lib_path[1024];
    char func_symbols[1024];
    char orig_selinux[1024];
} process_inject = {0, "", "symbols", "Permissive"};

struct hide_struct {
    procmaps_struct *original;
};
size_t lastSize = 0;
void *RemoteMapMemoryAddr;
void *ModuleAddr;

static int get_prot(const procmaps_struct *procstruct) {
    int prot = 0;
    if (procstruct->is_r) {
        prot |= PROT_READ;
    }
    if (procstruct->is_w) {
        prot |= PROT_WRITE;
    }
    if (procstruct->is_x) {
        prot |= PROT_EXEC;
    }
    return prot;
}

bool equals(const char *str1, const char *str2) {
    if (str1 == NULL && str2 == NULL) {
        return true;
    } else {
        if (str1 != NULL && str2 != NULL) {
            return strcmp(str1, str2) == 0;
        } else {
            return false;
        }
    }
}

void *get_munmap_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) munmap);
}

void *get_mprotect_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) mprotect);
}

void *get_memcpy_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) memcpy);
}

void *get_memmove_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) memmove);
}

void *get_syscall_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) syscall);
}


void *get_ftruncate_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) ftruncate);
}

void *get_write_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) write);
}


void *get_close_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) close);
}

void *get_fstat_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) fstat);
}


void *callMmap(void *addr, size_t size, int prot, int flags, int fd, off_t offset, struct pt_regs CurrentRegs) {
    uintptr_t parameters[6];
    parameters[0] = (uintptr_t) addr; // 设置为NULL表示让系统自动选择分配内存的地址
    parameters[1] = size; // 映射内存的大小
    parameters[2] = prot; // 表示映射内存区域 可读|可写|可执行
    parameters[3] = flags; // 建立匿名映射
    parameters[4] = fd; //  若需要映射文件到内存中，则为文件的fd
    parameters[5] = offset; //文件映射偏移量
    // 调用远程进程的mmap函数申请内存
    void *mmapAddr = get_mmap_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) mmapAddr, parameters, 6, &CurrentRegs) == -1) {
        return nullptr;
    }
    // 获取mmap函数执行后的返回值
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callMprotect(void *remoteAddr, size_t size, int prot, struct pt_regs CurrentRegs) {
    uintptr_t parameters[3];
    parameters[0] = (uintptr_t) remoteAddr;
    parameters[1] = size;
    parameters[2] = prot;
    void *mprotectAddr = get_mprotect_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) mprotectAddr, parameters, 3, &CurrentRegs) == -1) {
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}


bool writeRemoteMemory(void *remoteAddr, void *buffer, size_t size) {
    if (lastSize != 0) {
        void *tmpMemory = malloc(size);
        memset(tmpMemory, 0, size);
        if (ptrace_writedata(process_inject.pid, (uint8_t *) remoteAddr, (uint8_t *) tmpMemory, size) == -1) {
            LOGE("writeRemoteMemory ERRO");
            return false;
        }
    }
    if (ptrace_writedata(process_inject.pid, (uint8_t *) remoteAddr, (uint8_t *) buffer, size) == -1) {
        LOGE("writeRemoteMemory ERRO2");
        return false;
    }
    lastSize = size;
    return true;
}

bool callMunmap(void *remoteAddr, size_t size, struct pt_regs CurrentRegs) {
    uintptr_t parameters[2];
    parameters[0] = (uintptr_t) remoteAddr; //申请的内存区域地址头
    parameters[1] = size;
    void *munmapAddr = get_munmap_address(process_inject.pid);
    // 调用远程进程的munmap函数 卸载内存
    if (ptrace_call(process_inject.pid, (uintptr_t) munmapAddr, parameters, 2, &CurrentRegs) == -1) {
        return false;
    }
    return true;
}

int __open_real(const char *, int, ...)

__RENAME(open);

void *get_open_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) __open_real);
}

//int open(const char* const __pass_object_size pathname, int flags)
int callOpen(const char *pathname, int flags, struct pt_regs CurrentRegs) {
    void *bufAddr = callMmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, CurrentRegs);
    // LOGD("OpenTmp:%p",bufAddr);

    char str[PATH_MAX];
    snprintf(str, PATH_MAX, "%s", pathname);

    writeRemoteMemory(bufAddr, (void *) str, PAGE_SIZE);
    uintptr_t parameters[2];
    parameters[0] = (uintptr_t) bufAddr;
    parameters[1] = flags;
    void *addr = get_open_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) addr, parameters, 3, &CurrentRegs) == -1) {
        callMunmap(bufAddr, PAGE_SIZE, CurrentRegs);
        LOGE("callOpen err");
        return -1;
    }
    callMunmap(bufAddr, PAGE_SIZE, CurrentRegs);
    return (int) ptrace_getret(&CurrentRegs);
}

void *callDlclose(void *addr, struct pt_regs CurrentRegs) {
    uintptr_t parameters[1];
    parameters[0] = (uintptr_t) addr;
    void *ftraddr = get_dlclose_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) ftraddr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callDlclose erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callMemcpy(void *remoteDst, void *remoteSrc, size_t srcSize, struct pt_regs CurrentRegs) {
    uintptr_t parameters[3];
    parameters[0] = (uintptr_t) remoteDst;
    parameters[1] = (uintptr_t) remoteSrc;
    parameters[2] = srcSize;
    void *memcpyAddr = get_memcpy_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) memcpyAddr, parameters, 3, &CurrentRegs) == -1) {
        LOGE("callMemcpy erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callMemmove(void *remoteDst, void *remoteSrc, size_t srcSize, struct pt_regs CurrentRegs) {
    uintptr_t parameters[3];
    parameters[0] = (uintptr_t) remoteDst;
    parameters[1] = (uintptr_t) remoteSrc;
    parameters[2] = srcSize;
    void *moveAddr = get_memmove_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) moveAddr, parameters, 3, &CurrentRegs) == -1) {
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callSyscall(void *parameters, int parameterSize, struct pt_regs CurrentRegs) {
    void *syscallAddr = get_syscall_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) syscallAddr, (uintptr_t *) parameters, parameterSize, &CurrentRegs) == -1) {
        LOGE("callSyscall erro:%d", errno);

        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callFtruncate(int fd, size_t size, struct pt_regs CurrentRegs) {
    uintptr_t parameters[2];
    parameters[0] = fd;
    parameters[1] = size;
    void *ftruncateAddr = get_ftruncate_address(process_inject.pid);
    if (ptrace_call(process_inject.pid, (uintptr_t) ftruncateAddr, parameters, 2, &CurrentRegs) == -1) {
        LOGE("callFtruncate erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callDlOpen(void *remotePathAddr, int mode, struct pt_regs CurrentRegs) {
    void *dlopenAddr = get_dlopen_address(process_inject.pid);
    uintptr_t parameters[2];
    parameters[0] = (uintptr_t) remotePathAddr;
    parameters[1] = mode;
    if (ptrace_call(process_inject.pid, (uintptr_t) dlopenAddr, parameters, 2, &CurrentRegs) == -1) {
        LOGE("callDlOpen erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callAndroidDopenExt(void *__filename, int __flags, const android_dlextinfo *__info, struct pt_regs CurrentRegs) {
    void *dlopenAddr = get_android_dlopen_ext_address(process_inject.pid);
    uintptr_t parameters[3];
    parameters[0] = (uintptr_t) __filename;
    parameters[1] = __flags;
    parameters[2] = (uintptr_t) __info;
    if (ptrace_call(process_inject.pid, (uintptr_t) dlopenAddr, parameters, 3, &CurrentRegs) == -1) {
        LOGE("callAndroidDopenExt erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}
//android_dlopen_ext(const char* __filename, int __flags, const android_dlextinfo* __info)

void *callWrite(int fd, void *buffer, size_t size, struct pt_regs CurrentRegs) {
    void *writeAddr = get_write_address(process_inject.pid);
    uintptr_t parameters[3];
    parameters[0] = fd;
    parameters[1] = (uintptr_t) buffer;
    parameters[2] = size;
    if (ptrace_call(process_inject.pid, (uintptr_t) writeAddr, parameters, 3, &CurrentRegs) == -1) {
        LOGE("callWrite erro:%d", errno);
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *callClose(int fd, struct pt_regs CurrentRegs) {
    void *closeAddr = get_close_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = fd;
    if (ptrace_call(process_inject.pid, (uintptr_t) closeAddr, parameters, 1, &CurrentRegs) == -1) {
        return NULL;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}


void *get_fopen_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) fopen);
}

FILE *callFopen(char *__path, char *__mode, pt_regs CurrentRegs) {
    void *Addr = get_fopen_address(process_inject.pid);
    uintptr_t parameters[2];
    parameters[0] = (uintptr_t) __path;
    parameters[1] = (uintptr_t) __mode;

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 2, &CurrentRegs) == -1) {
        LOGE("callFopen erro");
        return 0;
    }
    return (FILE *) ptrace_getret(&CurrentRegs);
}

void *get_fseek_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) fseek);
}

//int fseek(FILE* __fp, long __offset, int __whence);
int callFseek(FILE *__fp, long __offset, int __whence, pt_regs CurrentRegs) {
    void *Addr = get_fseek_address(process_inject.pid);
    uintptr_t parameters[3];
    parameters[0] = (uintptr_t) __fp;
    parameters[1] = __offset;
    parameters[2] = __whence;
    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 3, &CurrentRegs) == -1) {
        LOGE("callFseek erro");
        return 0;
    }
    return (int) ptrace_getret(&CurrentRegs);
}

void *get_ftell_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) ftell);
}

long callftell(void *__fp, pt_regs CurrentRegs) {
    void *Addr = get_ftell_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = (uintptr_t) __fp;

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callftell erro");

        return 0;
    }
    return (long) ptrace_getret(&CurrentRegs);
}

void *get_malloc_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) malloc);
}

void *callMalloc(size_t __byte_count, pt_regs CurrentRegs) {
    void *Addr = get_malloc_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = __byte_count;

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callMalloc erro");

        return 0;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *get_rewind_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) rewind);
}

void *callRewind(FILE *__fp, pt_regs CurrentRegs) {
    void *Addr = get_rewind_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = reinterpret_cast<uintptr_t>(__fp);

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callRewind erro");

        return 0;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *get_fread_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) fread);
}

void *callFread(void *const buf, size_t size, size_t count, __sFILE *stream, pt_regs CurrentRegs) {
    void *Addr = get_fread_address(process_inject.pid);
    uintptr_t parameters[4];
    parameters[0] = (uintptr_t) buf;
    parameters[1] = size;
    parameters[2] = count;
    parameters[3] = reinterpret_cast<uintptr_t>(stream);

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 4, &CurrentRegs) == -1) {
        LOGE("callFread erro");

        return 0;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}


void *get_free_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) free);
}

void *callFree(void *__ptr, pt_regs CurrentRegs) {
    void *Addr = get_free_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = reinterpret_cast<uintptr_t>(__ptr);

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callFree erro");

        return 0;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

void *get_fclose_address(pid_t pid) {
    return get_remote_func_addr(pid, process_libs.libc_path, (void *) fclose);
}

void *callFclose(FILE *__fp, pt_regs CurrentRegs) {
    void *Addr = get_fclose_address(process_inject.pid);
    uintptr_t parameters[1];
    parameters[0] = reinterpret_cast<uintptr_t>(__fp);

    if (ptrace_call(process_inject.pid, (uintptr_t) Addr, parameters, 1, &CurrentRegs) == -1) {
        LOGE("callFclose erro");
        return 0;
    }
    return (void *) ptrace_getret(&CurrentRegs);
}

int shm_open_anon(struct pt_regs CurrentRegs) {
    void *mem = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, -1, 0, CurrentRegs);
    char str[PATH_MAX];
    snprintf(str, PATH_MAX, "test");
    writeRemoteMemory(mem, (void *) str, PAGE_SIZE);
    uintptr_t parameters[3];
    parameters[0] = __NR_memfd_create;
    parameters[1] = (uintptr_t) mem;//"shm_anon";
    parameters[2] = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    int fd = (uintptr_t) callSyscall(parameters, 3, CurrentRegs);
    LOGE("create:%p fd:%d", mem, fd);
    return fd;
}


bool hideLibraryMemory(const char *lib, void *memoryAddr, struct pt_regs CurrentRegs) {
    procmaps_iterator *maps = pmparser_parse(process_inject.pid);
    if (maps == nullptr) {
        return false;
    }
    //存储指定so的内存信息
    hide_struct *data = nullptr;
    //指定so的内存区域数量
    size_t dataCount = 0;
    //遍历内存maps
    procmaps_struct *tmpMaps;
    while ((tmpMaps = pmparser_next(maps)) != nullptr) {
        //判断是否是指定so的内存区域
        if (!equals(lib, tmpMaps->pathname)) {
            continue;
        }
        printf("%p-%p %s %ld %s\n", tmpMaps->addr_start, tmpMaps->addr_end, tmpMaps->perm, tmpMaps->offset, tmpMaps->pathname);
        //判断内存是否为空,不为空则重新调整内存大小
        if (data) {
            data = (hide_struct *) realloc(data, sizeof(hide_struct) * (dataCount + 1));
        } else {
            //申请内存
            data = (hide_struct *) malloc(sizeof(hide_struct));
        }
        //记录maps内存区域信息
        data[dataCount].original = tmpMaps;
        //计次+1
        dataCount += 1;
    }
    printf("[+]隐藏Library开始\n");
    for (int i = 0; i < dataCount; ++i) {

        auto start = data[i].original->addr_start;
        auto end = data[i].original->addr_end;
        auto length = (uintptr_t) end - (uintptr_t) start;
        //内存区域权限
        int prot = get_prot(data[i].original);
        //申请一片内存
        void *backupAddr = callMmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0, CurrentRegs);

        if (backupAddr == nullptr) {
            printf("[-]hideLibraryMemory: mmap failed\n");
            return false;
        }
        printf("[+]hideLibraryMemoryMmapaddr:%p\n", backupAddr);

        //原内存区域:是否有读属性,没有给他加上
        if (!data[i].original->is_r) {
            if ((uintptr_t) callMprotect(start, length, PROT_READ, CurrentRegs) == -1) {
                printf("[-]hideLibraryMemory: mprotect failed\n");
                return false;
            }
        }
        //将原内存区域复制到新内存区域
        callMemcpy(backupAddr, start, length, CurrentRegs);
        //将原内存区域卸载掉
        if ((uintptr_t) callMunmap(start, length, CurrentRegs) == -1) {
            printf("[-]hideLibraryMemory: munmap failed\n");
            return false;
        }
        const char *str = "jit-zygote-cache";
        writeRemoteMemory(memoryAddr, (void *) str, MEMORY_SIZE);
        uintptr_t parameters[3];
        parameters[0] = __NR_memfd_create;
        parameters[1] = (uintptr_t) memoryAddr;
        parameters[2] = MFD_CLOEXEC | MFD_ALLOW_SEALING;
        uintptr_t fd = (uintptr_t) callSyscall(parameters, 3, CurrentRegs);

        //int fd  = callOpen("/system/bin/app_process64", O_RDONLY, CurrentRegs);
        //修改fd的文件大小为指定大小
        callFtruncate(fd, length, CurrentRegs);
        //将内存写入到fd文件中
        callWrite(fd, data[i].original->addr_start, length, CurrentRegs);
        //在原内存区域上新建一片内存,覆盖掉
        //callMmap(start, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, fd, 0, CurrentRegs);
        callMmap(start, length, prot, MAP_PRIVATE, fd, 0, CurrentRegs);

        //关闭fd文件句柄
        callClose(fd, CurrentRegs);

        //callMmap(start, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, CurrentRegs);//匿名

        //给原内存区域加上写权限
        callMprotect(start, length, prot | PROT_WRITE, CurrentRegs);
        //拷贝新内存区域到原内存区域
        callMemcpy(start, backupAddr, length, CurrentRegs);
        if (!data[i].original->is_w) {
            //还原原内存区域权限
            callMprotect(start, length, prot, CurrentRegs);
        }
        //卸载新内存区域
        callMunmap(backupAddr, length, CurrentRegs);


        printf("%p-%p %s hidden success\n", data[i].original->addr_start, data[i].original->addr_end, data[i].original->perm);
//        printf("%p-%p %s hidden success\n",pmparser_next(maps)->addr_start, pmparser_next(maps)->addr_end, pmparser_next(maps)->perm);

    }
    //释放内存
    if (data) {
        free(data);
    }
    //释放maps数据
    pmparser_free(maps);

    return true;
}


void dlblob(char *path, struct pt_regs CurrentRegs) {
    LOGE("pid:%d path:%s", process_inject.pid, path);
    {
        //将路径写进去内存
        void *ptahAddr = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, CurrentRegs);
        char str[PATH_MAX];
        snprintf(str, PATH_MAX, "/jit-cache");
        writeRemoteMemory(ptahAddr, (void *) str, PAGE_SIZE);
        int fd = callOpen(path, O_RDWR, CurrentRegs);
        android_dlextinfo info{
                .flags = ANDROID_DLEXT_USE_LIBRARY_FD,
                .library_fd = fd,
        };
        LOGE("ptahAddr:%p fd:%d", ptahAddr, fd);
        void *infoAddr = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, CurrentRegs);
        writeRemoteMemory(infoAddr, &info, PAGE_SIZE);
        callAndroidDopenExt(ptahAddr, RTLD_LAZY, reinterpret_cast<const android_dlextinfo *>(infoAddr), CurrentRegs);
        callMunmap(ptahAddr, PAGE_SIZE, CurrentRegs);
        callClose(fd, CurrentRegs);
        callMunmap(infoAddr, PAGE_SIZE, CurrentRegs);

        void *MapMemory = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, CurrentRegs);
        //隐藏maps
        if (hideLibraryMemory(path, MapMemory, CurrentRegs)) {
            printf("[+]hideLibraryMemory Success\n");
        } else {
            printf("[-]hideLibraryMemory failed\n");
        }
        callMunmap(MapMemory, PAGE_SIZE, CurrentRegs);
        return;
    }


    int fake_fd = open(path, O_RDONLY);
    struct stat buf;
    fstat(fake_fd, &buf);
    char text[buf.st_size];
    read(fake_fd, text, buf.st_size);
    close(fake_fd);
    LOGE("fake_fd:%d len:%lx", fake_fd, buf.st_size);
    //要伪装的文件 将路径写进去内存
    int fd = callOpen("/data/local/tmp/libMao.so", O_RDWR, CurrentRegs);
    //int fd = shm_open_anon(CurrentRegs);
    LOGE("blob:%s fd:%d len:%lx", text, fd, buf.st_size);

    //修改fd大小
    callFtruncate(fd, buf.st_size, CurrentRegs);
    //申请一片内存
    void *mem = callMmap(0, buf.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0, CurrentRegs);
    //将加载的so拷贝到申请的内存里
    writeRemoteMemory(mem, (void *) text, buf.st_size);

    //将路径放入内存
//        void *open_tmp = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0, CurrentRegs);
//        writeRemoteMemory(open_tmp, (void *) path, PAGE_SIZE);
//        int fd = callOpen(open_tmp, O_RDONLY, CurrentRegs);
//        LOGE("callOpenFd:%d", fd);
//        void *mem = callMmap(0, PAGE_SIZE * 10, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, fd, 0, CurrentRegs);

    //获取创建的fd
    char BUF[PATH_MAX];
    snprintf(BUF, PATH_MAX, "/proc/self/fd/%d", fd);
    LOGE("BUF:%s mem:%p", BUF, mem);
    //加载fd 将fd路径写进去远程内存
    void *bufAddr = callMmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0, CurrentRegs);
    writeRemoteMemory(bufAddr, (void *) BUF, PATH_MAX);
    void *so = callDlOpen(bufAddr, RTLD_LAZY, CurrentRegs);
    if (so == nullptr) {
        LOGE("[-]dlopen %s failed\n", path);
    } else {
        LOGE("[+]dlopen:%p mem:%p \n", so, mem);
    }
    callMunmap(bufAddr, PAGE_SIZE, CurrentRegs);
    callMunmap(mem, buf.st_size, CurrentRegs);
    //  callClose(fd, CurrentRegs);
}

// TODO: 更优雅的处理SELinux问题
// TODO: 适配armeabi-v7a和x86_64

/**
 * @brief 通过远程直接调用dlopen/dlsym的方法ptrace注入so模块到远程进程中
 *
 * @param pid pid表示远程进程的ID
 * @param LibPath LibPath为被远程注入的so模块路径
 * @param FunctionName FunctionName为远程注入的模块后调用的函数
 * @param parameter FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中）
 * @param NumParameter NumParameter为参数的个数
 * @return int 返回0表示注入成功，返回-1表示失败
 */
int inject_remote_process(pid_t pid, char *LibPath, char *FunctionName, char *FlagSELinux) {
    int iRet = -1;
    uintptr_t parameters[6];
    // attach到目标进程
    if (ptrace_attach(pid) != 0) {
        return iRet;
    }

    /**
     * @brief 开始主要步骤
     */
    do {
        printf("[+] inject_remote_process\n");
        // CurrentRegs 当前寄存器
        // OriginalRegs 保存注入前寄存器
        struct pt_regs CurrentRegs, OriginalRegs;
        if (ptrace_getregs(pid, &CurrentRegs) != 0) {
            break;
        }
        // 保存原始寄存器
        memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));
        //RemoteMapMemoryAddr = callMmap(nullptr, 0x5000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0, CurrentRegs);

        RemoteMapMemoryAddr = callMmap(nullptr, 0x5000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0, CurrentRegs);
        printf("[+] Remote Process Map Memory Addr:0x%lx\n", (uintptr_t) RemoteMapMemoryAddr);
        if ((uintptr_t) RemoteMapMemoryAddr < 0xff) {
            printf("[-] error Memory Addr:0x%lx\n", (uintptr_t) RemoteMapMemoryAddr);
        }
        // 分别获取dlopen、dlsym、dlclose等函数的地址
        void *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
        dlopen_addr = get_dlopen_address(pid);
        dlsym_addr = get_dlsym_address(pid);
        dlclose_addr = get_dlclose_address(pid);
        dlerror_addr = get_dlerror_address(pid);

        // 打印一下
        printf("[+] Get imports: dlopen: %lx, dlsym: %lx, dlclose: %lx, dlerror: %lx\n", reinterpret_cast<uintptr_t>(dlopen_addr), reinterpret_cast<uintptr_t>(dlsym_addr),
               reinterpret_cast<uintptr_t>(dlclose_addr), reinterpret_cast<uintptr_t>(dlerror_addr));

        // 打印注入so的路径
        printf("[+] LibPath = %s\n", LibPath);

        // 将要加载的so库路径写入到远程进程内存空间中
        if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr, (uint8_t *) LibPath, strlen(LibPath) + 1) == -1) {
            printf("[-] Write LibPath:%s to RemoteProcess error\n", LibPath);
            break;
        }
        // 设置dlopen的参数,返回值为模块加载的地址
        // void *dlopen(const char *filename, int flag);
        parameters[0] = (uintptr_t) RemoteMapMemoryAddr; // 写入的libPath
        parameters[1] = RTLD_NOW | RTLD_GLOBAL; // dlopen的标识

        // 执行dlopen 载入so
        if (ptrace_call(pid, (uintptr_t) dlopen_addr, parameters, 2, &CurrentRegs) == -1) {
            printf("[+] Call Remote dlopen Func Failed\n");
            break;
        }

        //隐藏maps
//        if (hideLibraryMemory(LibPath, RemoteMapMemoryAddr, CurrentRegs)) {
//            printf("[+]hideLibraryMemory Success\n");
//        } else {
//            printf("[-]hideLibraryMemory failed\n");
//        }

        // RemoteModuleAddr为远程进程加载注入模块的地址
        void *RemoteModuleAddr = (void *) ptrace_getret(&CurrentRegs);
        ModuleAddr = RemoteModuleAddr;
        printf("[+] ptrace_call dlopen success, Remote Process load module Addr:0x%lx\n", (long) RemoteModuleAddr);
        // dlopen 错误
        if ((long) RemoteModuleAddr == 0x0) {
            printf("[-] dlopen error\n");
            if (ptrace_call(pid, (uintptr_t) dlerror_addr, parameters, 0, &CurrentRegs) == -1) {
                printf("[-] Call Remote dlerror Func Failed\n");
                break;
            }
            char *Error = (char *) ptrace_getret(&CurrentRegs);
            char LocalErrorInfo[1024] = {0};
            ptrace_readdata(pid, (uint8_t *) Error, (uint8_t *) LocalErrorInfo, 1024);
            printf("[-] dlopen error:%s\n", LocalErrorInfo);
            break;
        }


        // 判断是否传入symbols
        if (strcmp(FunctionName, "symbols") != 0) {
            printf("[+] func symbols is %s\n", FunctionName);
            // 传入了函数的symbols
            printf("[+] Have func !!\n");
            // 将so库中需要调用的函数名称写入到远程进程内存空间中
            if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2, (uint8_t *) FunctionName, strlen(FunctionName) + 1) == -1) {
                printf("[-] Write FunctionName:%s to RemoteProcess error\n", FunctionName);
                break;
            }
            // 设置dlsym的参数，返回值为远程进程内函数的地址 调用XXX功能
            // void *dlsym(void *handle, const char *symbol);
            parameters[0] = (uintptr_t) RemoteModuleAddr;
            parameters[1] = (uintptr_t)((uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2);
            //调用dlsym
            if (ptrace_call(pid, (uintptr_t) dlsym_addr, parameters, 2, &CurrentRegs) == -1) {
                printf("[-] Call Remote dlsym Func Failed\n");
                break;
            }
            // RemoteModuleFuncAddr为远程进程空间内获取的函数地址
            void *RemoteModuleFuncAddr = (void *) ptrace_getret(&CurrentRegs);
            printf("[+] ptrace_call dlsym success, Remote Process ModuleFunc Addr:0x%lx\n", (uintptr_t) RemoteModuleFuncAddr);

            // 调用远程进程到某功能 不支持参数传递 ！！
            if (ptrace_call(pid, (uintptr_t) RemoteModuleFuncAddr, parameters, 0, &CurrentRegs) == -1) {
                printf("[-] Call Remote injected Func Failed\n");
                break;
            }
        } else {
            // 没有传入函数的symbols
            printf("[+] No func !!\n");
        }

        if (ptrace_setregs(pid, &OriginalRegs) == -1) {
            printf("[-] Recover reges failed\n");
            break;
        }

        printf("[+] Recover Regs Success\n");
        ptrace_getregs(pid, &CurrentRegs);
        if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0) {
            printf("[-] Set Regs Error\n");
        }
        iRet = 0;
    } while (false);


    // 解除attach
    ptrace_detach(pid);

    // 如果原SELinux状态为严格 则恢复状态
    if (strcmp(FlagSELinux, "Enforcing") == 0) {
        if (set_selinux_state(1)) {
            printf("[+] SELinux has been rec\n");
        }
    }

    return iRet;
}

int inject_remote(pid_t pid, char *LibPath, char *FlagSELinux) {
    int iRet = -1;
    // attach到目标进程
    if (ptrace_attach(pid) != 0) {
        return iRet;
    }

    do {
        struct pt_regs CurrentRegs, OriginalRegs;
        if (ptrace_getregs(pid, &CurrentRegs) != 0) {
            break;
        }
        // 保存原始寄存器
        memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));

//        dlblob(LibPath, CurrentRegs);
        printf("[+] inject_remote_so:%p\n", ModuleAddr);
        dlblob(LibPath, CurrentRegs);
//        if (callDlclose(ModuleAddr, CurrentRegs)) {
//            printf("[-] CallRemote dlclose Func Failed\n");
//            break;
//        } else {
//            printf("[+] Call Remote dlso Func Done\n");
//        }

        if (ptrace_setregs(pid, &OriginalRegs) == -1) {
            printf("[-] Recover reges failed\n");
            break;
        }
        printf("[+] Recover Regs Success\n");
        ptrace_getregs(pid, &CurrentRegs);
        if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0) {
            printf("[-] Set Regs Error\n");
        }
        iRet = 0;
    } while (false);


    // 解除attach
    ptrace_detach(pid);

    // 如果原SELinux状态为严格 则恢复状态
    if (strcmp(FlagSELinux, "Enforcing") == 0) {
        if (set_selinux_state(1)) {
            printf("[+] SELinux has been rec\n");
        }
    }

    return iRet;
}

/**
 * @brief 参数处理
 * -p 目标进程pid
 * -n 目标App包名
 * -f 是否开启App
 * -so 注入的so路径
 * -func 指定启用so中的某功能
 *
 * @param argc
 * @param argv
 */
void handle_parameter(int argc, char *argv[]) {
    pid_t pid = 0;
    int index = 0;
    char *pkg_name = NULL;
    char *lib_path = NULL;
    char *func_symbols = NULL;
    bool start_app_flag = false;


    while (index < argc) { // 循环判断参数
        if (strcmp("-f", argv[index]) == 0) { // 是否强制开启App
            start_app_flag = true; // 强制开启App
        }

        if (strcmp("-p", argv[index]) == 0) { // 判断是否传入pid参数
            if (index + 1 >= argc) {
                printf("[-] Missing parameter -p\n");
                exit(-1);
            }
            index++;
            pid = atoi(argv[index]); // pid
        }

        if (strcmp("-n", argv[index]) == 0) { // 判断是否传入App包名
            if (index + 1 >= argc) {
                printf("[-] Missing parameter -n\n");
                exit(-1);
            }
            index++;
            pkg_name = argv[index]; // 包名

            if (start_app_flag) { // 如果强制开启App参数开启
                start_app(pkg_name); // 启动App
                // sleep(3); //延迟一下
                usleep(1000 * 3500); //延迟一下
            }
        }


        if (strcmp("-so", argv[index]) == 0) { // 判断是否传入so路径
            if (index + 1 >= argc) {
                printf("[-] Missing parameter -so\n");
                exit(-1);
            }
            index++;
            lib_path = argv[index]; // so路径
        }

        if (strcmp("-symbols", argv[index]) == 0) { // 判断是否传入so路径
            if (index + 1 >= argc) {
                printf("[-] Missing parameter -func\n");
                exit(-1);
            }
            index++;
            func_symbols = argv[index]; // so中的某功能
        }
        index++;
    }

    // 开始参数处理

    // 如果有包名 则通过包名获取pid
    if (pkg_name != NULL) {
        printf("[+] pkg_name is %s\n", pkg_name);
        if (get_pid_by_name(&pid, pkg_name)) {
            printf("[+] get_pid_by_name pid is %d\n", pid);
        }
    }

    // 处理pid
    if (pid == 0) {
        printf("[-] not found target & get_pid_by_name pid faild !\n");
        exit(0);
    } else {
        process_inject.pid = pid; // pid传给inject数据结构
    }

    // 处理so路径
    if (lib_path != NULL) { // 如果有so路径
        printf("[+] lib_path is %s\n", lib_path);
        strcpy(process_inject.lib_path, strdup(lib_path)); // 传递so路径到inject数据结构
    }

    // 处理功能名称
    if (func_symbols != NULL) { // 如果有功能名称
        printf("[+] symbols is %s\n", func_symbols);
        strcpy(process_inject.func_symbols, strdup(func_symbols)); // 传递功能名称到inject数据结构
    }
}

pid_t get_pid_by_name(char *task_name) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];
    struct dirent *entry;
    if (task_name == NULL)
        return -1;
    dir = opendir("/proc");
    if (dir == NULL)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(task_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

/**
 * @brief 初始化Inject
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int init_inject(int argc, char *argv[]) {
    // 参数处理
    handle_parameter(argc, argv);

    printf("[+] handle_parameter is OK\n");

    // SELinux处理
    if (process_selinux.enforce == 1) { // 为严格模式
        printf("[-] SELinux is Enforcing\n");
        strcpy(process_inject.orig_selinux, strdup("Enforcing"));
        if (set_selinux_state(0)) {
            printf("[+] Selinux has been changed to Permissive\n");
        }
    } else { // 已经为宽容模式 或者 关闭状态
        printf("[+] SELinux is Permissive or Disabled\n");
        strcpy(process_inject.orig_selinux, strdup("Permissive"));// 设置flag
    }
    // process_inject.pid = get_pid_by_name("/system/bin/surfaceflinger");


     return inject_remote_process(process_inject.pid, process_inject.lib_path, process_inject.func_symbols, process_inject.orig_selinux);
  //  return inject_remote(process_inject.pid, process_inject.lib_path, process_inject.orig_selinux);
}