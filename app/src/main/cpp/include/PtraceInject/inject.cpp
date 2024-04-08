// user lib
#include <PtraceInject.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<cstdio>
#include<fcntl.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<dirent.h>
#include<cstring>

char paths[1000], patht[1000], temp_paths[1000], temp_patht[1000];

void Copy(char *spathname, char *tpathname) {
    int sfd, tfd;
    struct stat s{}, t;
    char c;
    sfd = open(spathname, O_RDONLY);
    int flags = O_RDWR | O_CREAT;
    tfd = open(tpathname, flags);
    while (read(sfd, &c, 1) > 0)
        write(tfd, &c, 1);
    fstat(sfd, &s);
    chown(tpathname, s.st_uid, s.st_gid);
    chmod(tpathname, s.st_mode);

    close(sfd);
    close(tfd);
}

void d_copy(char *spathname, char *tpathname) {
    struct stat s, t, temp_s, temp_t;
    struct dirent *s_p;
    DIR *dirs, *dirt;

    stat(spathname, &s);
    mkdir(tpathname, s.st_mode);
    chown(tpathname, s.st_uid, s.st_gid);
    dirt = opendir(tpathname);
    dirs = opendir(spathname);
    strcpy(temp_paths, spathname);
    strcpy(temp_patht, tpathname);
    while ((s_p = readdir(dirs)) != NULL) {
        if (strcmp(s_p->d_name, ".") != 0 && strcmp(s_p->d_name, "..") != 0) {
            strcat(temp_paths, "/");
            strcat(temp_paths, s_p->d_name);
            strcat(temp_patht, "/");
            strcat(temp_patht, s_p->d_name);
            lstat(temp_paths, &s);
            temp_s.st_mode = s.st_mode;
            if (S_ISLNK(temp_s.st_mode)) {
                printf("%s is a symbol link file\n", temp_paths);
            } else if (S_ISREG(temp_s.st_mode)) {
                printf("Copy file %s ......\n", temp_paths);
                Copy(temp_paths, temp_patht);
                strcpy(temp_paths, spathname);
                strcpy(temp_patht, tpathname);
            } else if (S_ISDIR(temp_s.st_mode)) {
                printf("Copy directory %s ......\n", temp_paths);
                d_copy(temp_paths, temp_patht);
                strcpy(temp_paths, spathname);
                strcpy(temp_patht, tpathname);
            }
        }
    }
}


// 由于Inject是命令行工具 因此 替换全部的LOG为printf 以方便观察注入流程
int main(int argc, char *argv[]) {
//    printf("+临时关闭SeLinux\n");
//    system("setenforce 0");
//    //结束运行
//    printf("+结束运行\n");
//    system("killall com.tencent.mf.uam");
//    //启动游戏
//    printf("+启动游戏\n");
//    system("am start com.tencent.mf.uam/com.tencent.gcloud.msdk.core.policy.MSDKPolicyActivity");
//    printf("开始注入so\n");
//    //等待注入时机
//    sleep(1);
//    int pid = get_pid_by_name((char *) "com.tencent.mf.uam");
//    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
//        printf("[-] ptrace attach process error, pid:%d, err:%s\n", pid, strerror(errno));
//        return -1;
//    } else {
//        printf("[+] attach porcess success, pid:%d", pid);
//    }
//    return 0;

    // 开始注入
    /** 以下是Inject命令行工具的参数
     ** 部分参数选填
     * -p 目标进程pid <-- 不传pid就传包名
     * -n 目标App包名 <-- 不传包名就传pid
     * -f 是否开启App <-- 看你要不要强制唤醒App
     * ---- // 由于 -f 参数需要创建中间文件 因此 请务必在Inject工具目录执行该工具
     * ---- // 即 /data/local/tmp/Inject -f -n XXX <-- 错误
     * ---- // 即 cd /data/local/tmp && ./Inject -f -n XXX <-- 正确
     * -so 注入的so路径 <-- 必填 本来就是so注入工具 只能是绝对路径!!
     * -symbols 指定启用so中的某功能 <-- 选填 可以指定so中某功能的symbols 也可以通过__attribute__((constructor))让so注入后自行初始化
     */
    printf("[+] 开始注入\n");
    if (init_inject(argc, argv) == 0) {
        printf("[+] Finish Inject\n");
    } else {
        printf("[-] Inject Erro\n");
    }
    /**
     * eg:
     * cd /data/local/tmp && ./Inject -f -n bin.mt.plus -so /data/local/tmp/libHook.so -symbols hello
     * cd /data/local/tmp/UamHelper && ./inject -f -n com.tencent.mf.uam -so /data/local/tmp/UamHelper/libOoOoOoOoOoOoO.so -symbols init
     */
    return 0;
}