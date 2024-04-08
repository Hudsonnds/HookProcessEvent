//
// Created by admin on 2021/8/18.
//

#include <jni.h>
#include <string>
#include <cstdlib>
#include <math.h>
#include <cstdio>
#include <cstddef>
//#include <cmath>
#include <ctime>
#include <stack>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <sstream>
#include <vector>
#include <map>
#include <iomanip>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <android/log.h>
#include <pthread.h>
#include <dirent.h>
#include <list>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <codecvt>
#include <chrono>
#include <queue>
#include <memory.h>
#include <dlfcn.h>
#include <unordered_set>
#include <unordered_map>
#include <bitset>

#include <errno.h>
#include <android/log.h>


#ifndef LOG_TAG
#ifdef __LP64__
#define LOG_TAG    "GameInject_64"
#else
#define LOG_TAG    "GameInject_32"
#endif
#endif

//NDEBUG
#ifndef NDEBUG
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#else

#define LOGV(...)
#define LOGD(...)
#define LOGI(...)
#define LOGW(...)
#define LOGE(...)
#define PLOGE(fmt, args...)
#endif






