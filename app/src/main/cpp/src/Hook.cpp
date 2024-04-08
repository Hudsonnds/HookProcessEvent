//
// Created by BF on 2024/4/8
//
#include "Hook.h"
#include "dobby.h"

#pragma once


#include <string>
#include <unordered_set>
#include <codecvt>
#include <cstdlib>
#include <climits>
#include <unistd.h>
#include <sys/uio.h>
#include <asm-generic/unistd.h>
#include "logUtils.h"

using namespace std;


static int GWorld = 0xD0EB4E8;//搜索字串 g.GEnableNewGSCalcMethod
static int GNames = 0xD8D0358; //搜索字串 st.vw.shootinf
static int GObject = 0xDB84964;//搜索字串 ObjectHash.UseIndexHash    ADRL            X19, unk_AB0BB50  ObjectHash.EnableShrink
static int GProcessEvent = 0x69103CC; //字串搜索 ProcessEvent In Actor IsPendingConstruction
//Global
static int PointerSize = 0x8;
static int FUObjectItemPad = 0x0;
static int FUObjectItemSize = 0x18;
//Class: FUObjectArray
static int FUObjectArrayToTUObjectArray = 0xC8;
//Class: FUObjectArray
static int TUObjectArrayToNumElements = 0x38;
//Class: UObject
static int UObjectToClassPrivate = 0x10;
static int UObjectToInternalIndex = 0x18;
static int UObjectToOuterPrivate = 0x20;
//Class: FNameEntry
static int FNameEntryToNameString = 0xC;

uint64_t GnameAddress = 0;
uintptr_t libUE4 = 0;

__attribute__((always_inline)) bool IsPtrValid(void *ptr) {
    static int fd = syscall(__NR_memfd_create, "jit-zygote-cache", (unsigned int) (MFD_CLOEXEC));
    return syscall(__NR_write, fd, ptr, 4) >= 0;
}

__attribute__((always_inline))void *my_memmove(void *dst, const void *src, size_t count) {
    if (src == NULL || dst == NULL) {
        return NULL;
    }
    char *tmp_dst = (char *) dst;
    char *tmp_src = (char *) src;
    if (tmp_src == NULL) {
        return NULL;
    }
    if (tmp_dst + count < src || tmp_src + count < dst) {
        while (count--)
            *tmp_dst++ = *tmp_src++;
    } else {
        tmp_dst += count - 1;
        tmp_src += count - 1;
        while (count--)
            *tmp_dst-- = *tmp_src--;
    }
    return dst;
}


__attribute__((always_inline))bool memoryRead(uintptr_t address, void *buffer, int size) {
    memset(buffer, 0, size);
    if (!IsPtrValid(reinterpret_cast<void *>(address))) { return false; }
    return my_memmove(buffer, reinterpret_cast<void *>(address), size) != nullptr;
}

__attribute__((always_inline))uintptr_t getModuleBase(const char *name) {
    uintptr_t base = 0;
    char line[512] = {};
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        return 0;
    }
    while (fgets(line, sizeof line, f)) {
        uintptr_t tmpBase;
        char tmpName[256];
        if (sscanf(line, "%" PRIXPTR "-%*" PRIXPTR " %*s %*s %*s %*s %s", &tmpBase, tmpName) > 0) {
            if (!strcmp(basename(tmpName), name)) {
                base = tmpBase;
                break;
            }
        }
    }
    fclose(f);
    return base;
}


__attribute__((always_inline))int getI(uintptr_t address) {
    int value = 0;
    int *p = &value;
    if (!memoryRead(address, p, sizeof(int)))
        return 0;
    return value;
}

__attribute__((always_inline))uintptr_t getA(uintptr_t address) {
    uintptr_t value = 0;
    uintptr_t *p = &value;
    if (!memoryRead(address, p, sizeof(uintptr_t)))
        return 0;
    return value;
}

__attribute__((always_inline))float getF(uintptr_t address) {
    float value = 0.0f;
    float *p = &value;
    if (!memoryRead(address, p, sizeof(float)))
        return 0;
    return value;
}


class GUObjects {
public:
    static int GetObjectCount() {
        int count = getI(libUE4 + GObject + FUObjectArrayToTUObjectArray + TUObjectArrayToNumElements);
        if (count < 10 || count > 999999) {
            count = 300000;
        }
        return count;
    }

    static uintptr_t GetUObjectFromID(int index) {
        uintptr_t TUObjectArray = getA(libUE4 + GObject + FUObjectArrayToTUObjectArray);
        uintptr_t Chunk = getA(TUObjectArray + ((index / 0x10000) * PointerSize));
        return getA(Chunk + FUObjectItemPad + ((index % 0x10000) * FUObjectItemSize));
    }
};


class UObject {
public:
    static string GetFNameFromID(unsigned int index) {
        uintptr_t FNameEntryArr = getA(GnameAddress + ((index / 0x4000) * PointerSize));
        uintptr_t FNameEntry = getA(FNameEntryArr + ((index % 0x4000) * PointerSize));
        if (!IsPtrValid(reinterpret_cast<void *>(FNameEntry + FNameEntryToNameString))) { return "error"; }
        return string((char *) FNameEntry + FNameEntryToNameString);
    }

    static int getIndex(uintptr_t object) {
        return getI(object + UObjectToInternalIndex);
    }

    static uintptr_t getClass(uintptr_t object) {
        return getA(object + UObjectToClassPrivate);
    }

    static int getNameID(uintptr_t object) {
        return getI(object + UObjectToInternalIndex);
    }

    static uintptr_t getOuter(uintptr_t object) {
        return getA(object + UObjectToOuterPrivate);
    }

    static string getName(uintptr_t object) {
        if (!UObject::isValid(object)) return "错误";
        return GetFNameFromID(getNameID(object));
    }

    static string getClassName(uintptr_t object) {
        return getName(getClass(object));
    }

    static bool isValid(uintptr_t object) {
        return (IsPtrValid(reinterpret_cast<void *>(object)) && getNameID(object) > 0 && getClass(object) > 0);
    }

    static bool isValid(UObject *object) {
        return (IsPtrValid(reinterpret_cast<void *>(object)) && getNameID(reinterpret_cast<uintptr_t>(object)) > 0 && getClass(reinterpret_cast<uintptr_t>(object)) > 0);
    }

    static uintptr_t FindClass(const char *name) {
        int ocount = GUObjects::GetObjectCount();
        LOGD("ocount:%d", ocount);
        for (int i = 0; i < ocount; i++) {
            uintptr_t uobj = GUObjects::GetUObjectFromID(i);
            if (!UObject::isValid(uobj)) continue;
            string Name = UObject::getName(uobj);
            LOGE("FindClassName:%s", Name.c_str());
            if (isEqual(Name, name)) return uobj;
        }
        return 0;
    }


private:
    static bool isContain(string str, const char *check) {
        if (check == nullptr || str.empty()) return false;
        return str.find(check) != string::npos;
    }

    static bool isEqual(string s1, const char *check) {
        string s2(check);
        return (s1 == s2);
    }
};



static void (*orig_ProcessEvent)(void *thiz, void *function, void *params);

static void newProcessEvent(void *thiz, void *function, void *params) {
    static void *LogedFunctions[4096 * 4] = {};
    static int LogedCount;
    bool dumped = false;
    for (int i = 0; i < LogedCount; ++i) {
        if (LogedFunctions[i] == function) {
            dumped = true;
            break;
        }
    }
    if (!dumped) {
        LOGE("Call: class:%s fun:%s", UObject::getName((uintptr_t) thiz).c_str(), UObject::getClassName((uintptr_t) function).c_str());
    }
    if (!dumped) {
        LogedFunctions[LogedCount] = function;
        LogedCount++;
    }
    return orig_ProcessEvent(thiz, function, params);
}


inline void *read_thread(void *) {
    while (!libUE4) {
        sleep(1);
        libUE4 = getModuleBase("libUE4.so");
        usleep(1000);
        LOGD("[info] libUE4: %lx", libUE4);
    }
    GnameAddress = getA(libUE4 + GNames);
    DobbyHook(reinterpret_cast<void *>(libUE4 + GProcessEvent), (void *) newProcessEvent, (void **) &orig_ProcessEvent);
    return nullptr;
}

__attribute__((constructor)) void init() {
    pthread_t t;
    pthread_create(&t, nullptr, read_thread, nullptr);
}

#pragma clang diagnostic pop


