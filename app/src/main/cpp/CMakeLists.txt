#声明要求的cmake最低版本
cmake_minimum_required(VERSION 3.4.0)

#内联支持
ENABLE_LANGUAGE(C ASM)

#引入dobbyhook框架
add_library(local_dobby STATIC IMPORTED)
set_target_properties(local_dobby PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libdobby.a)


include_directories(
        src
        include
        include/PtraceInject
        include/PtraceInject/include
        include/PtraceInject/include/Utils
        )
#注入绘制
add_library(
        native-lib
        SHARED
        src/Hook.cpp
)


target_link_libraries(native-lib
        local_dobby
        m
        dl
        log
        z
        )

add_executable(
        ptrace
        include/PtraceInject/pmparser.c
        include/PtraceInject/inject.cpp
)
target_link_libraries(ptrace log m dl log z)



