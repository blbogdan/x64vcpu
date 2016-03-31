cmake_minimum_required(VERSION 2.6)
project(testemu)


set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")


add_library(x64cpu STATIC
    cpu/opcode_decoder.c
    cpu/opcode_decoder32.c
    cpu/cpu.c
    cpu/disasm.c
    cpu/virtual_memory.c
    cpu/dynamic_recompiler.c
)
set_target_properties(x64cpu PROPERTIES COMPILE_FLAGS "-msse2 -Wall -g -O0 -fPIC")

add_library(environment STATIC
    environment/linux/elf-file.c
    environment/linux/ElfLoader.cc
    environment/linux/EnvLinuxIO.cc
    environment/linux/EnvLinux.cc
    environment/linux/EnvLinuxSyscall.cc
    environment/win/PEFile.cc
    environment/win/EnvWin32.cc
    environment/environment.cc
)
set_target_properties(environment PROPERTIES COMPILE_FLAGS "-g -O0 -fpermissive -fPIC")
target_link_libraries(environment x64cpu)


# Debugger
add_executable(emudbg
    debugger/modules/CallStack.cc
    debugger/modules/MemoryViewer.cc
    debugger/modules/CodeLog.cc
    debugger/modules/Disassembler.cc
    debugger/modules/StackView.cc
    debugger/modules/CPUViewer.cc
    debugger/modules/Modules.cc
    debugger/Buffer.cc
    debugger/Window.cc
    debugger/Debugger.cc
    debugger/main.cc
)
set_target_properties(emudbg PROPERTIES COMPILE_FLAGS "-g -O0")
target_link_libraries(emudbg x64cpu environment ncurses)


# Deprecated
add_executable(dbg
    samples/dbg.cc
)
set_target_properties(dbg PROPERTIES COMPILE_FLAGS "-Wall -g -O0")
target_link_libraries(dbg x64cpu environment ncurses)


# OLD
# add_executable(test01 test/test01.c)
# set_target_properties(test01 PROPERTIES COMPILE_FLAGS "-Wall -g -O0")
# target_link_libraries(test01 x64cpu)

add_executable(test03 test/test03.c)
set_target_properties(test03 PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -ffreestanding -nostdlib")
target_link_libraries(test03 "-g -nostdlib")

add_executable(test04 test/test04.c)
set_target_properties(test04 PROPERTIES COMPILE_FLAGS "-Wall -g -O0")
target_link_libraries(test04 "-g")

add_executable(test05 test/test05.c)
set_target_properties(test05 PROPERTIES COMPILE_FLAGS "-Wall -g -O0")
target_link_libraries(test05 "-g")

add_executable(test06 test/test06.c)
set_target_properties(test06 PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -mno-sse")
target_link_libraries(test06 "-g")


# Wrappers

function(gen_wrapper name depname)
    exec_program(perl ARGS "-MExtUtils::Embed -e ccopts" OUTPUT_VARIABLE S_C_FLAGS)
    exec_program(perl ARGS "-MExtUtils::Embed -e ldopts" OUTPUT_VARIABLE S_LDFLAGS)

    MESSAGE(STATUS "Perl CFLAGS: ${S_C_FLAGS}")
    MESSAGE(STATUS "Perl LDFLAGS: ${S_LDFLAGS}")

    add_custom_command(OUTPUT wrappers/${name}_wrap.c COMMAND swig -perl wrappers/${name}.i
                        MAIN_DEPENDENCY wrappers/${name}.i
                        DEPENDS lib${depname}.a )
    add_library(${name} SHARED wrappers/${name}_wrap.c)
    set_target_properties(${name} PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fPIC `perl -MExtUtils::Embed -e ccopts` ")
    set_target_properties(${name} PROPERTIES LINK_FLAGS "${S_LDFLAGS}")
    set_target_properties(${name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "wrappers/")
    target_link_libraries(${name} ${depname})
endfunction()

function(gen_wrapper_cpp name depname)
    exec_program(perl ARGS "-MExtUtils::Embed -e ccopts" OUTPUT_VARIABLE S_C_FLAGS)
    exec_program(perl ARGS "-MExtUtils::Embed -e ldopts" OUTPUT_VARIABLE S_LDFLAGS)

    MESSAGE(STATUS "Perl CFLAGS: ${S_C_FLAGS}")
    MESSAGE(STATUS "Perl LDFLAGS: ${S_LDFLAGS}")

    add_custom_command(OUTPUT wrappers/${name}_wrap.cxx COMMAND swig -c++ -perl wrappers/${name}.i
                        MAIN_DEPENDENCY wrappers/${name}.i
                        DEPENDS lib${depname}.a )
    add_library(${name} SHARED wrappers/${name}_wrap.cxx)
    set_target_properties(${name} PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fPIC `perl -MExtUtils::Embed -e ccopts` ")
    set_target_properties(${name} PROPERTIES LINK_FLAGS "${S_LDFLAGS}")
    set_target_properties(${name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "wrappers/")
    target_link_libraries(${name} ${depname})
endfunction()

gen_wrapper(cpu x64cpu)
gen_wrapper_cpp(env environment)



# SAMPLES

add_executable(pedumper samples/pedumper.cc)
set_target_properties(pedumper PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fpermissive")
target_link_libraries(pedumper x64cpu environment)

add_executable(primes samples/primes.cc)
set_target_properties(primes PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fpermissive")
target_link_libraries(primes x64cpu environment)

add_executable(primes_vm samples/primes_vm.cc)
set_target_properties(primes_vm PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fpermissive")
target_link_libraries(primes_vm x64cpu environment)

add_executable(linload samples/linload.cc)
set_target_properties(linload PROPERTIES COMPILE_FLAGS "-Wall -g -O0 -fpermissive")
target_link_libraries(linload x64cpu environment)

