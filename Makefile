# NMake Makefile for WinIo demo
# Usage: nmake

CC=cl
CFLAGS=/nologo /O2 /EHsc /W3 /utf-8
LDFLAGS=/nologo

OBJS=main.obj WinIo.obj physmem.obj kernel.obj utils.obj uacbypass.obj rc.obj

main.exe: $(OBJS)
    $(CC) $(LDFLAGS) /Fe$@ $(OBJS) advapi32.lib ole32.lib

main.obj: main.cpp WinIo.h kernel.h utils.h log.h uacbypass.h
    $(CC) $(CFLAGS) /c main.cpp

WinIo.obj: WinIo.cpp WinIo.h physmem.h log.h
    $(CC) $(CFLAGS) /c WinIo.cpp

physmem.obj: physmem.cpp physmem.h WinIo.h log.h
    $(CC) $(CFLAGS) /c physmem.cpp

kernel.obj: kernel.cpp kernel.h physmem.h utils.h WinIo.h log.h
    $(CC) $(CFLAGS) /c kernel.cpp

utils.obj: utils.cpp utils.h kernel.h log.h
    $(CC) $(CFLAGS) /c utils.cpp

uacbypass.obj: uacbypass.cpp uacbypass.h log.h
    $(CC) $(CFLAGS) /c uacbypass.cpp

rc.obj: main.rc
    rc /nologo /fo main.res main.rc
    cvtres /nologo /machine:x64 /out:rc.obj main.res

clean:
    del /q *.obj *.exe *.res 2>NUL
