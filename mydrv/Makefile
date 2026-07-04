# NMake Makefile for mydrv kernel driver (.sys)
# Usage: nmake
# Requires: WDK (Windows Driver Kit) + Visual Studio BuildTools

KITVER=10.0.26100.0
KITDIR=C:\Program Files (x86)\Windows Kits\10

INC=$(KITDIR)\Include\$(KITVER)\km
LIB=$(KITDIR)\Lib\$(KITVER)\km\x64

CC=cl
CFLAGS=/nologo /Gz /W3 /WX /O2 /Zi /Gs /Gy /wd4995      \
       /I"$(INC)"                                          \
       /D"_AMD64_" /D"_WIN64" /D"AMD64"                    \
       /D"DBG=0" /D"NTDDI_VERSION=0x0A000000"             \
       /D"_NT_TARGET_VERSION_WIN10"

LINK=link
LDFLAGS=/nologo /DRIVER /RELEASE /MACHINE:X64               \
        /SUBSYSTEM:NATIVE /ENTRY:DriverEntry                \
        /LIBPATH:"$(LIB)"                                   \
        /NODEFAULTLIB /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text  \
        /SECTION:INIT,d

LIBS=ntoskrnl.lib wdmsec.lib hal.lib

mydrv.sys: driver.obj
	$(LINK) $(LDFLAGS) /OUT:$@ driver.obj $(LIBS)

driver.obj: driver.c
	$(CC) $(CFLAGS) /Fo$@ /c driver.c

all: mydrv.sys

clean:
	del /q *.obj *.sys *.pdb 2>NUL
