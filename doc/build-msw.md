Copyright (c) 2014-2019 Noblecoin Developers

Copyright (c) PeerUnity Developers

Distributed under the MIT/X11 software license, see the accompanying
file license.txt or http://www.opensource.org/licenses/mit-license.php.
This product includes software developed by the OpenSSL Project for use in
the OpenSSL Toolkit (http://www.openssl.org/).  This product includes
cryptographic software written by Eric Young (eay@cryptsoft.com) and UPnP
software written by Thomas Bernard.


See readme-qt.rst for instructions on building Bitcoin QT, the
graphical user interface.

WINDOWS BUILD NOTES
===================

#Building headless Noblecoind and noblecoin Qt on Windows

## 1. Prepare your build system
I strongly suggest setting up a clean Windows 7 virtual machine via Virtualbox or similar, with 7zip and Notepad++ installed.

### 1.1 Install MinGW (MSYS) shell

http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe

From MinGW installation manager -> All packages -> MSYS -> mark the following for installation:

*msys-base-bin*

... then click on Installation -> Apply changes

Make sure no MinGW packages are checked for installation or present from a previous install. Only the above MSYS package should be installed. Also make sure that *msys-gcc* and *msys-w32api* packages are not installed.

### 1.2 Install Perl

http://downloads.activestate.com/ActivePerl/releases/5.18.2.1802/ActivePerl-5.18.2.1802-MSWin32-x86-64int-298023.msi

Install with defaults.

### 1.3 Install Python

http://www.python.org/ftp/python/3.3.3/python-3.3.3.amd64.msi

Install with defaults.

### 1.4 Install a QT Creator 5.9.7 with MinGW 5.3:

https://www.qt.io/


### 1.5 Set system PATH environment variable

Ensure that mingw-builds, MSYS, Perl and Python bin folders are set in your PATH environment variable. On Windows 10, your path should look something like:
```
C:\MinGW\msys\1.0\bin
C:\mingw32\bin
C:\Python33
C:\Perl\site\bin;C:\Perl\bin
C:\Qt\Tools\mingw530_32\bin
C:\Qt\5.9.7\mingw53_32\bin

...
```

### 1.6 Additional checks

C:\MinGW\bin should contain nothing but mingw-get.exe.
Your gcc -v output should be:
```
$ gcc -v

... not important text...

gcc version 5.3.0 (i686-posix-dwarf-rev0, Built by MinGW-W64 project)

Same for G++ -v and Qmake -v

```

## 2. Download, unpack and build required dependencies

### 2.1 OpenSSL 

https://www.openssl.org/source/openssl-1.1.1g.tar.gz

From an MinGW shell (C:\MinGW\msys\1.0\msys.bat), unpack the source archive to C:\deps, then configure and make:

```
cd c/deps/openssl-1.1.1g
Configure mingw
make
```

### 2.2 Berkeley DB

http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz

We'll use version 4.8 to preserve binary wallet compatibility.
From a MinGW shell unpack the source archive, configure and make:

```
cd c/deps/db-4.8.30.NC/build_unix
../dist/configure --disable-replication --enable-mingw --enable-cxx
make
```

### 2.3 Boost

http://sourceforge.net/projects/boost/files/boost/1.66.0/

Download either the zip or the 7z archive, unpack Boost to C:\deps, then bootstrap and compile from a Windows command prompt:

```
cd C:\deps\boost_1_66_0\tools\build\
bootstrap.bat gcc
cd C:\deps\boost_1_66_0\
tools\build\b2 toolset=gcc --build-type=complete stage --with-filesystem --with-system --with-program_options --with-thread --with-chrono
```

This will compile the required Boost libraries and put them into the stage folder (C:\deps\boost_1_66_0\stage).
Note: make sure you don't use tarballs, as unix EOL markers can break batch files.

### 2.4 Miniupnpc

Download http://miniupnp.free.fr/files/download.php?file=miniupnpc-1.6.20120509.tar.gz and unpack to C:\deps, then from a Windows command prompt:

```
cd C:\deps\miniupnpc-1.6
mingw32-make -f Makefile.mingw init upnpc-static
mkdir C:\deps\miniupnpc-1.6\miniupnpc
copy C:\deps\miniupnpc-1.6\*.h C:\deps\miniupnpc-1.6\miniupnpc
```

### 2.5 Qrencode

Download http://prdownloads.sourceforge.net/libpng/libpng-1.6.9.tar.gz then, from a MinGW shell, unpack, configure and make:

```
cd c:/deps/libpng-1.6.9
configure
make
```

Download and unpack http://fukuchi.org/works/qrencode/qrencode-3.4.4.tar.gz inside your C:\ directory then configure and make:

```
cd c:/deps/qrencode-3.4.4

LIBS="../libpng-1.6.9/.libs/libpng16.a ../../Qt/Tools/mingw530_32/i686-w64-mingw32/lib/libz.a" \
png_CFLAGS="-I../libpng-1.6.9" \
png_LIBS="-L../libpng-1.6.9/.libs" \
configure --enable-static --disable-shared

make
```

## 3. Compile Noblecoind
 
Download the Noblecoin master at https://github.com/ and unzip to C:\

With a text editor, edit INCLUDEPATHS, LIBPATHS, and LIBS in your C:\noblecoin-master\src\makefile.mingw according to your dependency versions and locations:

```
INCLUDEPATHS= \
 -I"C:\deps\boost_1_58_0" \
 -I"C:\deps\db-4.8.30.NC\build_unix" \
 -I"C:\deps\openssl-1.0.2\include"

LIBPATHS= \
 -L"C:\deps\boost_1_58_0\stage\lib" \
 -L"C:\deps\db-4.8.30.NC\build_unix" \
 -L"C:\deps\openssl-1.0.2"

LIBS= \
 -l boost_system-mgw53-mt-s-1_58 \
 -l boost_filesystem-mgw53-mt-s-1_58 \
 -l boost_program_options-mgw53-mt-s-1_58 \
 -l boost_thread-mgw53-mt-s-1_58 \
 -l db_cxx \
 -l ssl \
 -l crypto
```

and...
```
ifdef USE_UPNP
 INCLUDEPATHS += -I"C:\deps\miniupnpc-1.6"
 LIBPATHS += -L"C:\deps\miniupnpc-1.6"
 LIBS += -l miniupnpc -l iphlpapi
 DEFS += -DSTATICLIB -DUSE_UPNP=$(USE_UPNP)
endif
```

Upnp support is disabled by default. If you want to compile with UPNP support set:

```
 USE_UPNP:=1
```

From MinGW shell, compile Noblecoind:
```
cd /c/noblecoin-master/src
make -f makefile.mingw
strip noblecoind.exe
```

## 4. Compile noblecoin-qt.exe with Qt 5.9.7

### 4.1 Download and unpack Qt 5.9.7

To make a Stand-alone version of Noblecoin (able to work seperate from development area) you need to setup a Static QT version.
For this Follow instructions: https://wiki.qt.io/Building_a_static_Qt_for_Windows_using_MinGW

Use this QT version:
https://download.qt.io/official_releases/qt/5.9/5.9.7/single/qt-everywhere-opensource-src-5.9.7.zip


### 4.3 Edit C:\noblecoin-master\noblecoin-qt.pro 

With your favorite text editor, add dependency library locations:

```
BOOST_LIB_SUFFIX=-mgw53-mt-s-x32-1_66
BOOST_INCLUDE_PATH=C:/deps/boost_1_66_0-mgw
BOOST_LIB_PATH=C:/deps/boost_1_66_0-mgw/stage/lib
BDB_INCLUDE_PATH=C:/deps/db-4.8.30.NC-mgw/build_unix
BDB_LIB_PATH=C:/deps/db-4.8.30.NC/build_unix
OPENSSL_INCLUDE_PATH=C:/deps/openssl-1.1.1g/include
OPENSSL_LIB_PATH=C:/deps/openssl-1.1.1g
MINIUPNPC_INCLUDE_PATH=C:/deps/miniupnpc-1.6
MINIUPNPC_LIB_PATH=C:/deps/miniupnpc-1.6
QRENCODE_INCLUDE_PATH=C:/deps/qrencode-3.4.4
QRENCODE_LIB_PATH=C:/deps/qrencode-3.4.4/.libs
```


### 4.5 Compile noblecoin-qt.exe

>Note that if you skipped noblecoind compilation or if you have cleaned up your source folder you will need to compile libleveldb.a and libmemenv.a libraries before proceeding. Skip this step if you did compile noblecoind.exe. 
>From MinGW shell:
>```
>cd /C/noblecoin-master/src/leveldb
>TARGET_OS=NATIVE_WINDOWS make libleveldb.a libmemenv.a
>``` 

From Qt Creator :
```
open noblecoin-qt.pro
Select the STATIC kit
Press Build
```
