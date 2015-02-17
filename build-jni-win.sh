#!/bin/sh

#############################################
# Build the JNI libraries for Windows       #
#                                           #
# 64-bit gcc is in PATH                     #
# 32-bit gcc is in /c/mingw/bin             #
#                                           #
# 64-bit Windows switches \Windows\system32 #
# based on whether the executable is        #
# 32-bit or 64-bit, so we need to use       #
# the 32-bit gcc when linking the           #
# 32-bit dll.                               #
#############################################

#############################################
# Bitcoin-Core uses the same library name   #
# for 32-bit and 64-bit versions.  So we    #
# need to place them in separate            #
# directories.  We will use win_x86 for     #
# the 32-bit library and win_x86_64 for     #
# the 64-bit library.                       #
#############################################

# Package name
PKG=org.ScripterRon.JavaBitcoin

# Class libraries for JavaBitcoin and BitcoinCore
CLASS="target/*;target/lib/*"

# Output directory for generated include files
INCLUDE=target/generated-sources/include

# Output directory for generated object files
OBJ=target/generated-sources/obj

# Output directory for generated library files
JNI=target/jni

# JNI source directory
SRC=src/main/c

# JNI include directory
INC=src/main/include

# Bitcoin-Core library directory
LIB=package/jni

# Create output directories
if [ ! -d $INCLUDE ] ; then
    mkdir $INCLUDE
fi

if [ ! -d $OBJ ] ; then
    mkdir $OBJ
fi

if [ ! -d $JNI ] ; then
    mkdir $JNI
fi

echo "Building the Java include files"
javah -d $INCLUDE -cp "$CLASS" $PKG.BitcoinConsensus || exit 1

echo "Building JavaBitcoin_x86_64.dll"
gcc -c -O3 -m64 -D_POSIX_C_SOURCE -I$INCLUDE -I$INC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/win32" -o $OBJ/JniConsensus.o $SRC/JniConsensus.c || exit 1
gcc -m64 -shared -L$LIB/win_x86_64 -o $JNI/JavaBitcoin_x86_64.dll $OBJ/JniConsensus.o -lbitcoinconsensus-0 || exit 1

echo "Building JavaBitcoin_x86.dll"
gcc -c -O3 -m32 -D_POSIX_C_SOURCE -I$INCLUDE -I$INC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/win32" -o $OBJ/JniConsensus.o $SRC/JniConsensus.c || exit 1
/c/mingw/bin/gcc -m32 -shared -L$LIB/win_x86 -o $JNI/JavaBitcoin_x86.dll $OBJ/JniConsensus.o -lbitcoinconsensus-0 || exit 1

exit 0

