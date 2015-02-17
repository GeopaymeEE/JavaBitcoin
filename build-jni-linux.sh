#!/bin/sh

#############################################
# Build the JNI libraries for Linux         #
#############################################

#############################################
# Bitcoin-Core uses the same library name   #
# for 32-bit and 64-bit versions.  So we    #
# need to place them in separate            #
# directories.  We will use linux_x86 for   #
# the 32-bit library and linux_x86_64 for   #
# the 64-bit library.                       #
#############################################

# Java home
JAVA_HOME=/usr/lib/jvm/default-java

# Package name
PKG=org.ScripterRon.JavaBitcoin

# Class libraries for JavaBitcoin and BitcoinCore
CLASS="*:lib/*"

# Output directory for generated include files
INCLUDE=include

# Output directory for generated object files
OBJ=obj

# Output directory for generated library files
JNI=jni

# JNI source directory
SRC=src/c

# JNI include directory
INC=src/include

# Bitcoin-Core library directory
LIB=jni

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

echo "Building libJavaBitcoin_x86_64.so"
gcc -c -O3 -m64 -fPIC -D_POSIX_C_SOURCE -I$INCLUDE -I$INC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -o $OBJ/JniConsensus.o $SRC/JniConsensus.c || exit 1
gcc -m64 -shared -L$LIB/linux_x86_64 -o $JNI/libJavaBitcoin_x86_64.so $OBJ/JniConsensus.o -lbitcoinconsensus || exit 1

echo "Building libJavaBitcoin_x86.so"
gcc -c -O3 -m32 -fPIC -D_POSIX_C_SOURCE -I$INCLUDE -I$INC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -o $OBJ/JniConsensus.o $SRC/JniConsensus.c || exit 1
gcc -m32 -shared -L$LIB/linux_x86 -o $JNI/libJavaBitcoin_x86.so $OBJ/JniConsensus.o -lbitcoinconsensus || exit 1

exit 0
