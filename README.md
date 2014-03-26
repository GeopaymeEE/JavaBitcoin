JavaBitcoin
===========

JavaBitcoin is a bitcoin client node written in Java.  It supports receiving and relaying blocks and transactions but does not support bitcoin mining.  This ensure that running this node won't cause a block chain fork.  It also supports Simple Payment Verification (SPV) clients such as the Android Wallet and MultiBit.

It does full verification for blocks that it receives and will reject blocks that do not pass the verification tests.  These rejected blocks are still stored in the database and can be included in the block chain by either temporarily turning off block verification or by updating the verification logic.  Spent transaction outputs are periodically removed from the database.  The full blocks are maintained in external storage in the same manner as the reference client (blknnnnn.dat files).

There is a graphical user interface that displays alerts, peer connections (network address and client version) and recent blocks (both chain and orphan).

You can use the production network (PROD) or the regression test network (TEST).  The regression test network is useful because bitcoind will immediately generate a specified number of blocks.  To use the regression test network, start bitcoind with the -regtest option.  You can then generate blocks using bitcoin-cli to issue 'setgenerate true n' where 'n' is the number of blocks to generate.  Block generation will stop after the requested number of blocks have been generated.  Note that the genesis block, address formats and magic numbers are different between the two networks.  JavaBitcoin will create files related to the TEST network in the TestNet subdirectory of the application data directory.

BouncyCastle (1.51 or later) is used for the elliptic curve functions.  Version 1.51 provides a custom SecP256K1 curve which significantly improves ECDSA performance.  Earlier versions of BouncyCastle do not provide this support and will not work with JavaBitcoin.

Simple Logging Facade (1.7.5 or later) is used for console and file logging.  I'm using the JDK logger implementation which is controlled by the logging.properties file located in the application data directory.  If no logging.properties file is found, the system logging.properties file will be used (which defaults to logging to the console only).

LevelDB is used for the database.  The LevelDB support is provided by leveldbjni (1.8 or later).  leveldbjni provides a native interface to the LevelDB routines.  The native LevelDB library is included in the leveldbjni.jar file and is extracted when you run the program.  On Windows, this causes a new temporary file to be created each time the program is run.  To get around this, extract the Windows version of leveldbjni.dll from the leveldbjni.jar and place it in a directory in the executable path (specified by the PATH environment variable).  Alternately, you can define the path to leveldbjni.dll by specifying '-Djava.library.path=directory-path' on the command line used to start JavaBitcoin.

A compiled version is available here: https://drive.google.com/folderview?id=0B1312_6UqRHPYjUtbU1hdW9VMW8&usp=sharing.  Download the desired archive file and extract the files to a directory of your choice.  If you are building from the source, the dependent jar files can also be obtained here.


Build
=====

I use the Netbeans IDE but any build environment with Maven and the Java compiler available should work.  The documentation is generated from the source code using javadoc.

Here are the steps for a manual build.  You will need to install Maven 3 and Java SE Development Kit 7 if you don't already have them.

  - Create the executable: mvn clean install
  - [Optional] Create the documentation: mvn javadoc:javadoc
  - [Optional] Copy target/JavaBitcoin-v.r.jar to wherever you want to store the executable.
  - Create a shortcut to start JavaBitcoin using java.exe for a command window or javaw.exe for GUI only. 
  
  
Install
=======

JavaBitcoin stores its application data in the user application data directory.  You can override this by specifying -Dbitcoin.datadir=data-path on the command line before the -jar option.  The blocks are stored in the Blocks subdirectory.  The LevelDB databases are stored in the LevelDB subdirectory.

The first time you start JavaBitcoin, it will create and initialize the tables in the database.  You will also need to resize the GUI to the desired size.  Stop and restart JavaBitcoin and the GUI tables should be resized to match the new window dimensions.

If you have Bitcoin-Qt already installed, you can use its block files to build the database as follows:

	java -Xmx512m -Dbitcoin.verify.blocks=0 -jar JavaBitcoin.jar LOAD PROD "%Bitcoin%"
  
where %Bitcoin% specifies the Bitcoin-Qt application directory (for example, \Users\YourName\AppData\Roaming\Bitcoin).

Otherwise, start JavaBitcoin and it will download the block chain from the peer network:

	java -Xmx512m -jar JavaBitcoin.jar PROD


Runtime Options
===============

The following command-line arguments are supported:

  - INDEX PROD|TEST		
    Rebuild the block index in the LevelDB database using a new block chain.  The Blocks subdirectory in the application directory must be empty.  New files will be created using the supplied block chain files (for example, the block chain files created by the reference client).  This allows the LevelDB database to be copied to a new system which already has the block chain files.  The existing block chain must be at the database level or higher (that is, if the chain head in the database is 275000, then the block chain files must contain block 275000).  After the block index has been rebuilt, the block chain files will be processed to add any additional blocks to the database.  Upon completion, the LevelDB database will contain entries for all blocks in the block chain files.
	
  - LOAD PROD|TEST directory-path start-block		
    Load the block chain from the reference client data directory and create the block database. Specify PROD to load the production database or TEST to load the test database. The default reference client data directory will be used if no directory path is specified. The program will terminate after loading the block chain.
	
  - PROD	
    Start the program using the production network. Application files are stored in the application data directory and the production database is used. DNS discovery will be used to locate peer nodes.
	
  - RETRY PROD|TEST block-hash		
    Retry a block which is currently held. Specify PROD to use the production database or TEST to use the test database. The block hash is the 64-character hash for the block to be retried.
	
  - TEST	
    Start the program using the regression test network. Application files are stored in the TestNet folder in the application data directory and the test database is used. At least one peer node must be specified in JavaBitcoin.conf since DNS discovery is not supported for the regression test network.
	
The following command-line options can be specified using -Dname=value

  - bitcoin.datadir=directory-path	
    Specifies the application data directory. Application data will be stored in a system-specific directory if this option is omitted:		
	    - Linux: user-home/.JavaBitcoin		
		- Mac: user-home/Library/Application Support/JavaBitcoin	
		- Windows: user-home\AppData\Roaming\JavaBitcoin	
	
  - bitcoin.verify.blocks=n		
    Blocks are normally verified as they are added to the block chain. Block verification can be disabled to improve performance. Specify 1 to enable verification and 0 to disable verification. The default is 1.
	
  - java.util.logging.config.file=file-path		
    Specifies the logger configuration file. The logger properties will be read from 'logging.properties' in the application data directory. If this file is not found, the 'java.util.logging.config.file' system property will be used to locate the logger configuration file. If this property is not defined, the logger properties will be obtained from jre/lib/logging.properties.
	
    JDK FINE corresponds to the SLF4J DEBUG level	
	JDK INFO corresponds to the SLF4J INFO level	
	JDK WARNING corresponds to the SLF4J WARN level		
	JDK SEVERE corresponds to the SLF4J ERROR level		
	
The following configuration options can be specified in JavaBitcoin.conf.  This file is optional and must be in the application directory in order to be used.

  - connect=[address]:port		
    Specifies the address and port of a peer node.  This statement can be repeated to define multiple nodes.  If this option is specified, outbound connections will be created to only the listed addresses and DNS discovery will not be used.
	
  - maxconnections=n	
    Specifies the maximum number of inbound and outbound connections and defaults to 32.
	
  - maxoutbound=n	
    Specifies the maximum number of outbound connections and defaults to 8.
	
  - port=n		
	Specifies the port for receiving inbound connections and defaults to 8333
	
Sample Windows shortcut:

	javaw.exe -Xmx512m -Djava.library.path=\Bitcoin\JavaBitcoin -jar \Bitcoin\JavaBitcoin\JavaBitcoin.jar PROD
	
Replace javaw.exe with java.exe if you want to run from a command prompt.  This will allow you to view log messages as they occur.

In this example, the leveldbjni.dll file was extracted from the jar file and placed in the \Bitcoin\JavaBitcoin directory.  Specifying java.library.path tells the JVM where to find the native resources.
