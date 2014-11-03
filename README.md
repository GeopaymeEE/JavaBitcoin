JavaBitcoin
===========

JavaBitcoin is a bitcoin client node written in Java.  It supports receiving and relaying blocks and transactions but does not support bitcoin mining.  This ensure that running this node won't cause a block chain fork.  It also supports Simple Payment Verification (SPV) clients such as the Android Wallet and MultiBit.

It does full verification for blocks that it receives and will reject blocks that do not pass the verification tests.  These rejected blocks are still stored in the database and can be included in the block chain by either temporarily turning off block verification or by updating the verification logic.  Spent transaction outputs are periodically removed from the database.  The full blocks are maintained in external storage in the same manner as the reference client (blknnnnn.dat files).  

Starting with JavaBitcoin 4.0.0, the block files can be deleted to reduce the disk space requirement.  If this is done, JavaBitcoin will return a NOT FOUND error if a block in a deleted block file is requested.  Recent block files should not be deleted since a block chain reorganization will require access to all of the blocks in the new chain following the junction block (the block where the current chain and the new chain intersect).  I suggest keeping all block files containing blocks generated within the previous 6 months.

There is a graphical user interface that displays alerts, peer connections (network address and client version) and recent blocks (both chain and orphan).  You can use this GUI for a local node or BitcoinMonitor for a remote node.  The SIGTERM signal is used to stop JavaBitcoin when running in headless mode.

The RPC interface currently supports just the requests needed by BitcoinMonitor.  These are based on the Bitcoin reference client and will be expanded as needed.  However, JavaBitcoin does not support mining and does not manage a wallet, so most of the Bitcoin RPC requests are not needed in this environment.

JavaBitcoin supports LevelDB and H2 for the database support.  

You can use the production network (PROD) or the regression test network (TEST).  The regression test network is useful because bitcoind will immediately generate a specified number of blocks.  To use the regression test network, start bitcoind with the -regtest option.  You can then generate blocks using bitcoin-cli to issue 'setgenerate true n' where 'n' is the number of blocks to generate.  Block generation will stop after the requested number of blocks have been generated.  Note that the genesis block, address formats and magic numbers are different between the two networks.  JavaBitcoin will create files related to the TEST network in the TestNet subdirectory of the application data directory.


Build
=====

I use the Netbeans IDE but any build environment with Maven and the Java compiler available should work.  The documentation is generated from the source code using javadoc.

Here are the steps for a manual build.  You will need to install Maven 3 and Java SE Development Kit 8 if you don't already have them.

  - Build and install BitcoinCore (https://github.com/ScripterRon/BitcoinCore)      
  - Create the executable: mvn clean package
  - [Optional] Create the documentation: mvn javadoc:javadoc
  - [Optional] Copy target/JavaBitcoin-v.r.m.jar and target/lib/* to wherever you want to store the executable.
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

  - BOOTSTRAP PROD|TEST directory-path start-height stop-height     
    Create bootstrap files in the 'blocks' subdirectory of the specified directory.  Specify PROD to use the production database or TEST to use the test database.  The block file names are blknnnnn.dat.gz and the files will contain just blocks in the current block chain (orphan blocks will be ignored).  start-height defaults to 0 and stop-height defaults to the current block chain height.  Use the LOAD option to load the bootstrap files and create the database on another system.  The program will terminate after creating the bootstrap files.       
    
  - COMPACT PROD|TEST   
    Compact the database.  This is a lengthy process and must not be aborted once it has been started.  You should backup the database before compacting it in case an unrecoverable error occurs.  
    
    For LevelDB, each database is compacted in-place.  
    
    For H2, a SQL backup script is created, the database is deleted and then it is recreated from the backup script.  The backup script is backup.sql.gz and can be found in the Database subdirectory.  You can delete it once you have verified that the new database is working correctly.   
    
  - LOAD PROD|TEST directory-path start-block stop-block		
    Load the block chain from the 'blocks' subdirectory of the specified directory and create the block chain database. Specify PROD to load the production database or TEST to load the test database. The default reference client data directory will be used if no directory path is specified.  The block file names are blknnnnn.dat or blknnnnn.dat.gz where nnnnn is the block file number specified by start-block and stop-block.  start-block defaults to 0 and stop-block defaults to the highest contiguous block file number following the start block.  The program will terminate after loading the block chain.  The block files used by the LOAD option can be deleted upon completion since new block files will be created in the Blocks subdirectory.
	
  - MIGRATE     
    Migrate the current LevelDB database to a new H2 database or the current H2 database to a new LevelDB database.  The existing Blocks subdirectory is not modified and will be used by the new database.  This means that you cannot switch back and forth between the LevelDB and H2 databases since the other database will no longer match the Blocks subdirectory after a new block has been processed by the current database.  The current database is determined by the dbType configuration parameter.  After migrating the current database, be sure to change the dbType configuration parameter to the new database type.    
    
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
	
  - bitcoin.headless=n        
    The local GUI is not started when 1 is specified (the default is 0).  You can use BitcoinMonitor to monitor a remote node running in headless mode.  You should also remove console logging in logging.properties so that all logging is done to a log file.        
    
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
    Specifies the address and port of a peer node.  Note that the IP address is enclosed in brackets.  This statement can be repeated to define multiple nodes.  If this option is specified, outbound connections will be created to only the listed addresses and DNS discovery will not be used. 
	
  - dbType=type		
    Specifies the database type and may be 'LevelDB' or 'H2'.  The LevelDB database will be used if no database type is specified.  
	
  - hostName=host.domain		
	Specifies the host name for this node.  An HTTP request will be made to checkip.dyndns.org to resolve the external IP address if no host name is specified in the configuration file.
	
  - maxConnections=n	
    Specifies the maximum number of inbound and outbound connections and defaults to 32.    
	
  - maxOutbound=n	
    Specifies the maximum number of outbound connections and defaults to 8. 
	
  - port=n		
	Specifies the port for receiving inbound connections and defaults to 8333       
    
  - rpcAllowIp=address     
    Specifies the address of a host that is allowed to issue JSON-RPC requests.  The default is to allow no hosts.  This statement can be repeated to define multiple hosts.  
    
  - rpcPassword=password    
    Specifies the password for RPC requests and defaults to an empty string.    
    
  - rpcPort=n   
    Specifies the port for receiving JSON-RPC requests and defaults to 8332    
    
  - rpcUser=name    
    Specifies the user for RPC requests and defaults to an empty string.    
	
Sample Windows shortcut:

	javaw.exe -Xmx512m -Djava.library.path=\Bitcoin\JavaBitcoin -jar \Bitcoin\JavaBitcoin\JavaBitcoin.4.0.0.jar PROD
	
Replace javaw.exe with java.exe if you want to run from a command prompt.  This will allow you to view log messages as they occur.

In this example, the leveldbjni.dll file was extracted from the jar file and placed in the \Bitcoin\JavaBitcoin directory.  Specifying java.library.path tells the JVM where to find the native resources.
