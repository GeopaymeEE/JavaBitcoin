/**
 * Copyright 2013-2014 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.JavaBitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;

import java.net.UnknownHostException;

import java.nio.channels.FileLock;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.LogManager;
import java.util.Map;
import java.util.Properties;

import javax.swing.*;

/**
 * <p>Main class for the JavaBitcoin peer node</p>
 *
 * <p>The JavaBitcoin peer node accepts blocks from the network, verifies them and then stores them in its
 * database.  It will also relay blocks and transactions to other nodes on the network.</p>
 *
 * <p>If no command-line arguments are provided, we will connect to the production Bitcoin network
 * using DNS discovery.  The production database will be used.</p>
 *
 * <p>The following command-line arguments are supported:</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>INDEX PROD|TEST directory-path</td>
 * <td>Rebuild the block index for an existing database.  Existing block chain files will
 * be read and the file pointers in the database will be updated to point to the new block
 * locations.  The Blocks subdirectory must be empty before starting this operation.</td>
 * 
 * <tr><td>LOAD PROD|TEST directory-path start-block</td>
 * <td>Load the block chain from the reference client data directory and create the block database.  Specify PROD
 * to load the production database or TEST to load the test database.  The
 * reference client default data directory will be used if no directory path is specified.  The database load
 * will start with blk00000.dat if no starting block number is specified.
 * The program will terminate after loading the block chain.</td></tr>
 *
 * <tr><td>PROD</td>
 * <td>Start the program using the production network.  Application files are stored in the application data
 * directory and the production database is used.</td></tr>
 * 
 * <tr><td>REGRESSION</td>
 * <td>Run a regression test using the current production network block chain database.  The transaction
 * signatures will be verified for each block in the chain.  The program will terminate after processing
 * all of the blocks.</td></tr>
 *
 * <tr><td>RETRY PROD|TEST block-hash</td>
 * <td>Retry a block which is currently held.  Specify PROD to use the production database or TEST to use the
 * test database.  The block hash is the 64-character hash for the block to be retried.
 * The program will terminate after the block has been processed.</td></tr>
 *
 * <tr><td>TEST</td>
 * <td>Start the program using the regression test network.  Application files are stored in the TestNet
 * folder in the application data directory and the test database is used.  At least one peer node must
 * be specified in JavaBitcoin.conf since DNS discovery is not supported for the regression test network.</td></tr>
 * </table>
 *
 * <p>The following command-line options can be specified:</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>-Dbitcoin.datadir=directory-path</td>
 * <td>Specifies the application data directory.  Application data will be stored in
 * a system-specific default directory if no data directory is specified:
 *      <ul>
 *      <li>Linux: user-home/.JavaBitcoin</li>
 *      <li>Mac: user-home/Library/Application Support/JavaBitcoin</li>
 *      <li>Windows: user-home\AppData\Roaming\JavaBitcoin</li>
 *      </ul>
 * </td></tr>
 *
 * <tr><td>-Dbitcoin.verify.blocks=n</td>
 * <td>Blocks are normally verified as they are added to the block chain.  Block verification can be disabled
 * to improve performance. Specify 1 to enable verification and 0 to disable verification.
 * The default is 1.</td></tr>
 *
 * <tr><td>-Djava.util.logging.config.file=file-path</td>
 * <td>Specifies the logger configuration file.  The logger properties will be read from 'logging.properties'
 * in the application data directory.  If this file is not found, the 'java.util.logging.config.file' system
 * property will be used to locate the logger configuration file.  If this property is not defined,
 * the logger properties will be obtained from jre/lib/logging.properties.
 *      <ul>
 *      <li>JDK FINE corresponds to the SLF4J DEBUG level</li>
 *      <li>JDK INFO corresponds to the SLF4J INFO level</li>
 *      <li>JDK WARNING corresponds to the SLF4J WARN level</li>
 *      <li>JDK SEVERE corresponds to the SLF4J ERROR level</li>
 *      </ul>
 *  </td></tr>
 * </table>
 *
 * <p>The following configuration options can be specified in JavaBitcoin.conf.  Blank lines and lines beginning
 * with '#' are ignored.</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>connect=[address]:port</td>
 * <td>Connect to the specified peer.  The connect option can be repeated to connect to multiple peers.
 * If one or more connect options are specified, connections will be created to just the listed peers.
 * If no connect option is specified, DNS discovery will be used along with the broadcast peer addresses to create
 * outbound connections.</td></tr>
 *
 * <tr><td>maxconnections=n</td>
 * <td>Specifies the maximum number of inbound and outbound connections and defaults to 32.</td></tr>
 *
 * <tr><td>maxoutbound=n</td>
 * <td>Specifies the maximum number of outbound connections and defaults to 8.</td></tr>
 *
 * <tr><td>port=n</td>
 * <td>Specifies the port for receiving inbound connections and defaults to 8333</td></tr>
 * </table>
 */
public class Main {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    /** File separator */
    public static String fileSeparator;

    /** Line separator */
    public static String lineSeparator;

    /** User home */
    public static String userHome;

    /** Operating system */
    public static String osName;
    
    /** Application identifier */
    public static String applicationID;
    
    /** Application name */
    public static String applicationName;
    
    /** Application version */
    public static String applicationVersion;

    /** Application lock file */
    private static RandomAccessFile lockFile;

    /** Application lock */
    private static FileLock fileLock;

    /** Application properties */
    public static Properties properties;

    /** Main application window */
    public static MainWindow mainWindow;

    /** Data directory */
    public static String dataPath;

    /** Application properties file */
    private static File propFile;

    /** Peer addresses file */
    private static File peersFile;

    /** Test network */
    private static boolean testNetwork = false;

    /** Listen port */
    private static int listenPort = 8333;

    /** Maximum number of connections */
    private static int maxConnections = 32;

    /** Maximum number of outbound connections */
    private static int maxOutbound = 8;

    /** Load block chain */
    private static boolean loadBlockChain = false;
    
    /** Regression test */
    private static boolean regressionTest = false;

    /** Retry block */
    private static boolean retryBlock = false;
    
    /** Rebuild block index */
    private static boolean rebuildIndex = false;

    /** Bypass block verification */
    private static boolean verifyBlocks = true;

    /** Block chain data directory for load */
    private static String blockChainPath;

    /** Starting block number for load */
    private static int startBlock;

    /** Retry block hash */
    private static Sha256Hash retryHash;

    /** Peer address */
    private static PeerAddress[] peerAddresses;

    /** Block store */
    private static BlockStore blockStore;

    /** Block chain */
    private static BlockChain blockChain;

    /** Thread group */
    private static ThreadGroup threadGroup;

    /** Worker threads */
    private static final List<Thread> threads = new ArrayList<>(5);

    /** Database listener */
    private static DatabaseHandler databaseHandler;

    /** Message handlers */
    private static MessageHandler messageHandler;

    /** Deferred exception text */
    private static String deferredText;

    /** Deferred exception */
    private static Throwable deferredException;

    /**
     * The main() method is invoked by the JVM to start the application
     *
     * @param       args            Command-line arguments
     */
    public static void main(String[] args) {
        try {
            fileSeparator = System.getProperty("file.separator");
            lineSeparator = System.getProperty("line.separator");
            userHome = System.getProperty("user.home");
            osName = System.getProperty("os.name").toLowerCase();
            //
            // Process command-line options
            //
            dataPath = System.getProperty("bitcoin.datadir");
            if (dataPath == null) {
                if (osName.startsWith("win"))
                    dataPath = userHome+"\\Appdata\\Roaming\\JavaBitcoin";
                else if (osName.startsWith("linux"))
                    dataPath = userHome+"/.JavaBitcoin";
                else if (osName.startsWith("mac os"))
                    dataPath = userHome+"/Library/Application Support/JavaBitcoin";
                else
                    dataPath = userHome+"/JavaBitcoin";
            }
            String pString = System.getProperty("bitcoin.verify.blocks");
            if (pString != null && pString.equals("0"))
                verifyBlocks = false;
            //
            // Process command-line arguments
            //
            if (args.length != 0)
                processArguments(args);
            if (testNetwork)
                dataPath = dataPath+fileSeparator+"TestNet";
            //
            // Create the data directory if it doesn't exist
            //
            File dirFile = new File(dataPath);
            if (!dirFile.exists())
                dirFile.mkdirs();
            //
            // Initialize the logging properties from 'logging.properties'
            //
            File logFile = new File(dataPath+fileSeparator+"logging.properties");
            if (logFile.exists()) {
                FileInputStream inStream = new FileInputStream(logFile);
                LogManager.getLogManager().readConfiguration(inStream);
            }
            //
            // Use the brief logging format
            //
            BriefLogFormatter.init();
            //
            // Open the application lock file
            //
            lockFile = new RandomAccessFile(dataPath+fileSeparator+".lock", "rw");
            fileLock = lockFile.getChannel().tryLock();
            if (fileLock == null)
                throw new IllegalStateException("JavaBitcoin is already running");
            //
            // Process configuration file options
            //
            processConfig();
            if (testNetwork && peerAddresses == null && maxOutbound != 0)
                throw new IllegalArgumentException("You must specify at least one peer for the test network");
            //
            // Initialize the network parameters
            //
            String genesisName;
            if (testNetwork) {
                Parameters.MAGIC_NUMBER = Parameters.MAGIC_NUMBER_TESTNET;
                Parameters.MAX_TARGET_DIFFICULTY = Parameters.MAX_DIFFICULTY_TESTNET;
                Parameters.GENESIS_BLOCK_HASH = Parameters.GENESIS_BLOCK_TESTNET;
                genesisName = "GenesisBlock/GenesisBlockTest.dat";
            } else {
                Parameters.MAGIC_NUMBER = Parameters.MAGIC_NUMBER_PRODNET;
                Parameters.MAX_TARGET_DIFFICULTY = Parameters.MAX_DIFFICULTY_PRODNET;
                Parameters.GENESIS_BLOCK_HASH = Parameters.GENESIS_BLOCK_PRODNET;
                genesisName = "GenesisBlock/GenesisBlockProd.dat";
            }
            Parameters.PROOF_OF_WORK_LIMIT = Utils.decodeCompactBits(Parameters.MAX_TARGET_DIFFICULTY);
            //
            // Load the genesis block
            //
            Class<?> mainClass = Class.forName("org.ScripterRon.JavaBitcoin.Main");
            try (InputStream classStream = mainClass.getClassLoader().getResourceAsStream(genesisName)) {
                if (classStream == null)
                    throw new IOException("Genesis block resource not found");
                Parameters.GENESIS_BLOCK_BYTES = new byte[classStream.available()];
                classStream.read(Parameters.GENESIS_BLOCK_BYTES);
            }
            //
            // Get the application build properties
            //
            try (InputStream classStream = mainClass.getClassLoader().getResourceAsStream("META-INF/application.properties")) {
                if (classStream == null)
                    throw new IOException("Application build properties not found");
                Properties applicationProperties = new Properties();
                applicationProperties.load(classStream);
                applicationID = applicationProperties.getProperty("application.id");
                applicationName = applicationProperties.getProperty("application.name");
                applicationVersion = applicationProperties.getProperty("application.version");
            }
            Parameters.SOFTWARE_NAME = String.format("/%s:%s/", applicationID, applicationVersion);
            log.info(String.format("%s Version %s", applicationName, applicationVersion));
            log.info(String.format("Application data path: '%s'", dataPath));
            log.info(String.format("Block verification is %s", (verifyBlocks?"enabled":"disabled")));
            //
            // Load the saved application properties
            //
            propFile = new File(dataPath+fileSeparator+"JavaBitcoin.properties");
            properties = new Properties();
            if (propFile.exists()) {
                try (FileInputStream in = new FileInputStream(propFile)) {
                    properties.load(in);
                }
            }
            //
            // Rebuild the block index and then continue to load the block chain
            //
            if (rebuildIndex) {
                blockStore = new BlockStoreLdb(dataPath, true);
                blockStore.rebuildIndex(blockChainPath);
                blockStore.close();
                loadBlockChain = true;
            }
            //
            // Create the block store
            //
            blockStore = new BlockStoreLdb(dataPath, false);
            Parameters.blockStore = blockStore;
            //
            // Create the block chain
            //
            blockChain = new BlockChain(verifyBlocks);
            Parameters.blockChain = blockChain;
            //
            // Retry a held block and then exit
            //
            if (retryBlock) {
                StoredBlock storedBlock = blockStore.getStoredBlock(retryHash);
                if (storedBlock != null) {
                    if (!storedBlock.isOnChain()) {
                        blockChain.updateBlockChain(storedBlock);
                    } else {
                        log.error(String.format("Block is already on the chain\n  Block %s",
                                                retryHash.toString()));
                    }
                } else{
                    log.error(String.format("Block not found\n  Block %s", retryHash.toString()));
                }
                blockStore.close();
                System.exit(0);
            }
            //
            // Run the regression test
            //
            if (regressionTest) {
                txRegressionTest();
                blockStore.close();
                System.exit(0);
            }
            //
            // Compact the database
            //
            blockStore.compactDatabase();
            //
            // Load the block chain from disk and then exit
            //
            if (loadBlockChain) {
                loadBlockChain();
                blockStore.close();
                System.exit(0);
            }
            //
            // Get the peer addresses
            //
            peersFile = new File(String.format("%s%speers.dat", dataPath, fileSeparator));
            if (peersFile.exists()) {
                int peerCount = (int)peersFile.length()/PeerAddress.PEER_ADDRESS_SIZE;
                try (FileInputStream inStream = new FileInputStream(peersFile)) {
                    for (int i=0; i<peerCount; i++) {
                        PeerAddress peerAddress = new PeerAddress(inStream);
                        Parameters.peerAddresses.add(peerAddress);
                        Parameters.peerMap.put(peerAddress, peerAddress);
                    }
                }
            }
            //
            // Start the worker threads
            //
            threadGroup = new ThreadGroup("Workers");

            databaseHandler = new DatabaseHandler();
            Thread thread = new Thread(threadGroup, databaseHandler);
            thread.start();
            threads.add(thread);

            Parameters.networkListener = new NetworkListener(maxConnections, maxOutbound, listenPort,
                                                             peerAddresses);
            thread = new Thread(threadGroup, Parameters.networkListener);
            thread.start();
            threads.add(thread);

            messageHandler = new MessageHandler();
            thread = new Thread(threadGroup, messageHandler);
            thread.start();
            threads.add(thread);
            //
            // Start the GUI
            //
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            javax.swing.SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    createAndShowGUI();
                }
            });
        } catch (Throwable exc) {
            log.error("Exception during program initialization", exc);
        }
    }

    /**
     * Save the application properties
     */
    public static void saveProperties() {
        try {
            try (FileOutputStream out = new FileOutputStream(propFile)) {
                properties.store(out, "JavaBitcoin Properties");
            }
        } catch (Exception exc) {
            Main.logException("Exception while saving application properties", exc);
        }
    }

    /**
     * Create and show our application GUI
     *
     * This method is invoked on the AWT event thread to avoid timing
     * problems with other window events
     */
    private static void createAndShowGUI() {
        try {
            //
            // Use the normal window decorations as defined by the look-and-feel
            // schema
            //
            JFrame.setDefaultLookAndFeelDecorated(true);
            //
            // Create the main application window
            //
            mainWindow = new MainWindow();
            //
            // Show the application window
            //
            mainWindow.pack();
            mainWindow.setVisible(true);
        } catch (Exception exc) {
            Main.logException("Exception while initializing application window", exc);
        }
    }

    /**
     * Shutdown and exit
     */
    public static void shutdown() {
        //
        // Stop the worker threads
        //
        try {
            Parameters.networkListener.shutdown();
            Parameters.databaseQueue.put(new ShutdownDatabase());
            Parameters.messageQueue.put(new ShutdownMessage());
            log.info("Waiting for worker threads to stop");
            for (Thread thread : threads)
                thread.join(2*60*1000);
            log.info("Worker threads have stopped");
        } catch (InterruptedException exc) {
            log.info("Interrupted while waiting for threads to stop");
        }
        //
        // Close the database
        //
        blockStore.close();
        //
        // Save the first 50 peer addresses
        //
        try {
            try (FileOutputStream outStream = new FileOutputStream(peersFile)) {
                int peerCount = 0;
                for (PeerAddress peerAddress : Parameters.peerAddresses) {
                    if (!peerAddress.isStatic()) {
                        outStream.write(peerAddress.getBytes());
                        peerCount++;
                        if (peerCount >= 50)
                            break;
                    }
                }
            }
        } catch (IOException exc) {
            log.error("Unable to save peer addresses", exc);
        }
        //
        // Save the application properties
        //
        saveProperties();
        //
        // Close the application lock file
        //
        try {
            fileLock.release();
            lockFile.close();
        } catch (IOException exc) {
        }
        //
        // All done
        //
        System.exit(0);
    }

    /**
     * Load the block chain from the reference client data directory
     */
    private static void loadBlockChain() {
        int blockCount = 0;
        int heldCount = 0;
        String fileName = null;
        boolean stopLoad = false;
        log.info(String.format("Loading block chain from '%s'", blockChainPath));
        try {
            //
            // Get the block chain file list from the 'blocks' subdirectory sorted by ordinal value
            // (blk00000.dat, blk00001.dat, blk00002.dat, etc).  We will stop when we reach a
            // non-existent file.
            //
            List<File> fileList = new ArrayList<>(150);
            for (int i=startBlock; true; i++) {
                File file = new File(String.format("%s%sblocks%sblk%05d.dat",
                                                   blockChainPath, fileSeparator, fileSeparator, i));
                if (!file.exists())
                    break;
                fileList.add(file);
            }
            //
            // Read the blocks in each file
            //
            // The blocks in the file are separated by 4 bytes containing the network-specific packet magic
            // value.  The next 4 bytes contain the block length in little-endian format.
            //
            byte[] numBuffer = new byte[8];
            byte[] blockBuffer = new byte[Parameters.MAX_BLOCK_SIZE];
            for (File inFile : fileList) {
                fileName = inFile.getName();
                log.info(String.format("Processing block data file %s", fileName));
                try (FileInputStream in = new FileInputStream(inFile)) {
                    while (!stopLoad) {
                        //
                        // Get the magic number and the block length from the input stream.
                        // Stop when we reach the end of the file or the magic number is zero.
                        //
                        int count = in.read(numBuffer);
                        if (count < 8)
                            break;
                        long magic = Utils.readUint32LE(numBuffer, 0);
                        long length = Utils.readUint32LE(numBuffer, 4);
                        if (magic == 0)
                            break;
                        if (magic != Parameters.MAGIC_NUMBER) {
                            log.error(String.format("Block magic number %X is incorrect", magic));
                            throw new IOException("Incorrect file format");
                        }
                        if (length > blockBuffer.length) {
                            log.error(String.format("Block length %d exceeds maximum block size", length));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Read the block from the input stream
                        //
                        count = in.read(blockBuffer, 0, (int)length);
                        if (count != (int)length) {
                            log.error(String.format("Block truncated: Needed %d bytes, Read %d bytes",
                                      (int)length, count));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Create a new block from the serialized byte stream.  Since we are
                        // reading from a trusted input source, we won't waste time verifying blocks
                        // (this also avoids a lot of problems with bad blocks that made it into
                        // the block chain before the rules were tightened)
                        //
                        Block block = new Block(blockBuffer, 0, count, false);
                        //
                        // Add the block to the block store and update the block chain.  Stop
                        // loading blocks if we get 5 consecutive blocks being held (something
                        // is wrong and needs to be investigated)
                        //
                        if (blockStore.isNewBlock(block.getHash())) {
                            if (blockChain.storeBlock(block) == null) {
                              log.info(String.format("Current block was not added to the block chain\n  %s",
                                                     block.getHashAsString()));
                              if (++heldCount >= 5)
                                stopLoad = true;
                            } else {
                                heldCount = 0;
                            }
                        }
                        blockCount++;
                    }
                }
                //
                // Stop loading blocks if we encountered a problem
                //
                if (stopLoad)
                    break;
            }
            //
            // All done
            //
            log.info(String.format("Processed %d blocks", blockCount));
        } catch (IOException exc) {
            log.error(String.format("I/O error reading block chain file %s", fileName), exc);
        } catch (BlockStoreException exc) {
            log.error("Unable to store block in database", exc);
        } catch (VerificationException exc) {
            log.error("Block verification error", exc);
        } catch (Exception exc) {
            log.error("Exception during block chain load", exc);
        }
    }
    
    /**
     * Perform the transaction regression test
     */
    private static void txRegressionTest() {
        log.info("Performing transaction regression test");
        try {
            Map<Sha256Hash, Sha256Hash> txMap = new HashMap<>(5000);
            Sha256Hash chainHead = blockStore.getChainHead();
            Sha256Hash blockHash = Sha256Hash.ZERO_HASH;
            int blockHeight = 0;
            while (true) {
                //
                // Get the next block list
                //
                List<Sha256Hash> chainList = blockStore.getChainList(blockHeight, Sha256Hash.ZERO_HASH);
                //
                // Process each block in the list
                //
                for (Sha256Hash chainHash : chainList) {
                    log.info(String.format("Checking %s", chainHash.toString()));
                    blockHash = chainHash;
                    blockHeight++;
                    Block block = blockStore.getBlock(blockHash);
                    if (block == null) {
                        log.error(String.format("Chain block not found\n  Block %s", blockHash.toString()));
                        throw new BlockStoreException("Chain block not found", blockHash);
                    }
                    List<Transaction> txList = block.getTransactions();
                    //
                    // Process each transaction in the block
                    //
                    for (Transaction tx : txList) {
                        if (tx.isCoinBase())
                            continue;
                        Sha256Hash txHash = tx.getHash();
                        txMap.put(txHash, blockHash);
                        List<TransactionInput> txInputs = tx.getInputs();
                        //
                        // Process each transaction input
                        //
                        for (TransactionInput txInput : txInputs) {
                            OutPoint outPoint = txInput.getOutPoint();
                            Sha256Hash outTxHash = outPoint.getHash();
                            int outTxIndex = outPoint.getIndex();
                            Sha256Hash outBlockHash = txMap.get(outTxHash);
                            if (outBlockHash == null) {
                                log.error(String.format("Connected output transaction not found\n"+
                                                        "  Input Tx: %s\n  Input Index: %d\n"+
                                                        "  Output Tx: %s\n  Output Index: %d\n",
                                                        txHash.toString(), txInput.getIndex(),
                                                        outTxHash.toString(), outTxIndex));
                                throw new VerificationException("Connected output transaction not found", txHash);
                            }
                            Block outBlock = blockStore.getBlock(outBlockHash);
                            if (outBlock == null) {
                                log.error(String.format("Connected output block not found\n  Block %s", 
                                                        outBlockHash.toString()));
                                throw new BlockStoreException("Connected output block not found", outBlockHash);
                            }
                            List<Transaction> outTxList = outBlock.getTransactions();
                            Transaction outTx = null;
                            for (Transaction checkTx : outTxList) {
                                if (checkTx.getHash().equals(outTxHash)) {
                                    outTx = checkTx;
                                    break;
                                }
                            }
                            if (outTx == null) {
                                log.error(String.format("Connected output transaction not found in block\n  Tx %s",
                                                        outTxHash.toString()));
                                throw new BlockStoreException("Connected output transaction not found", outTxHash);
                            }
                            List<TransactionOutput> txOutputs = outTx.getOutputs();
                            if (outTxIndex >= txOutputs.size()) {
                                log.error(String.format("Connected output index %d is invalid\n  Tx", 
                                                        outTxIndex, txHash.toString()));
                                throw new VerificationException("Connected output index is invalid", txHash);
                            }
                            TransactionOutput txOutput = txOutputs.get(outTxIndex);
                            StoredOutput output = new StoredOutput(outTxIndex, txOutput.getValue(),
                                                                   txOutput.getScriptBytes(), outTx.isCoinBase());
                            boolean isValid = tx.verifyInput(txInput, output);
                            if (!isValid) {
                                log.error(String.format("Signature verification failed\n"+
                                                        "  Input Tx: %s\n  Input Index: %d\n"+
                                                        "  Output Tx: %s\n  Output Index: %d",
                                                        txHash.toString(), txInput.getIndex(),
                                                        outTxHash.toString(), outTxIndex));
                                throw new VerificationException("Signature verification failed", txHash);
                            }
                        }
                    }
                }
                //
                // Stop if we have processed the chain head
                //
                if (blockHash.equals(chainHead))
                    break;
            }
        } catch (BlockStoreException exc) {
            log.error(String.format("Unable to retrieve data\n  Hash %s", exc.getHash()), exc);
        } catch (VerificationException exc) {
            log.error(String.format("Unable to verify transaction\n  Tx %s", exc.getHash()), exc);
        } catch (Exception exc) {
            log.error("Exception during transaction regression test", exc);
        }
        log.info("Transaction regression test completed");
    }

    /**
     * Parses the command-line arguments
     *
     * @param       args                        Command-line arguments
     * @throws      IllegalArgumentException    Unrecognized or invalid command argument
     * @throws      UnknownHostException        Incorrect peer address format
     */
    private static void processArguments(String[] args) throws UnknownHostException {
        //
        // PROD indicates we should use the production network
        // TEST indicates we should use the test network
        // LOAD indicates we should load the block chain from the reference client data directory
        // RETRY indicates we should retry a block that is currently held
        // INDEX indicates we should rebuild the block index
        // REGRESSION indicate we should run a transaction regression test
        //
        if (args[0].equalsIgnoreCase("LOAD")) {
            loadBlockChain = true;
            if (args.length < 2)
                throw new IllegalArgumentException("Specify PROD or TEST with the LOAD option");
            if (args[1].equalsIgnoreCase("TEST")) {
                testNetwork = true;
            } else if (!args[1].equalsIgnoreCase("PROD")) {
                throw new IllegalArgumentException("Specify PROD or TEST after the LOAD option");
            }
            if (args.length > 2) {
                blockChainPath = args[2];
            } else if (osName.startsWith("win")) {
                blockChainPath = userHome+"\\AppData\\Roaming\\Bitcoin";
            } else if (osName.startsWith("linux")) {
                blockChainPath = userHome+"/.bitcoin";
            } else if (osName.startsWith("mac os")) {
                blockChainPath = userHome+"/Library/Application Support/Bitcoin";
            } else {
                blockChainPath = userHome+"/Bitcoin";
            }
            if (args.length > 3) {
                startBlock = Integer.parseInt(args[3]);
            } else {
                startBlock = 0;
            }
            if (args.length > 4)
                throw new IllegalArgumentException("Unrecognized command line parameter");
            return;
        }
        if (args[0].equalsIgnoreCase("RETRY")) {
            retryBlock = true;
            if (args.length < 3)
                throw new IllegalArgumentException("Specify PROD or TEST followed by the block hash");
            if (args[1].equalsIgnoreCase("TEST")) {
                testNetwork = true;
            } else if (!args[1].equalsIgnoreCase("PROD")) {
                throw new IllegalArgumentException("Specify PROD or TEST after the RETRY option");
            }
            retryHash = new Sha256Hash(args[2]);
            if (args.length > 3)
                throw new IllegalArgumentException("Unrecognized command line parameter");
            return;
        }
        if (args[0].equalsIgnoreCase("INDEX")) {
            rebuildIndex = true;
            if (args.length < 2)
                throw new IllegalArgumentException("Specify PROD or TEST with the INDEX option");
            if (args[1].equalsIgnoreCase("TEST")) {
                testNetwork = true;
            } else if (!args[1].equalsIgnoreCase("PROD")) {
                throw new IllegalArgumentException("Specify PROD or TEST after the INDEX option");
            }
            if (args.length > 2) {
                blockChainPath = args[2];
            } else if (osName.startsWith("win")) {
                blockChainPath = userHome+"\\AppData\\Roaming\\Bitcoin";
            } else if (osName.startsWith("linux")) {
                blockChainPath = userHome+"/.bitcoin";
            } else if (osName.startsWith("mac os")) {
                blockChainPath = userHome+"/Library/Application Support/Bitcoin";
            } else {
                blockChainPath = userHome+"/Bitcoin";
            }
            if (args.length > 3)
                throw new IllegalArgumentException("Unrecognized command line parameter");
            return;
        }
        if (args[0].equalsIgnoreCase("REGRESSION")) {
            regressionTest = true;
            if (args.length > 1)
                throw new IllegalArgumentException("Unrecognized command line parameter");
            return;
        }
        if (args[0].equalsIgnoreCase("TEST")) {
            testNetwork = true;
        } else if (!args[0].equalsIgnoreCase("PROD")) {
            throw new IllegalArgumentException("Valid options are LOAD, RETRY, PROD and TEST");
        }
        if (args.length > 1)
            throw new IllegalArgumentException("Unrecognized command line parameter");
    }

    /**
     * Process the configuration file
     *
     * @throws      IllegalArgumentException    Invalid configuration option
     * @throws      IOException                 Unable to read configuration file
     * @throws      UnknownHostException        Invalid peer address specified
     */
    private static void processConfig() throws IOException, IllegalArgumentException, UnknownHostException {
        //
        // Use the defaults if there is no configuration file
        //
        File configFile = new File(dataPath+Main.fileSeparator+"JavaBitcoin.conf");
        if (!configFile.exists())
            return;
        //
        // Process the configuration file
        //
        List<PeerAddress> addressList = new ArrayList<>(5);
        try (BufferedReader in = new BufferedReader(new FileReader(configFile))) {
            String line;
            while ((line=in.readLine()) != null) {
                line = line.trim();
                if (line.length() == 0 || line.charAt(0) == '#')
                    continue;
                int sep = line.indexOf('=');
                if (sep < 1)
                    throw new IllegalArgumentException(String.format("Invalid configuration option: %s", line));
                String option = line.substring(0, sep).trim().toLowerCase();
                String value = line.substring(sep+1).trim();
                switch (option) {
                    case "connect":
                        PeerAddress addr = new PeerAddress(value);
                        addressList.add(addr);
                        break;
                    case "maxconnections":
                        maxConnections = Integer.parseInt(value);
                        break;
                    case "maxoutbound":
                        maxOutbound = Integer.parseInt(value);
                        break;
                    case "port":
                        listenPort = Integer.parseInt(value);
                        break;
                    default:
                        throw new IllegalArgumentException(String.format("Invalid configuration option: %s", line));
                }
            }
        }
        if (!addressList.isEmpty())
            peerAddresses = addressList.toArray(new PeerAddress[addressList.size()]);
    }

    /**
     * Display a dialog when an exception occurs.
     *
     * @param       text        Text message describing the cause of the exception
     * @param       exc         The Java exception object
     */
    public static void logException(String text, Throwable exc) {
        if (SwingUtilities.isEventDispatchThread()) {
            StringBuilder string = new StringBuilder(512);
            //
            // Display our error message
            //
            string.append("<html><b>");
            string.append(text);
            string.append("</b><br><br>");
            //
            // Display the exception object
            //
            string.append(exc.toString());
            string.append("<br>");
            //
            // Display the stack trace
            //
            StackTraceElement[] trace = exc.getStackTrace();
            int count = 0;
            for (StackTraceElement elem : trace) {
                string.append(elem.toString());
                string.append("<br>");
                if (++count == 25)
                    break;
            }
            string.append("</html>");
            JOptionPane.showMessageDialog(Main.mainWindow, string, "Error", JOptionPane.ERROR_MESSAGE);
        } else if (deferredException == null) {
            deferredText = text;
            deferredException = exc;
            try {
                javax.swing.SwingUtilities.invokeAndWait(new Runnable() {
                    @Override
                    public void run() {
                        Main.logException(deferredText, deferredException);
                        deferredException = null;
                        deferredText = null;
                    }
                });
            } catch (Exception logexc) {
                log.error("Unable to log exception during program initialization");
            }
        }
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     */
    public static void dumpData(String text, byte[] data) {
        dumpData(text, data, 0, data.length);
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       length      Length to dump
     */
    public static void dumpData(String text, byte[] data, int length) {
        dumpData(text, data, 0, length);
    }

    /**
     * Dump a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       offset      Offset into array
     * @param       length      Data length
     */
    public static void dumpData(String text, byte[] data, int offset, int length) {
        StringBuilder outString = new StringBuilder(512);
        outString.append(text);
        outString.append("\n");
        for (int i=0; i<length; i++) {
            if (i%32 == 0)
                outString.append(String.format(" %14X  ", i));
            else if (i%4 == 0)
                outString.append(" ");
            outString.append(String.format("%02X", data[offset+i]));
            if (i%32 == 31)
                outString.append("\n");
        }
        if (length%32 != 0)
            outString.append("\n");
        log.info(outString.toString());
    }
}
