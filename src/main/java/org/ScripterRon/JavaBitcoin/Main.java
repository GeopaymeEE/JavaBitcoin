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
import java.util.List;
import java.util.logging.LogManager;
import java.util.Properties;
import javax.swing.*;

/**
 * Main class for the JavaBitcoin peer node
 *
 * The JavaBitcoin peer node accepts blocks from the network, verifies them and then stores them in its
 * database.  It will also relay blocks and transactions to other nodes on the network.
 */
public class Main {

    /** Logger instance */
    public static final Logger log = LoggerFactory.getLogger("org.ScripterRon.JavaBitcoin");

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

    /** Host name */
    private static String hostName;

    /** Listen port */
    private static int listenPort = 8333;

    /** Maximum number of connections */
    private static int maxConnections = 32;

    /** Maximum number of outbound connections */
    private static int maxOutbound = 8;

    /** Database type */
    private static String dbType = "LevelDB";

    /** Migrate the LevelDB database to the H2 database */
    private static boolean migrateDatabase = false;

    /** Load block chain */
    private static boolean loadBlockChain = false;

    /** Retry block */
    private static boolean retryBlock = false;

    /** Bypass block verification */
    private static boolean verifyBlocks = true;

    /** Block chain data directory for load */
    private static String blockChainPath;

    /** Starting block number */
    private static int startBlock;

    /** Stop block number */
    private static int stopBlock;

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
            log.info(String.format("Application data path: %s", dataPath));
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
            // Migrate the LevelDB database to an H2 database
            //
            if (migrateDatabase) {
                MigrateLdb db = new MigrateLdb(dataPath);
                db.migrateDb();
                db.close();
                System.exit(0);
            }
            //
            // Create the block store
            //
            if (dbType.equalsIgnoreCase("leveldb"))
                blockStore = new BlockStoreLdb(dataPath);
            else if (dbType.equalsIgnoreCase("h2"))
                blockStore = new BlockStoreSql(dataPath);
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
            // Compact the database
            //
            blockStore.compactDatabase();
            //
            // Load the block chain from disk and then exit
            //
            if (loadBlockChain) {
                LoadBlockChain.load(blockChainPath, startBlock, stopBlock);
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

            Parameters.networkListener = new NetworkListener(maxConnections, maxOutbound, hostName, listenPort,
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
            javax.swing.SwingUtilities.invokeLater(() -> {
                createAndShowGUI();
            });
        } catch (Throwable exc) {
            log.error(String.format("%s: %s", exc.getClass().getName(), exc.getMessage()));
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
     *
     */
    public static void shutdown() {
        //
        // Stop the worker threads
        //
        try {
            Parameters.networkListener.shutdown();
            Parameters.databaseQueue.put(new ShutdownDatabase());
            Parameters.messageQueue.put(new ShutdownMessage());
            for (Thread thread : threads)
                thread.join(15000);
        } catch (InterruptedException exc) {
            // Nothing to be done at this point
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
            log.error("Unable to release application lock", exc);
        }
        //
        // All done
        //
        System.exit(0);
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
        // MIGRATE indicate we should migrate a LevelDB database to an H2 database
        //
        switch (args[0].toLowerCase()) {
            case "load":
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
                if (args.length > 4) {
                    stopBlock = Integer.parseInt(args[4]);
                    if (stopBlock < startBlock)
                        throw new IllegalArgumentException("Stop block is less than start block");
                } else {
                    stopBlock = Integer.MAX_VALUE;
                }
                if (args.length > 5)
                    throw new IllegalArgumentException("Unrecognized command line parameter");
                break;
            case "migrate":
                migrateDatabase = true;
                if (args.length < 2)
                    throw new IllegalArgumentException("Specify PROD or TEST with the MIGRATE option");
                if (args[1].equalsIgnoreCase("TEST")) {
                    testNetwork = true;
                } else if (!args[1].equalsIgnoreCase("PROD")) {
                    throw new IllegalArgumentException("Specify PROD or TEST after the MIGRATE option");
                }
                if (args.length > 2)
                    throw new IllegalArgumentException("Unrecognized command line parameter");
                break;
            case "retry":
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
                break;
            case "test":
                testNetwork = true;
                if (args.length > 1)
                    throw new IllegalArgumentException("Unrecognized command line parameter");
                break;
            case "prod":
                if (args.length > 1)
                    throw new IllegalArgumentException("Unrecognized command line parameter");
                break;
            default:
                throw new IllegalArgumentException("Unrecognized command line parameter");
        }
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
                    case "dbtype":
                        if (!value.equalsIgnoreCase("leveldb") && !value.equalsIgnoreCase("h2"))
                            throw new IllegalArgumentException("Invalid database type specified");
                        dbType = value;
                        break;
                    case "hostname":
                        hostName = value;
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
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    Main.logException(deferredText, deferredException);
                    deferredException = null;
                    deferredText = null;
                });
            } catch (Exception logexc) {
                log.error(text, exc);
            }
        } else {
            log.error(text, exc);
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
