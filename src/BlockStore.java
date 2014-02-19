/**
 * Copyright 2013 Ronald W Hoffman
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
package JavaBitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * <p>BlockStore manages the SQL database containing the block chain information.  The database is
 * periodically pruned to reduce storage requirements by removing transactions with completely-spent outputs.</p>
 *
 * <p>The block files are named 'blknnnnn.dat' and are stored in the 'Blocks' subdirectory.  A new
 * block is added to the end of the current block file.  When the file reaches the maximum size,
 * the file number is incremented and a new block file is created.</p>
 *
 * <p>The Settings table contains application control information</p>
 * <pre>
 *   Column             Definition          Description
 *   ======             ==========          ===========
 *   schemaName         VARCHAR(32)         Schema name
 *   schemaVersion      INTEGER             Schema version
 *   fileNumber         INTEGER             Current block file number
 * </pre>
 *
 * <p>The Blocks table contains the blocks that have been received and includes
 * orphan blocks as well as chain blocks.  The actual block data is stored in a file
 * in the Block subdirectory.</p>
 * <pre>
 *   Column             Definition          Description
 *   ======             ==========          ===========
 *   blockHash          BYTEA               Block hash
 *   prevHash           BYTEA               Previous block hash
 *   timeStamp          BIGINT              Block timestamp
 *   blockHeight        INTEGER             Block height (if block is on block chain)
 *   chainWork          BYTEA               Chain work (if block is on block chain)
 *   onChain            BOOLEAN             TRUE if the block is on the block chain
 *   onHold             BOOLEAN             TRUE if the block is held
 *   fileNumber         INTEGER             Block file number containing this block
 *   fileOffset         INTEGER             Block file offset for this block
 * </pre>
 *
 * <p>The TxOutputs table contains the transaction outputs.  A transaction is not added
 * to the table until the block containing the transaction is added to the block chain.
 * A transaction will be removed from the table if the corresponding block is
 * removed from the block chain during a block chain reorganization.  Spent outputs
 * are periodically deleted when the age limit has been exceeded.</p>
 * <pre>
 *   Column             Definition                  Description
 *   ======             ==========                  ===========
 *   txHash             BYTEA               Transaction hash
 *   txIndex            INTEGER             Transaction output index
 *   blockHash          BYTEA               Block containing this transaction
 *   blockHeight        INTEGER             Chain height of block spending this output
 *   timeSpent          BIGINT              Time this output was spent
 *   value              BYTEA               Value of this output
 *   scriptBytes        BYTEA               Script bytes
 * </pre>
 *
 * <p>The Alerts table contains alerts that have been broadcast by the developers.
 * An alert remains active until its expiration time is reached or it is canceled
 * by a subsequent alert.</p>
 * <pre>
 *   Column             Definition          Description
 *   ======             ==========          ===========
 *   AlertID            INTEGER             Alert identifier
 *   isCanceled         BOOLEAN             TRUE if alert has been canceled
 *   payload            BYTEA               Alert payload
 *   signature          BYTEA               Alert signature
 * </pre>
 */
public class BlockStore {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(BlockStore.class);

    /** Maximum block file size */
    private static final long MAX_BLOCK_FILE_SIZE = 256 * 1024 * 1024;

    /** Maximum age (seconds) of spent transactions in the transaction outputs table */
    private static final long MAX_TX_AGE = 1 * 24 * 60 * 60;

    /** Block chain checkpoints */
    private static final Map<Integer, Sha256Hash> checkpoints = new HashMap<>();
    static {
        checkpoints.put(Integer.valueOf(50000),
                        new Sha256Hash("000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a"));
        checkpoints.put(Integer.valueOf(75000),
                        new Sha256Hash("00000000000ace2adaabf1baf9dc0ec54434db11e9fd63c1819d8d77df40afda"));
        checkpoints.put(Integer.valueOf(91722),
                        new Sha256Hash("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
        checkpoints.put(Integer.valueOf(91812),
                        new Sha256Hash("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
        checkpoints.put(Integer.valueOf(91842),
                        new Sha256Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
        checkpoints.put(Integer.valueOf(91880),
                        new Sha256Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        checkpoints.put(Integer.valueOf(100000),
                        new Sha256Hash("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"));
        checkpoints.put(Integer.valueOf(125000),
                        new Sha256Hash("00000000000042391c3620056af66ca9ad7cb962424a9b34611915cebb9e1a2a"));
        checkpoints.put(Integer.valueOf(150000),
                        new Sha256Hash("0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"));
        checkpoints.put(Integer.valueOf(175000),
                        new Sha256Hash("00000000000006b975c097e9a5235de03d9024ddb205fd24dfcd508403fa907c"));
        checkpoints.put(Integer.valueOf(200000),
                        new Sha256Hash("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));
        checkpoints.put(Integer.valueOf(225000),
                        new Sha256Hash("000000000000013d8781110987bf0e9f230e3cc85127d1ee752d5dd014f8a8e1"));
        checkpoints.put(Integer.valueOf(250000),
                        new Sha256Hash("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"));
        checkpoints.put(Integer.valueOf(275000),
                        new Sha256Hash("00000000000000044750d80a0d3f3e307e54e8802397ae840d91adc28068f5bc"));
    }

   /** Settings table definition */
    private static final String Settings_Table = "CREATE TABLE Settings ("+
            "schemaName         CHARACTER VARYING(32)   NOT NULL,"+
            "schemaVersion      INTEGER                 NOT NULL,"+
            "fileNumber         INTEGER                 NOT NULL)";

    /** Blocks table definition */
    private static final String Blocks_Table = "CREATE TABLE Blocks ("+
            "blockHash          BYTEA                   NOT NULL PRIMARY KEY,"+
            "prevHash           BYTEA                   NOT NULL,"+
            "timeStamp          BIGINT                  NOT NULL,"+
            "blockHeight        INTEGER                 NOT NULL,"+
            "chainWork          BYTEA                   NOT NULL,"+
            "onHold             BOOLEAN                 NOT NULL,"+
            "onChain            BOOLEAN                 NOT NULL,"+
            "fileNumber         INTEGER                 NOT NULL,"+
            "fileOffset         INTEGER                 NOT NULL)";
    private static final String Blocks_IX1 = "CREATE INDEX Blocks_IX1 ON Blocks(blockHeight)";

    /** TxOutputs table definition */
    private static final String TxOutputs_Table = "CREATE TABLE TxOutputs ("+
            "txHash             BYTEA                   NOT NULL,"+
            "txIndex            INTEGER                 NOT NULL,"+
            "blockHash          BYTEA                   NOT NULL,"+
            "blockHeight        INTEGER                 NOT NULL,"+
            "timeSpent          BIGINT                  NOT NULL,"+
            "value              BYTEA                   NOT NULL,"+
            "scriptBytes        BYTEA                   NOT NULL)";
    private static final String TxOutputs_IX1 = "CREATE UNIQUE INDEX TxOutputs_IX1 ON TxOutputs(txHash,txIndex)";

    /** Alerts table definition */
    private static final String Alerts_Table = "CREATE TABLE Alerts ("+
            "alertID            INTEGER                 NOT NULL PRIMARY KEY,"+
            "isCanceled         BOOLEAN                 NOT NULL,"+
            "payload            BYTEA                   NOT NULL,"+
            "signature          BYTEA                   NOT NULL)";

    /** Database schema name */
    private static final String schemaName = "JavaBitcoin Block Store";

    /** Database schema version */
    private static final int schemaVersion = 100;

    /** Database update lock */
    private final Object lock = new Object();

    /** Application data path */
    private String dataPath;

    /** Chain update time */
    private long chainTime;

    /** Chain head */
    private Sha256Hash chainHead;

    /** Block preceding the chain head */
    private Sha256Hash prevChainHead;

    /** Target difficulty */
    private long targetDifficulty;

    /** Current chain height */
    private int chainHeight;

    /** Current chain work */
    private BigInteger chainWork;

    /** Current block file number */
    private int blockFileNumber;

    /** Per-thread database connection */
    private ThreadLocal<Connection> threadConnection;

    /** List of all database connections */
    private List<Connection> allConnections;

    /** Database connection URL */
    private String connectionURL;

    /** Database connection user */
    private String connectionUser;

    /** Database connection password */
    private String connectionPassword;

    /**
     * Creates a BlockStore using the PostgresQL database
     *
     * @param       dataPath            Application data path
     * @param       dbName              Database name
     * @throws      BlockStoreException Unable to initialize the database
     */
    public BlockStore(String dataPath, String dbName) throws BlockStoreException {
        this.dataPath = dataPath;
        //
        // Create the Blocks subdirectory if it doesn't exist
        //
        File blocksDir = new File(dataPath+"\\Blocks");
        if (!blocksDir.exists())
            blocksDir.mkdirs();
        //
        // We will use the PostgreSQL database
        //
        connectionURL = "jdbc:postgresql://127.0.0.1:8335/"+dbName;
        connectionUser = "javabtc";
        connectionPassword = "btcnode";
        //
        // We will use a separate database connection for each thread
        //
        threadConnection = new ThreadLocal<>();
        allConnections = new ArrayList<>();
        //
        // Load the JDBC driver (Jaybird)
        //
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException exc) {
            log.error("Unable to load the JDBC driver", exc);
            throw new BlockStoreException("Unable to load the JDBC driver");
        }
        //
        // Initialize the database
        //
        if (tableExists("Settings")) {
            getSettings();
        } else {
            createTables();
            initTables();
        }
    }

    /**
     * Closes the database
     */
    public void close() {
        //
        // Close all database connections
        //
        for (Connection c : allConnections) {
            try {
                c.close();
            } catch (SQLException exc) {
                log.error("SQL error while closing connections", exc);
            }
        }
        allConnections.clear();
    }

    /**
     * Checks the database connection for the current thread and gets a
     * new connection if necessary
     *
     * @return      Connection for the current thread
     * @throws      BlockStoreException Unable to obtain a database connection
     */
    private Connection checkConnection() throws BlockStoreException {
        //
        // Nothing to do if we already have a connection for this thread
        //
        Connection conn = threadConnection.get();
        if (conn != null)
            return conn;
        //
        // Set up a new connection
        //
        synchronized (lock) {
            try {
                threadConnection.set(
                        DriverManager.getConnection(connectionURL, connectionUser, connectionPassword));
                conn = threadConnection.get();
                allConnections.add(conn);
                log.info(String.format("New connection created to SQL database %s", connectionURL));
            } catch (SQLException exc) {
                log.error(String.format("Unable to connect to SQL database %s", connectionURL), exc);
                throw new BlockStoreException("Unable to connect to SQL database");
            }
        }
        return conn;
    }

    /**
     * Rollback the current transaction and turn auto commit back on
     *
     * @param       stmt            Statement to be closed or null
     */
    private void rollback(AutoCloseable... stmts) {
        try {
            Connection conn = checkConnection();
            for (AutoCloseable stmt : stmts)
                if (stmt != null)
                    stmt.close();
            conn.rollback();
            conn.setAutoCommit(true);
        } catch (Exception exc) {
            log.error("Unable to rollback transaction", exc);
        }
    }

    /**
     * Returns the block hash for the current chain head
     *
     * @return      Chain head block hash
     */
    public Sha256Hash getChainHead() {
        return chainHead;
    }

    /**
     * Returns the current chain height
     *
     * @return      Current chain height
     */
    public int getChainHeight() {
        return chainHeight;
    }

    /**
     * Returns the current target difficulty as a BigInteger
     *
     * @return      Target difficulty
     */
    public BigInteger getTargetDifficulty() {
        return Utils.decodeCompactBits(targetDifficulty);
    }

    /**
     * Returns the current chain work
     *
     * @return      Current chain work
     */
    public BigInteger getChainWork() {
        return chainWork;
    }

    /**
     * Checks if the block is already in our database
     *
     * @param       block               The block to check
     * @return                          TRUE if this is a new block
     * @throws      BlockStoreException Unable to check the block status
     */
    public boolean isNewBlock(Block block) throws BlockStoreException {
        return isNewBlock(block.getHash());
    }

    /**
     * Checks if the block is already in our database
     *
     * @param       blockHash           The block to check
     * @return                          TRUE if this is a new block
     * @throws      BlockStoreException Unable to check the block status
     */
    public boolean isNewBlock(Sha256Hash blockHash) throws BlockStoreException {
        boolean isNewBlock;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "SELECT onChain FROM Blocks WHERE blockHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                r = s.executeQuery();
                if (r.next())
                    isNewBlock = false;
                else
                    isNewBlock = true;
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to check block status\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return isNewBlock;
    }

    /**
     * Checks if the alert is already in our database
     *
     * @param       alertID             Alert identifier
     * @return                          TRUE if this is a new alert
     * @throws      BlockStoreException Unable to get the alert status
     */
    public boolean isNewAlert(int alertID) throws BlockStoreException {
        boolean isNewAlert;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "SELECT isCanceled FROM Alerts WHERE alertID=?")) {
                s.setInt(1,alertID);
                r = s.executeQuery();
                if (r.next())
                    isNewAlert = false;
                else
                    isNewAlert = true;
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to check alert status for %d", alertID), exc);
            throw new BlockStoreException("Unable to check alert status");
        }
        return isNewAlert;
    }

    /**
     * Returns a list of all alerts in the database
     *
     * @return                          List of all alerts
     * @throws      BlockStoreException Unable to get alerts from database
     */
    public List<Alert> getAlerts() throws BlockStoreException {
        List<Alert> alertList = new LinkedList<>();
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (Statement s = conn.createStatement()) {
                r = s.executeQuery("SELECT alertID,isCanceled,payload,signature FROM Alerts "+
                                                        "ORDER BY alertID");
                while (r.next()) {
                    boolean isCanceled = r.getBoolean(2);
                    byte[] payload = r.getBytes(3);
                    byte[] signature = r.getBytes(4);
                    Alert alert = new Alert(payload, signature);
                    alert.setCancel(isCanceled);
                    alertList.add(alert);
                }
                r.close();
            }
        } catch (IOException | SQLException exc) {
            log.error("Unable to build alert list", exc);
            throw new BlockStoreException("Unable to build alert list");
        }
        return alertList;
    }

    /**
     * Stores an alert in the database
     *
     * @param       alert               The alert
     * @throws      BlockStoreException Unable to store the alert
     */
    public void storeAlert(Alert alert) throws BlockStoreException {
        try {
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "INSERT INTO Alerts(alertID,isCanceled,payload,signature) "+
                                        "VALUES(?,false,?,?)")) {
                s.setInt(1, alert.getID());
                s.setBytes(2, alert.getPayload());
                s.setBytes(3, alert.getSignature());
                s.executeUpdate();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to store alert %d", alert.getID()), exc);
            throw new BlockStoreException("Unable to store alert");
        }
    }

    /**
     * Cancels an alert
     *
     * @param       alertID             The alert identifier
     * @throws      BlockStoreException Unable to update the alert
     */
    public void cancelAlert(int alertID) throws BlockStoreException {
        try {
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "UPDATE Alerts SET isCanceled=true WHERE alertID=?")) {
                s.setInt(1, alertID);
                s.executeUpdate();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to cancel alert %d", alertID), exc);
            throw new BlockStoreException("Unable to cancel alert");
        }
    }

    /**
     * Checks if the block is on the main chain
     *
     * @param       blockHash           The block to check
     * @return                          TRUE if the block is on the main chain
     * @throws      BlockStoreException Unable to get the block status
     */
    public boolean isOnChain(Sha256Hash blockHash) throws BlockStoreException {
        boolean onChain;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "SELECT onChain from Blocks WHERE blockHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                r = s.executeQuery();
                if (r.next())
                    onChain = r.getBoolean(1);
                else
                    onChain = false;
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to check block status\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return onChain;
    }

    /**
     * Returns a block that was stored in the database.  The returned block represents the
     * block data sent over the wire and does not include any information about the
     * block location within the block chain.
     *
     * @param       blockHash           Block hash
     * @return                          The block or null if the block is not found
     * @throws      BlockStoreException Unable to get block from database
     */
    public Block getBlock(Sha256Hash blockHash) throws BlockStoreException {
        Block block = null;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                        "SELECT fileNumber, fileOffset FROM Blocks WHERE blockHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                r = s.executeQuery();
                if (r.next()) {
                    int fileNumber = r.getInt(1);
                    int fileOffset = r.getInt(2);
                    block = getBlock(fileNumber, fileOffset);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get block\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to get block", blockHash);
        }
        return block;
    }

    /**
     * Returns a block that was stored in the database.  The returned block contains
     * the basic block plus information about its current location within the block chain.
     *
     * @param       blockHash           The block hash
     * @return                          The stored block or null if the block is not found
     * @throws      BlockStoreException Unable to get block from database
     */
    public StoredBlock getStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock storedBlock = null;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                        "SELECT blockHeight,chainWork,onChain,onHold,fileNumber,fileOffset "+
                                                    "FROM Blocks WHERE blockHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                r = s.executeQuery();
                if (r.next()) {
                    int blockHeight = r.getInt(1);
                    BigInteger blockWork = new BigInteger(r.getBytes(2));
                    boolean onChain = r.getBoolean(3);
                    boolean onHold = r.getBoolean(4);
                    int fileNumber = r.getInt(5);
                    int fileOffset = r.getInt(6);
                    Block block = getBlock(fileNumber, fileOffset);
                    storedBlock = new StoredBlock(block, blockWork, blockHeight, onChain, onHold);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get block\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to get block", blockHash);
        }
        return storedBlock;
    }

    /**
     * Returns the child block for the specified block
     *
     * @param       blockHash           The block hash
     * @return                          The stored block or null if the block is not found
     * @throws      BlockStoreException Unable to get block
     */
    public StoredBlock getChildStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock childStoredBlock = null;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                                    "SELECT blockHeight,chainWork,onChain,onHold,fileNumber,fileOffset "+
                                    "FROM Blocks WHERE prevHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                r = s.executeQuery();
                if (r.next()) {
                    int blockHeight = r.getInt(1);
                    BigInteger blockWork = new BigInteger(r.getBytes(2));
                    boolean onChain = r.getBoolean(3);
                    boolean onHold = r.getBoolean(4);
                    int fileNumber = r.getInt(5);
                    int fileOffset = r.getInt(6);
                    Block block = getBlock(fileNumber, fileOffset);
                    childStoredBlock = new StoredBlock(block, blockWork, blockHeight, onChain, onHold);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get child block\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to get child block", blockHash);
        }
        return childStoredBlock;
    }

    /**
     * Returns the block status for the most recent blocks
     *
     * @param       maxCount            The maximum number of blocks to be returned
     * @return                          A list of BlockStatus objects
     * @throws      BlockStoreException Unable to get block status
     */
    public List<BlockStatus> getBlockStatus(int maxCount) throws BlockStoreException {
        List<BlockStatus> blockList = new LinkedList<>();
        try {
            Connection conn = checkConnection();
            ResultSet r;
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT blockHash,timeStamp,blockHeight,onChain,onHold FROM Blocks "+
                                        "ORDER BY timeStamp DESC LIMIT ?")) {
                s.setInt(1, maxCount);
                r = s.executeQuery();
                while (r.next()) {
                    Sha256Hash blockHash = new Sha256Hash(r.getBytes(1));
                    long timeStamp = r.getLong(2);
                    int blockHeight = r.getInt(3);
                    boolean onChain = r.getBoolean(4);
                    boolean onHold = r.getBoolean(5);
                    BlockStatus status = new BlockStatus(blockHash, timeStamp, blockHeight, onChain, onHold);
                    blockList.add(status);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error("Unable to get block status", exc);
            throw new BlockStoreException("Unable to get block status");
        }
        return blockList;
    }

    /**
     * Returns the outputs for the specified transaction
     *
     * @param       txHash              Transaction hash
     * @return                          Stored output list or null if the transaction is not found
     * @throws      BlockStoreException Unable to get transaction outputs
     */
    public List<StoredOutput> getTxOutputs(Sha256Hash txHash) throws BlockStoreException {
        List<StoredOutput> outputList = new LinkedList<>();
        try {
            Connection conn = checkConnection();
            ResultSet r;
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT txIndex,timeSpent,value,scriptBytes,blockHeight FROM TxOutputs "+
                                    "WHERE txHash=? ORDER BY txIndex ASC")) {
                s.setBytes(1, txHash.getBytes());
                r = s.executeQuery();
                while (r.next()) {
                    int txIndex = r.getInt(1);
                    long timeSpent = r.getLong(2);
                    BigInteger value = new BigInteger(r.getBytes(3));
                    byte[] scriptBytes = r.getBytes(4);
                    int blockHeight = r.getInt(5);
                    StoredOutput output = new StoredOutput(txIndex, value, scriptBytes, timeSpent!=0 ? true : false,
                                                           blockHeight);
                    outputList.add(output);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get transaction outputs\n  %s", txHash.toString()), exc);
            throw new BlockStoreException("Unable to get transaction outputs", txHash);
        }
        return outputList;
    }

    /**
     * Returns the chain list from the block following the start block up to the stop
     * block.  A maximum of 500 blocks will be returned.  The list will start with the
     * genesis block if the start block is not found.
     *
     * @param       startBlock          The start block
     * @param       stopBlock           The stop block
     * @return                          Block hash list
     * @throws      BlockStoreException Unable to get blocks from database
     */
    public List<Sha256Hash> getChainList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                        throws BlockStoreException {
        //
        // Get the block height for the start block
        //
        int blockHeight = 0;
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT blockHeight,onChain FROM Blocks WHERE blockHash=?")) {
                s.setBytes(1, startBlock.getBytes());
                r = s.executeQuery();
                if (r.next()) {
                    if (r.getBoolean(2))
                        blockHeight = r.getInt(1);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get start block\n  %s", startBlock.toString()), exc);
            throw new BlockStoreException("Unable to get start block", startBlock);
        }
        //
        // If we found the start block, we will start at the block following it.  Otherwise,
        // we will start with the block following the genesis block.
        //
        return getChainList(blockHeight, stopBlock);
    }

    /**
     * Returns the chain list from the block following the start block up to the stop
     * block.  A maximum of 500 blocks will be returned.
     *
     * @param       startHeight         Start block height
     * @param       stopBlock           Stop block
     * @return                          Block hash list
     * @throws      BlockStoreException Unable to get blocks from database
     */
    public List<Sha256Hash> getChainList(int startHeight, Sha256Hash stopBlock)
                                        throws BlockStoreException {
        List<Sha256Hash> chainList = new LinkedList<>();
        //
        // Get the chain list starting at the block following the start block and continuing
        // for a maximum of 500 blocks.
        //
        try {
            ResultSet r;
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT blockHash,blockHeight FROM Blocks "+
                                        "WHERE onChain=true AND blockHeight>? AND blockHeight<=? "+
                                        "ORDER BY blockHeight ASC")) {
                s.setInt(1, startHeight);
                s.setInt(2, startHeight+500);
                r = s.executeQuery();
                while (r.next()) {
                    Sha256Hash blockHash = new Sha256Hash(r.getBytes(1));
                    chainList.add(blockHash);
                    if (blockHash.equals(stopBlock))
                        break;
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error("Unable to get the chain list", exc);
            throw new BlockStoreException("Unable to get the chain list");
        }
        return chainList;
    }

    /**
     * Returns the header list from the block following the start block up to the stop
     * block.  A maximum of 2000 blocks will be returned.  The list will start with the
     * genesis block if the start block is not found.  The returned header will include
     * the block header plus the encoded transaction count.
     *
     * @param       startBlock          The start block
     * @param       stopBlock           The stop block
     * @return                          Block header list (includes the transaction count)
     * @throws      BlockStoreException Unable to get data from the database
     */
    public List<byte[]> getHeaderList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                        throws BlockStoreException {
        List<byte[]> headerList = new LinkedList<>();
        //
        // Get the start block
        //
        int blockHeight = 0;
        try {
            Connection conn = checkConnection();
            ResultSet r;
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT blockHeight,onChain FROM Blocks WHERE blockHash=?")) {
                s.setBytes(1, startBlock.getBytes());
                r = s.executeQuery();
                if (r.next()) {
                    if (r.getBoolean(2))
                        blockHeight = r.getInt(1);
                }
                r.close();
            }
            //
            // If we found the start block, we will start at the block following it.  Otherwise,
            // we will start at the block following the genesis block.
            //
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT fileNumber,fileOffset,blockHeight FROM Blocks "+
                                    "WHERE onChain=true AND blockHeight>? AND blockHeight<=? "+
                                    "ORDER BY blockHeight ASC")) {
                s.setInt(1, blockHeight);
                s.setInt(2, blockHeight+2000);
                r = s.executeQuery();
                while (r.next()) {
                    int fileNumber = r.getInt(1);
                    int fileOffset = r.getInt(2);
                    Block block = getBlock(fileNumber, fileOffset);
                    byte[] blockData = block.bitcoinSerialize();
                    int length = Block.HEADER_SIZE;
                    length += VarInt.sizeOf(blockData, length);
                    byte[] headerData = Arrays.copyOf(blockData, length);
                    headerList.add(headerData);
                }
                r.close();
            }
        } catch (SQLException exc) {
            log.error("Unable to get header list", exc);
            throw new BlockStoreException("Unable to get header list");
        }
        return headerList;
    }

    /**
     * Releases a held block for processing
     *
     * @param       blockHash           Block hash
     * @throws      BlockStoreException Unable to release the block
     */
    public void releaseBlock(Sha256Hash blockHash) throws BlockStoreException {
        try {
            Connection conn = checkConnection();
            try (PreparedStatement s = conn.prepareStatement(
                            "UPDATE Blocks SET onHold=false WHERE blockHash=?")) {
                s.setBytes(1, blockHash.getBytes());
                s.executeUpdate();
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to release held block\n  %s", blockHash.toString()), exc);
            throw new BlockStoreException("Unable to release held block");
        }
    }

    /**
     * Stores a block in the database
     *
     * @param       block               Block to be stored
     * @throws      BlockStoreException Unable to store the block
     */
    public void storeBlock(StoredBlock storedBlock) throws BlockStoreException {
        Block block = storedBlock.getBlock();
        synchronized(lock) {
            //
            // Add the block to the current block file
            //
            int[] fileLocation = storeBlock(block);
            try {
                Connection conn = checkConnection();
                conn.setAutoCommit(false);
                //
                // Store the block in the Blocks table
                //
                try (PreparedStatement s = conn.prepareStatement(
                                "INSERT INTO Blocks (blockHash,prevHash,blockHeight,timeStamp,"+
                                        "chainWork,onChain,onHold,fileNumber,fileOffset) "+
                                        "VALUES(?,?,?,?,?,?,?,?,?)")) {
                    s.setBytes(1, block.getHash().getBytes());
                    s.setBytes(2, block.getPrevBlockHash().getBytes());
                    s.setInt(3, storedBlock.getHeight());
                    s.setLong(4, block.getTimeStamp());
                    s.setBytes(5, storedBlock.getChainWork().toByteArray());
                    s.setBoolean(6, storedBlock.isOnChain());
                    s.setBoolean(7, storedBlock.isOnHold());
                    s.setInt(8, fileLocation[0]);
                    s.setInt(9, fileLocation[1]);
                    s.executeUpdate();
                }
                //
                // Update the current block file number in the Settings table
                //
                try (PreparedStatement s = conn.prepareStatement (
                                "UPDATE Settings SET fileNumber=?")) {
                    s.setInt(1, blockFileNumber);
                    s.executeUpdate();
                }
                //
                // Commit the transaction
                //
                conn.commit();
                conn.setAutoCommit(true);
            } catch (SQLException exc) {
                log.error(String.format("Unable to store block in database\n  %s",
                                        storedBlock.getHash().toString()), exc);
                rollback();
                truncateBlockFile(fileLocation);
                throw new BlockStoreException("Unable to store block in database");
            }
        }
    }

    /**
     * Cleans up the database tables by deleting transaction outputs that are older
     * than the age limit
     *
     * @param       forcePurge          Purge entries even if the age limit hasn't been reached
     * @throws      BlockStoreException Unable to delete transaction outputs
     */
    public void cleanupDatabase(boolean forcePurge) throws BlockStoreException {
        long ageLimit;
        if (forcePurge)
            ageLimit = System.currentTimeMillis()/1000 - 24*60*60;
        else
            ageLimit = chainTime - MAX_TX_AGE;
        try {
            Connection conn = checkConnection();
            log.info("Deleting spent transaction outputs");
            try (PreparedStatement s = conn.prepareStatement(
                            "DELETE FROM TxOutputs WHERE timeSpent>0 AND timeSpent<?")) {
                s.setLong(1, ageLimit);
                int count = s.executeUpdate();
                log.info(String.format("%,d transaction outputs deleted", count));
            }
        } catch (SQLException exc) {
            log.error("Unable to delete transaction outputs", exc);
            throw new BlockStoreException("Unable to delete transaction outputs");
        }
    }

    /**
     * Locates the junction where the chain represented by the specified block joins
     * the current block chain.  The returned list starts with the junction block
     * and contains all blocks in the chain leading to the specified block.
     * The StoredBlock object for the junction block will not contain a Block object while
     * the StoredBlock objects for the blocks in the new chain will contain Block objects.
     *
     * A BlockNotFoundException will be thrown if the chain cannot be resolved because a
     * block is missing.  The caller should get the block from a peer, store it in the
     * database and then retry.
     *
     * A ChainTooLongException will be thrown if the block chain is getting too big.  The
     * caller should restart the chain resolution closer to the junction block and then
     * work backwards toward the original block.
     *
     * @param       chainHash               The block hash of the chain head
     * @throws      BlockNotFoundException  A block in the chain was not found
     * @throws      BlockStoreException     Unable to get blocks from the database
     * @throws      ChainTooLongException   The block chain is too long
     */
    public List<StoredBlock> getJunction(Sha256Hash chainHash)
                         throws BlockNotFoundException, BlockStoreException, ChainTooLongException {
        List<StoredBlock> chainList = new LinkedList<>();
        boolean onChain = false;
        Sha256Hash blockHash = chainHash;
        Block block;
        StoredBlock chainStoredBlock;
        synchronized (lock) {
            //
            // If this block immediately follows the current chain head, we don't need
            // to search the database.  Just create a StoredBlock and add it to the beginning
            // of the chain list.
            //
            if (chainHead.equals(blockHash)) {
                chainStoredBlock = new StoredBlock(chainHead, prevChainHead, chainWork, chainHeight);
                chainList.add(0, chainStoredBlock);
            } else {
                //
                // Starting with the supplied block, follow the previous hash values until
                // we reach a block which is on the block chain.  This block is the junction
                // block.  We will throw a ChainTooLongException if the chain exceeds 144 blocks
                // (1 days worth).  The caller should call this method again starting with the
                // last block found to build a sub-segment of the chain.
                //
                PreparedStatement s1 = null;
                try {
                    Sha256Hash prevHash;
                    boolean onHold;
                    int fileNumber;
                    int fileOffset;
                    int blockHeight;
                    BigInteger blockWork;
                    Connection conn = checkConnection();
                    ResultSet r;
                    s1 = conn.prepareStatement(
                                    "SELECT prevhash,onChain,onHold,chainWork,blockHeight,fileNumber,fileOffset "+
                                                    "FROM Blocks WHERE blockHash=?");
                    while (!onChain) {
                        s1.setBytes(1, blockHash.getBytes());
                        r = s1.executeQuery();
                        if (r.next()) {
                            prevHash = new Sha256Hash(r.getBytes(1));
                            onChain = r.getBoolean(2);
                            onHold = r.getBoolean(3);
                            blockWork = new BigInteger(r.getBytes(4));
                            blockHeight = r.getInt(5);
                            fileNumber = r.getInt(6);
                            fileOffset = r.getInt(7);
                            r.close();
                            if (!onChain) {
                                if (chainList.size() >= 144) {
                                    log.warn(String.format("Chain length exceeds 144 blocks\n  Restart %s",
                                                           blockHash.toString()));
                                    throw new ChainTooLongException("Chain length too long", blockHash);
                                }
                                block = getBlock(fileNumber, fileOffset);
                                chainStoredBlock = new StoredBlock(block, BigInteger.ZERO, 0, false, onHold);
                                blockHash = block.getPrevBlockHash();
                            } else {
                                chainStoredBlock = new StoredBlock(blockHash, prevHash, blockWork, blockHeight);
                            }
                            chainList.add(0, chainStoredBlock);
                        } else {
                            r.close();
                            log.warn(String.format("Chain block is not available\n  %s", blockHash.toString()));
                            throw new BlockNotFoundException("Unable to resolve block chain", blockHash);
                        }
                    }
                } catch (SQLException exc) {
                    log.error("Unable to locate junction block", exc);
                    throw new BlockStoreException("Unable to locate junction block", blockHash);
                }
            }
        }
        return chainList;
    }

    /**
     * Changes the chain head and updates all blocks from the junction block up to the new
     * chain head.  The junction block is the point where the current chain and the new
     * chain intersect.  A VerificationException will be thrown if the new chain head is
     * for a checkpoint block and the block hash doesn't match the checkpoint hash.
     *
     * @param       chainList               List of all chain blocks starting with the junction block
     *                                      up to and including the new chain head
     * @throws      BlockStoreException     Unable to update the database
     * @throws      VerificationException   Chain verification failed
     */
    public void setChainHead(List<StoredBlock> chainList)
                                            throws BlockStoreException, VerificationException {
        //
        // See if we have reached a checkpoint.  If we have, the new block at that height
        // must match the checkpoint block.
        //
        for (StoredBlock storedBlock : chainList) {
            if (storedBlock.getBlock() == null)
                continue;
            Sha256Hash checkHash = checkpoints.get(Integer.valueOf(storedBlock.getHeight()));
            if (checkHash != null) {
                if (checkHash.equals(storedBlock.getHash())) {
                    log.info(String.format("New chain head at height %d matches checkpoint",
                                           storedBlock.getHeight()));
                } else {
                    log.error(String.format("New chain head at height %d does not match checkpoint",
                                            storedBlock.getHeight()));
                    throw new VerificationException("Checkpoint verification failed",
                                                    Parameters.REJECT_CHECKPOINT, storedBlock.getHash());
                }
            }
        }
        //
        // Make the new block the chain head
        //
        StoredBlock storedBlock = chainList.get(chainList.size()-1);
        synchronized (lock) {
            Sha256Hash blockHash = null;
            Block block;
            Sha256Hash txHash;
            PreparedStatement s1 = null;
            PreparedStatement s2 = null;
            PreparedStatement s3 = null;
            PreparedStatement s4 = null;
            try {
                Connection conn = checkConnection();
                conn.setAutoCommit(false);
                ResultSet r;
                //
                // The ideal case is where the new block links to the current chain head.
                // If this is not the case, we need to remove all blocks from the block
                // chain following the junction block.
                //
                if (!chainHead.equals(storedBlock.getPrevBlockHash())) {
                    s1 = conn.prepareStatement("SELECT fileNumber,fileOffset FROM Blocks WHERE blockHash=?");
                    s2 = conn.prepareStatement("DELETE FROM TxOutputs WHERE txHash=?");
                    s3 = conn.prepareStatement("UPDATE TxOutputs SET timeSpent=0 WHERE txHash=? AND txIndex=?");
                    s4 = conn.prepareStatement("UPDATE Blocks SET onChain=false,blockHeight=0 WHERE blockHash=?");
                    Sha256Hash junctionHash = chainList.get(0).getHash();
                    blockHash = chainHead;
                    //
                    // Process each block starting at the current chain head and working backwards
                    // until we reach the junction block
                    //
                    while(!blockHash.equals(junctionHash)) {
                        //
                        // Get the block from the Blocks database
                        //
                        s1.setBytes(1, blockHash.getBytes());
                        r = s1.executeQuery();
                        if (!r.next()) {
                            r.close();
                            log.error(String.format("Chain block not found in Blocks database\n  %s",
                                                    blockHash.toString()));
                            throw new BlockStoreException("Chain block not found in Blocks database");
                        }
                        int fileNumber = r.getInt(1);
                        int fileOffset = r.getInt(2);
                        block = getBlock(fileNumber, fileOffset);
                        //
                        // Process each transaction in the block
                        //
                        List<Transaction> txList = block.getTransactions();
                        for (Transaction tx : txList) {
                            txHash = tx.getHash();
                            //
                            // Delete the transaction from the TxOutputs table
                            //
                            s2.setBytes(1, txHash.getBytes());
                            s2.executeUpdate();
                            //
                            // Update spent outputs to indicate they have not been spent.  We
                            // need to ignore inputs for coinbase transactions since they are
                            // not used for spending coins.  It is also possible that a transaction
                            // in the block spends an output from another transaction in the block,
                            // in which case the output will not be found since we have already
                            // deleted all of the block transactions.
                            //
                            if (tx.isCoinBase())
                                continue;
                            List<TransactionInput> txInputs = tx.getInputs();
                            for (TransactionInput txInput : txInputs) {
                                OutPoint op = txInput.getOutPoint();
                                Sha256Hash outHash = op.getHash();
                                int outIndex = op.getIndex();
                                s3.setBytes(1, outHash.getBytes());
                                s3.setInt(2, outIndex);
                                s3.executeUpdate();
                            }
                        }
                        //
                        // Update the block status in the Blocks table
                        //
                        s4.setBytes(1, blockHash.getBytes());
                        s4.executeUpdate();
                        log.info(String.format("Block removed from block chain\n  %s", blockHash.toString()));
                        //
                        // Advance to the block before this block
                        //
                        blockHash = block.getPrevBlockHash();
                    }
                    s1.close();
                    s1 = null;
                    s2.close();
                    s2 = null;
                    s3.close();
                    s3 = null;
                    s4.close();
                    s4 = null;
                }
                //
                // Now add the new blocks to the block chain starting with the
                // block following the junction block
                //
                s1 = conn.prepareStatement(
                                "SELECT txIndex FROM TxOutputs WHERE txHash=? LIMIT 1");
                s2 = conn.prepareStatement(
                                "INSERT INTO TxOutputs (txHash,txIndex,blockHash,blockHeight,timeSpent,"+
                                        "value,scriptBytes) VALUES(?,?,?,0,0,?,?)");
                s3 = conn.prepareStatement(
                                "UPDATE TxOutputs SET timeSpent=?,blockHeight=? WHERE txHash=? AND txIndex=?");
                s4 = conn.prepareStatement(
                                "UPDATE Blocks SET onChain=true,blockHeight=?,chainWork=? WHERE blockHash=?");
                for (int i=1; i<chainList.size(); i++) {
                    storedBlock = chainList.get(i);
                    block = storedBlock.getBlock();
                    blockHash = block.getHash();
                    int blockHeight = storedBlock.getHeight();
                    BigInteger blockWork = storedBlock.getChainWork();
                    List<Transaction> txList = block.getTransactions();
                    //
                    // Add the block transactions to the TxOutputs table and update the
                    // spent status for transaction outputs referenced by the transactions
                    // in this block.
                    //
                    // Unfortunately, before BIP 30 was implemented, there were several
                    // cases where a block contained the same coinbase transaction.  So
                    // we need to check the TxOutputs table first to make sure the transaction
                    // output is not already in the table for a coinbase transaction.  We will
                    // allow a duplicate coinbase transaction if it is in a block before 250,000.
                    //
                    // Some transactions contain a text message as one of the outputs with the
                    // associated script set to OP_RETURN (which means the output can never be spent).
                    // We will check for this case and set the transaction output as spent.
                    //
                    for (Transaction tx : txList) {
                        txHash = tx.getHash();
                        boolean processOutputs = true;
                        s1.setBytes(1, txHash.getBytes());
                        r = s1.executeQuery();
                        if (r.next()) {
                            r.close();
                            if (!tx.isCoinBase() || storedBlock.getHeight() >= 250000) {
                                log.error(String.format("Height %d: Transaction outputs already in TxOutputs\n"+
                                                        "  Block %s\n  Tx %s",
                                                         storedBlock.getHeight(), block.getHashAsString(),
                                                         txHash));
                                throw new VerificationException("Transaction outputs already in TxOutputs",
                                                                Parameters.REJECT_DUPLICATE, txHash);
                            }
                            processOutputs = false;
                        } else {
                            r.close();
                        }
                        if (processOutputs) {
                            List<TransactionOutput> txOutputs = tx.getOutputs();
                            for (TransactionOutput txOutput : txOutputs) {
                                if (txOutput.isSpendable()) {
                                    s2.setBytes(1, txHash.getBytes());
                                    s2.setInt(2, txOutput.getIndex());
                                    s2.setBytes(3, blockHash.getBytes());
                                    s2.setBytes(4, txOutput.getValue().toByteArray());
                                    s2.setBytes(5, txOutput.getScriptBytes());
                                    s2.executeUpdate();
                                }
                            }
                        }
                        //
                        // Connect transaction inputs to transaction outputs and mark them spent.
                        //
                        // We need to ignore inputs for coinbase transactions since they are not
                        // used for spending coins.
                        //
                        if (tx.isCoinBase())
                            continue;
                        long currentTime = System.currentTimeMillis()/1000;
                        List<TransactionInput> txInputs = tx.getInputs();
                        for (TransactionInput txInput : txInputs) {
                            OutPoint op = txInput.getOutPoint();
                            Sha256Hash outHash = op.getHash();
                            int outIndex = op.getIndex();
                            s3.setLong(1, currentTime);
                            s3.setInt(2, blockHeight);
                            s3.setBytes(3, outHash.getBytes());
                            s3.setInt(4, outIndex);
                            s3.executeUpdate();
                        }
                    }
                    //
                    // Update the block status in the Blocks database
                    //
                    s4.setInt(1, blockHeight);
                    s4.setBytes(2, blockWork.toByteArray());
                    s4.setBytes(3, blockHash.getBytes());
                    s4.executeUpdate();
                    log.info(String.format("Block added to block chain at height %d\n  %s",
                                           blockHeight, block.getHashAsString()));
                }
                s1.close();
                s1 = null;
                s2.close();
                s2 = null;
                s3.close();
                s3 = null;
                s4.close();
                s4 = null;
                //
                // Commit the changes
                //
                conn.commit();
                conn.setAutoCommit(true);
                //
                // Update chain values for the new chain
                //
                storedBlock = chainList.get(chainList.size()-1);
                chainTime = storedBlock.getBlock().getTimeStamp();
                chainHead = storedBlock.getHash();
                prevChainHead = storedBlock.getPrevBlockHash();
                chainHeight = storedBlock.getHeight();
                chainWork = storedBlock.getChainWork();
                targetDifficulty = storedBlock.getBlock().getTargetDifficulty();
            } catch (SQLException exc) {
                log.error("Unable to update block chain", exc);
                rollback(s1, s2, s3, s4);
                throw new BlockStoreException("Unable to update block chain", blockHash);
            }
        }
    }

    /**
     * Checks if a table exists
     *
     * @param       table               Table name
     * @return                          TRUE if the table exists
     * @throws      BlockStoreException Unable to access the database server
     */
    private boolean tableExists(String table) throws BlockStoreException {
        boolean tableExists = false;
        Connection conn = checkConnection();
        try {
            try (Statement s = conn.createStatement()) {
                s.executeQuery("SELECT * FROM "+table+" WHERE 1 = 2");
                tableExists = true;
            }
        } catch (SQLException exc) {
            tableExists = false;
        }
        return tableExists;
    }

    /**
     * Create the tables
     *
     * @throws      BlockStoreException Unable to create database tables
     */
    private void createTables() throws BlockStoreException {
        Connection conn = checkConnection();
        try {
            try (Statement s = conn.createStatement()) {
                conn.setAutoCommit(false);
                s.executeUpdate(Settings_Table);
                s.executeUpdate(TxOutputs_Table);
                s.executeUpdate(TxOutputs_IX1);
                s.executeUpdate(Blocks_Table);
                s.executeUpdate(Blocks_IX1);
                s.executeUpdate(Alerts_Table);
                conn.commit();
                conn.setAutoCommit(true);
            }
            log.info("SQL database tables created");
        } catch (SQLException exc) {
            log.error("Unable to create SQL database tables", exc);
            rollback();
            throw new BlockStoreException("Unable to create SQL database tables");
        }
    }

    /**
     * Initialize the tables
     *
     * @throws      BlockStoreException Unable to initialize the database tables
     */
    private void initTables() throws BlockStoreException {
        Connection conn = checkConnection();
         try {
            conn.setAutoCommit(false);
            //
            // Initialize the block chain with the genesis block
            //
            chainHead = new Sha256Hash(Parameters.GENESIS_BLOCK_HASH);
            prevChainHead = Sha256Hash.ZERO_HASH;
            chainHeight = 0;
            chainWork = BigInteger.ONE;
            targetDifficulty = Parameters.MAX_TARGET_DIFFICULTY;
            blockFileNumber = 0;
            chainTime = 0x495fab29L;
            //
            // Initialize the Settings table
            //
            try (PreparedStatement s = conn.prepareStatement(
                    "INSERT INTO Settings (schemaName,schemaVersion,fileNumber) "+
                                            "VALUES(?,?,?)")) {
                s.setString(1, schemaName);
                s.setInt(2, schemaVersion);
                s.setInt(3, 0);
                s.executeUpdate();
            }
            //
            // Add the genesis block to the Blocks table
            //
            try (PreparedStatement s = conn.prepareStatement(
                        "INSERT INTO Blocks(blockHash,prevHash,blockHeight,timeStamp,chainWork,onChain,onHold,"+
                                           "fileNumber,fileOffset) VALUES(?,?,0,?,?,true,false,0,0)")) {
                s.setBytes(1, chainHead.getBytes());
                s.setBytes(2, prevChainHead.getBytes());
                s.setLong(3, chainTime);
                s.setBytes(4, chainWork.toByteArray());
                s.executeUpdate();
            }
            //
            // Copy the genesis block as the initial block file
            //
            File blockFile = new File(String.format("%s\\Blocks\\blk00000.dat", dataPath));
            File genesisFile = new File(String.format("%s\\GenesisBlock.dat", dataPath));
            int inLength = (int)genesisFile.length();
            try (FileInputStream inFile = new FileInputStream(genesisFile)) {
                try (FileOutputStream outFile = new FileOutputStream(blockFile)) {
                    byte[] blockData = new byte[inLength+8];
                    Utils.uint32ToByteArrayLE(Parameters.MAGIC_NUMBER, blockData, 0);
                    Utils.uint32ToByteArrayLE(inLength, blockData, 4);
                    inFile.read(blockData, 8, inLength);
                    outFile.write(blockData);
                }
            }
            //
            // All done - commit the updates
            //
            conn.commit();
            conn.setAutoCommit(true);
            log.info(String.format("Database initialized with schema version %d.%d",
                                   schemaVersion/100, schemaVersion%100));
        } catch (IOException | SQLException exc) {
            log.error("Unable to initialize the database tables", exc);
            rollback();
            throw new BlockStoreException("Unable to initialize the database tables");
        }
    }

    /**
     * Get the initial database settings
     *
     * @throws      BlockStoreException Unable to get the initial values
     */
    private void getSettings() throws BlockStoreException {
        Connection conn = checkConnection();
        ResultSet r = null;
        int version = 0;
        try {
            //
            // Get the initial values from the Settings table
            //
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT schemaVersion,fileNumber "+
                                        "FROM SETTINGS WHERE schemaName=?")) {
                s.setString(1, schemaName);
                r = s.executeQuery();
                if (!r.next())
                    throw new BlockStoreException("Incorrect database schema");
                version = r.getInt(1);
                blockFileNumber = r.getInt(2);
                r.close();
                if (version != schemaVersion)
                    throw new BlockStoreException(String.format("Schema version %d.%d is not supported",
                                                                version/100, version%100));
            }
            //
            // Get the current chain height and chain timestamp
            //
            try (Statement s = conn.createStatement()) {
                r = s.executeQuery("SELECT MAX(blockHeight) FROM Blocks WHERE onChain=true");
                if (!r.next())
                    throw new BlockStoreException(String.format("Unable to get chain height"));
                chainHeight = r.getInt(1);
                r.close();
                r = s.executeQuery("SELECT MAX(timeStamp) FROM Blocks");
                if (!r.next())
                    throw new BlockStoreException(String.format("Unable to get chain timestamp"));
                chainTime = r.getLong(1);
                r.close();
            }
            //
            // Get the current chain values from the chain head block
            //
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT blockHash,chainWork,fileNumber,fileOffset FROM Blocks "+
                            "WHERE blockHeight=? AND onChain=true")) {
                s.setInt(1, chainHeight);
                r = s.executeQuery();
                if (!r.next())
                    throw new BlockStoreException(String.format("Unable to get chain block at height %d",
                                                                chainHeight));
                chainHead = new Sha256Hash(r.getBytes(1));
                chainWork = new BigInteger(r.getBytes(2));
                int fileNumber = r.getInt(3);
                int fileOffset = r.getInt(4);
                r.close();
                Block block = getBlock(fileNumber, fileOffset);
                prevChainHead = block.getPrevBlockHash();
                targetDifficulty = block.getTargetDifficulty();
            }
            BigInteger networkDifficulty =
                            Parameters.PROOF_OF_WORK_LIMIT.divide(Utils.decodeCompactBits(targetDifficulty));
            log.info(String.format("Database opened with schema version %d.%d\n"+
                                   "  Chain height %,d, Target difficulty %s\n  Chain head %s",
                                   version/100, version%100, chainHeight,
                                   Utils.numberToShortString(networkDifficulty), chainHead.toString()));
        } catch (SQLException exc) {
            log.error("Unable to query initial settings", exc);
            throw new BlockStoreException("Unable to query initial settings");
        }
    }

    /**
     * Returns a block that was stored in one of the block files
     *
     * @param       fileNumber          The block file number
     * @param       fileOffset          The block offset within the file
     * @return                          The requested block or null if the block is not found
     * @throws      BlockStoreException Unable to read the block data
     */
    private Block getBlock(int fileNumber, int fileOffset) throws BlockStoreException {
        Block block = null;
        File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, fileNumber));
        try {
            try (RandomAccessFile inFile = new RandomAccessFile(blockFile, "r")) {
                inFile.seek(fileOffset);
                byte[] bytes = new byte[8];
                int count = inFile.read(bytes);
                if (count != 8) {
                    log.error(String.format("End-of-data reading from block file %d, offset %d",
                                            fileNumber, fileOffset));
                    throw new BlockStoreException("Unable to read block file");
                }
                long magic = Utils.readUint32LE(bytes, 0);
                int length = (int)Utils.readUint32LE(bytes, 4);
                if (magic != Parameters.MAGIC_NUMBER) {
                    log.error(String.format("Magic number %X is incorrect in block file %d, offset %d",
                                            magic, fileNumber, fileOffset));
                    throw new BlockStoreException("Incorrect block file format");
                }
                if (length < Block.HEADER_SIZE) {
                    log.error(String.format("Block length %d is too small in block file %d, offset %d",
                                            length, fileNumber, fileOffset));
                    throw new BlockStoreException("Incorrect block length");
                }
                byte[] blockData = new byte[length];
                count = inFile.read(blockData);
                if (count != length) {
                    log.error(String.format("End-of-data reading block file %d, offset %d",
                                            fileNumber, fileOffset));
                    throw new BlockStoreException("Unable to read block file");
                }
                block = new Block(blockData, 0, length, false);
            }
        } catch (IOException | VerificationException exc) {
            log.error(String.format("Unable to read block file %d, offset %d",
                                    fileNumber, fileOffset), exc);
            throw new BlockStoreException("Unable to read block file");
        }
        return block;
    }

    /**
     * Stores a block in the current block file
     *
     * @param       block               Block to store
     * @return                          Array containing the block file number and offset
     * @throws      BlockStoreException Error while writing to the block file
     */
    private int[] storeBlock(Block block) throws BlockStoreException {
        int[] blockLocation = new int[2];
        try {
            byte[] blockData = block.bitcoinSerialize();
            File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, blockFileNumber));
            long filePosition = blockFile.length();
            if (filePosition >= MAX_BLOCK_FILE_SIZE) {
                blockFileNumber++;
                filePosition = 0;
                blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, blockFileNumber));
                if (blockFile.exists())
                    blockFile.delete();
            }
            try (RandomAccessFile outFile = new RandomAccessFile(blockFile, "rws")) {
                outFile.seek(filePosition);
                byte[] bytes = new byte[8];
                Utils.uint32ToByteArrayLE(Parameters.MAGIC_NUMBER, bytes, 0);
                Utils.uint32ToByteArrayLE(blockData.length, bytes, 4);
                outFile.write(bytes);
                outFile.write(blockData);
                blockLocation[0] = blockFileNumber;
                blockLocation[1] = (int)filePosition;
            }
        } catch (IOException exc) {
            log.error(String.format("Unable to write to block file %d", blockFileNumber), exc);
            throw new BlockStoreException("Unable to write to block file");
        }
        return blockLocation;
    }

    /**
     * Truncate a block file to recover from a database error
     *
     * @param       fileLocation            The file location returned by storeBlock()
     */
    private void truncateBlockFile(int[] fileLocation) {
        File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, fileLocation[0]));
        try {
            //
            // If the block is stored at the beginning of the file, just delete the file
            // and decrement the block number.  Otherwise, truncate the file.
            if (fileLocation[1] == 0) {
                blockFile.delete();
                blockFileNumber--;
            } else {
                try (RandomAccessFile outFile = new RandomAccessFile(blockFile, "rws")) {
                    outFile.getChannel().truncate(fileLocation[1]);
                }
            }
        } catch (IOException exc) {
            log.error(String.format("Unable to truncate block file %d", fileLocation[0]), exc);
        }
    }
}