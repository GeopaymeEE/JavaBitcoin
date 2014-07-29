/*
 * Copyright 2013-2014 Ronald Hoffman.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ScripterRon.JavaBitcoin;
import static org.ScripterRon.JavaBitcoin.Main.log;

import org.ScripterRon.BitcoinCore.Alert;
import org.ScripterRon.BitcoinCore.Block;
import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.OutPoint;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionInput;
import org.ScripterRon.BitcoinCore.TransactionOutput;
import org.ScripterRon.BitcoinCore.Utils;
import org.ScripterRon.BitcoinCore.VerificationException;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>BlockStoreSql manages the SQL database containing the block chain information.
 * The database is periodically pruned to reduce storage requirements by removing transactions
 * with completely-spent outputs.</p>
 *
 * <p>The block files are named 'blknnnnn.dat' and are stored in the 'Blocks' subdirectory.  A new
 * block is added to the end of the current block file.  When the file reaches the maximum size,
 * the file number is incremented and a new block file is created.</p>
 */
public class BlockStoreSql extends BlockStore {

   /** Settings table definition */
    private static final String Settings_Table = "CREATE TABLE Settings ("+
        "schema_name        VARCHAR(32)     NOT NULL,"+     // Schema name
        "schema_version     INTEGER         NOT NULL)";     // Schema version

    /** Blocks table definition */
    private static final String Blocks_Table = "CREATE TABLE Blocks ("+
            "block_hash     BINARY          NOT NULL,"+     // Block hash
            "prev_hash      BINARY          NOT NULL,"+     // Previous hash
            "timestamp      BIGINT          NOT NULL,"+     // Block timestamp
            "block_height   INTEGER         NOT NULL,"+     // Block height or -1
            "chain_work     BINARY          NOT NULL,"+     // Cumulative chain work
            "on_hold        BOOLEAN         NOT NULL,"+     // Block is held
            "file_number    INTEGER         NOT NULL,"+     // Block file number
            "file_offset    INTEGER         NOT NULL)";     // Block offset within file
    private static final String Blocks_IX1 = "CREATE UNIQUE INDEX Blocks_IX1 on Blocks(block_hash)";
    private static final String Blocks_IX2 = "CREATE INDEX Blocks_IX2 ON Blocks(prev_hash)";
    private static final String Blocks_IX3 = "CREATE INDEX Blocks_IX3 ON Blocks(block_height)";

    /** TxOutputs table definition */
    private static final String TxOutputs_Table = "CREATE TABLE TxOutputs ("+
            "db_id          IDENTITY,"+                     // Database identity
            "tx_hash        BINARY          NOT NULL,"+     // Transaction hash
            "tx_index       SMALLINT        NOT NULL,"+     // Output index
            "block_hash     BINARY          NOT NULL,"+     // Block hash
            "block_height   INTEGER         NOT NULL,"+     // Block height when output spent
            "time_spent     BIGINT          NOT NULL,"+     // Time when output spent
            "is_coinbase    BOOLEAN         NOT NULL,"+     // Coinbase transaction
            "value          BIGINT          NOT NULL,"+     // Value
            "script_bytes   BINARY          NOT NULL)";     // Script bytes
    private static final String TxOutputs_IX1 = "CREATE UNIQUE INDEX TxOutputs_IX1 ON TxOutputs(tx_hash,tx_index)";

    /** TxSpentOutputs table definition */
    private static final String TxSpentOutputs_Table = "CREATE TABLE TxSpentOutputs ("+
            "time_spent     BIGINT          NOT NULL,"+     // Time when output spent
            "db_id          INTEGER         NOT NULL "+     // Referenced spent output
            "               REFERENCES TxOutputs(db_id) ON DELETE CASCADE)";
    private static final String TxSpentOutputs_IX1 = "CREATE INDEX TxSpentOutputs_IX1 ON TxSpentOutputs(time_spent)";

    /** Alerts table definition */
    private static final String Alerts_Table = "CREATE TABLE Alerts ("+
            "alert_id       INTEGER         NOT NULL,"+     // Alert identifier
            "is_cancelled   BOOLEAN         NOT NULL,"+     // Alert cancelled
            "payload        BINARY          NOT NULL,"+     // Payload
            "signature      BINARY          NOT NULL)";     // Signature
    private static final String Alerts_IX1 = "CREATE UNIQUE INDEX Alerts_IX1 on Alerts(alert_id)";

    /** Database schema name */
    private static final String schemaName = "JavaBitcoin Block Store";

    /** Database schema version */
    private static final int schemaVersion = 100;

    /** Per-thread database connection */
    private final ThreadLocal<Connection> threadConnection = new ThreadLocal<>();

    /** List of all database connections */
    private final List<Connection> allConnections = Collections.synchronizedList(new ArrayList<Connection>());

    /** Database connection URL */
    private final String connectionURL;

    /**
     * Create a BlockStore
     *
     * @param       dataPath                Application data path
     * @throws      BlockStoreException     Unable to initialize the database
     */
    public BlockStoreSql(String dataPath) throws BlockStoreException {
        super(dataPath);
        String databasePath = dataPath.replace('\\', '/');
        connectionURL = String.format("jdbc:h2:%s/Database/bitcoin;MVCC=TRUE", databasePath);
        //
        // Load the JDBC driver
        //
        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException exc) {
            log.error("Unable to load the JDBC driver", exc);
            throw new BlockStoreException("Unable to load the JDBC driver", exc);
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
     * Close the database
     */
    @Override
    public void close() {
        allConnections.stream().forEach((conn) -> {
            try {
                conn.close();
            } catch (SQLException exc) {
                log.error("SQL error while closing connection", exc);
            }
        });
        allConnections.clear();
    }

    /**
     * Get the database connection for the current thread
     *
     * @return                              Connection for the current thread
     * @throws      BlockStoreException     Unable to obtain a database connection
     */
    private Connection getConnection() throws BlockStoreException {
        //
        // Return the current connection if we have one
        //
        Connection conn = threadConnection.get();
        if (conn != null)
            return conn;
        //
        // Obtain a new connection
        //
        synchronized (lock) {
            try {
                threadConnection.set(DriverManager.getConnection(connectionURL, "ScripterRon", ""));
                conn = threadConnection.get();
                allConnections.add(conn);
                log.info(String.format("Database connection %d created", allConnections.size()));
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
            Connection conn = getConnection();
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
     * Check if the block is already in the database
     *
     * @param       blockHash               The block to check
     * @return                              TRUE if this is a new block
     * @throws      BlockStoreException     Unable to check the block status
     */
    @Override
    public boolean isNewBlock(Sha256Hash blockHash) throws BlockStoreException {
        boolean isNewBlock;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT 1 FROM Blocks WHERE block_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            ResultSet r = s.executeQuery();
            isNewBlock = !r.next();
        } catch (SQLException exc) {
            log.error(String.format("Unable to check block status\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return isNewBlock;
    }

    /**
     * Check if the alert is already in our database
     *
     * @param       alertID                 Alert identifier
     * @return                              TRUE if this is a new alert
     * @throws      BlockStoreException     Unable to get the alert status
     */
    @Override
    public boolean isNewAlert(int alertID) throws BlockStoreException {
        boolean isNewAlert;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT 1 FROM Alerts WHERE alert_id=?")) {
            s.setInt(1, alertID);
            ResultSet r = s.executeQuery();
            isNewAlert = !r.next();
        } catch (SQLException exc) {
            log.error(String.format("Unable to check alert status for %d", alertID), exc);
            throw new BlockStoreException("Unable to check alert status");
        }
        return isNewAlert;
    }

    /**
     * Return a list of all alerts in the database
     *
     * @return                              List of all alerts
     * @throws      BlockStoreException     Unable to get alerts from database
     */
    @Override
    public List<Alert> getAlerts() throws BlockStoreException {
        List<Alert> alertList = new LinkedList<>();
        Connection conn = getConnection();
        try (Statement s = conn.createStatement()) {
            ResultSet r = s.executeQuery("SELECT is_cancelled,payload,signature FROM Alerts ORDER BY alert_id ASC");
            while (r.next()) {
                boolean isCancelled = r.getBoolean(1);
                byte[] payload = r.getBytes(2);
                byte[] signature = r.getBytes(3);
                Alert alert = new Alert(payload, signature);
                alert.setCancel(isCancelled);
                alertList.add(alert);
            }
        } catch (IOException | SQLException exc) {
            log.error("Unable to build alert list", exc);
            throw new BlockStoreException("Unable to build alert list");
        }
        return alertList;
    }

    /**
     * Store an alert in the database
     *
     * @param       alert                   The alert
     * @throws      BlockStoreException     Unable to store the alert
     */
    @Override
    public void storeAlert(Alert alert) throws BlockStoreException {
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("INSERT INTO Alerts "
                        + "(alert_id,is_cancelled,payload,signature) VALUES(?,false,?,?)")) {
            s.setInt(1, alert.getID());
            s.setBytes(2, alert.getPayload());
            s.setBytes(3, alert.getSignature());
            s.executeUpdate();
        } catch (SQLException exc) {
            log.error(String.format("Unable to store alert %d", alert.getID()), exc);
            throw new BlockStoreException("Unable to store alert");
        }
    }

    /**
     * Cancel an alert
     *
     * @param       alertID                 The alert identifier
     * @throws      BlockStoreException     Unable to update the alert
     */
    @Override
    public void cancelAlert(int alertID) throws BlockStoreException {
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("UPDATE Alerts SET is_cancelled=true WHERE alert_id=?")) {
            s.setInt(1, alertID);
            s.executeUpdate();
        } catch (SQLException exc) {
            log.error(String.format("Unable to cancel alert %d", alertID), exc);
            throw new BlockStoreException("Unable to cancel alert");
        }
    }

    /**
     * Check if the block is on the block chain
     *
     * @param       blockHash               The block to check
     * @return                              TRUE if the block is on the block chain
     * @throws      BlockStoreException     Unable to get the block status
     */
    @Override
    public boolean isOnChain(Sha256Hash blockHash) throws BlockStoreException {
        boolean onChain;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT block_height from Blocks WHERE block_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            ResultSet r = s.executeQuery();
            onChain = (r.next() && r.getInt(1)>=0);
        } catch (SQLException exc) {
            log.error(String.format("Unable to check block status\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return onChain;
    }

    /**
     * Return a block stored in the database.  The returned block represents the
     * block data sent over the wire and does not include any information about the
     * block location within the block chain.
     *
     * @param       blockHash               Block hash
     * @return                              The block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block from database
     */
    @Override
    public Block getBlock(Sha256Hash blockHash) throws BlockStoreException {
        Block block = null;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT file_number,file_offset FROM Blocks "
                        + "WHERE block_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            ResultSet r = s.executeQuery();
            if (r.next()) {
                int fileNumber = r.getInt(1);
                int fileOffset = r.getInt(2);
                block = getBlock(fileNumber, fileOffset);
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get block\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get block", blockHash);
        }
        return block;
    }

    /**
     * Return a block stored in the database.  The returned block contains
     * the basic block plus information about its current location within the block chain.
     *
     * @param       blockHash               The block hash
     * @return                              The stored block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block from database
     */
    @Override
    public StoredBlock getStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock storedBlock = null;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT block_height,chain_work,on_hold,"
                        + "file_number,file_offset FROM Blocks WHERE block_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            ResultSet r = s.executeQuery();
            if (r.next()) {
                int blockHeight = r.getInt(1);
                BigInteger blockWork = new BigInteger(r.getBytes(2));
                boolean onHold = r.getBoolean(3);
                int fileNumber = r.getInt(4);
                int fileOffset = r.getInt(5);
                Block block = getBlock(fileNumber, fileOffset);
                storedBlock = new StoredBlock(block, blockWork, blockHeight, (blockHeight>=0), onHold);
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get block\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get block", blockHash);
        }
        return storedBlock;
    }

    /**
     * Return the child block for the specified block.  If the block has multiple children, the child
     * block that is on the chain will be returned.
     *
     * @param       blockHash               The block hash
     * @return                              The stored block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block
     */
    @Override
    public StoredBlock getChildStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock childStoredBlock = null;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement(
                            "SELECT block_height,chain_work,on_hold,file_number,file_offset "+
                            "FROM Blocks WHERE prev_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            ResultSet r = s.executeQuery();
            while (r.next()) {
                int blockHeight = r.getInt(1);
                if (blockHeight < 0 && childStoredBlock != null)
                    continue;
                BigInteger blockWork = new BigInteger(r.getBytes(2));
                boolean onHold = r.getBoolean(3);
                int fileNumber = r.getInt(4);
                int fileOffset = r.getInt(5);
                Block block = getBlock(fileNumber, fileOffset);
                childStoredBlock = new StoredBlock(block, blockWork, blockHeight, (blockHeight>=0), onHold);
                if (blockHeight >= 0)
                    break;
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get child block\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get child block", blockHash);
        }
        return childStoredBlock;
    }

    /**
     * Return the block status for recent blocks
     *
     * @param       maxCount                The maximum number of blocks to be returned
     * @return                              A list of BlockStatus objects
     * @throws      BlockStoreException     Unable to get block status
     */
    @Override
    public List<BlockStatus> getBlockStatus(int maxCount) throws BlockStoreException {
        List<BlockStatus> blockList = new LinkedList<>();
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement(
                        "SELECT block_hash,timestamp,block_height,on_hold FROM Blocks "+
                        "ORDER BY timestamp DESC LIMIT ?")) {
            s.setInt(1, maxCount);
            ResultSet r = s.executeQuery();
            while (r.next()) {
                Sha256Hash blockHash = new Sha256Hash(r.getBytes(1));
                long timeStamp = r.getLong(2);
                int blockHeight = r.getInt(3);
                boolean onHold = r.getBoolean(4);
                BlockStatus status = new BlockStatus(blockHash, timeStamp, blockHeight, (blockHeight>=0), onHold);
                blockList.add(status);
            }
        } catch (SQLException exc) {
            log.error("Unable to get block status", exc);
            throw new BlockStoreException("Unable to get block status");
        }
        return blockList;
    }

    /**
     * Check if this is a new transaction
     *
     * @param       txHash                  Transaction hash
     * @return                              TRUE if the transaction is not in the database
     * @throws      BlockStoreException     Unable to check transaction status
     */
    @Override
    public boolean isNewTransaction(Sha256Hash txHash) throws BlockStoreException {
        boolean isNew;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT 1 FROM TxOutputs WHERE tx_hash=? LIMIT 1")) {
            s.setBytes(1, txHash.getBytes());
            ResultSet r = s.executeQuery();
            isNew = !r.next();
        } catch (SQLException exc) {
            log.error(String.format("Unable to get transaction status\n  Tx %s", txHash.toString()), exc);
            throw new BlockStoreException("Unable to get transaction status");
        }
        return isNew;
    }

    /**
     * Return the transaction depth.  A depth of 0 indicates the transaction is not in a block
     * on the current chain.
     *
     * @param       txHash                  Transaction hash
     * @return                              Transaction depth
     * @throws      BlockStoreException     Unable to get transaction depth
     */
    @Override
    public int getTxDepth(Sha256Hash txHash) throws BlockStoreException {
        int txDepth = 0;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT block_height from Blocks "+
                        "WHERE block_hash=(SELECT block_hash FROM TxOutputs WHERE tx_hash=? LIMIT 1)")) {
            s.setBytes(1, txHash.getBytes());
            ResultSet r = s.executeQuery();
            if (r.next()) {
                int height = r.getInt(1);
                txDepth = chainHeight - height + 1;
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get transaction depth\n  Tx %s", txHash), exc);
            throw new BlockStoreException("Unable to get transaction depth");
        }
        return txDepth;
    }

    /**
     * Return the requested transaction output
     *
     * @param       outPoint                Transaction outpoint
     * @return                              Transaction output or null if the transaction is not found
     * @throws      BlockStoreException     Unable to get transaction output status
     */
    @Override
    public StoredOutput getTxOutput(OutPoint outPoint) throws BlockStoreException {
        StoredOutput output = null;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement(
                        "SELECT time_spent,value,script_bytes,block_height,is_coinbase "+
                        "FROM TxOutputs WHERE tx_hash=? AND tx_index=?")) {
            s.setBytes(1, outPoint.getHash().getBytes());
            s.setShort(2, (short)outPoint.getIndex());
            ResultSet r = s.executeQuery();
            if (r.next()) {
                long timeSpent = r.getLong(1);
                BigInteger value = BigInteger.valueOf(r.getLong(2));
                byte[] scriptBytes = r.getBytes(3);
                int blockHeight = r.getInt(4);
                boolean isCoinbase = r.getBoolean(5);
                output = new StoredOutput(outPoint.getIndex(), value, scriptBytes,
                                          isCoinbase, (timeSpent!=0), blockHeight);
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get transaction output\n  Tx %s : Index %d",
                                    outPoint.getHash(), outPoint.getIndex()), exc);
            throw new BlockStoreException("Unable to get transaction output");
        }
        return output;
    }

    /**
     * Returns the outputs for the specified transaction
     *
     * @param       txHash                  Transaction hash
     * @return                              Stored output list
     * @throws      BlockStoreException     Unable to get transaction outputs
     */
    @Override
    public List<StoredOutput> getTxOutputs(Sha256Hash txHash) throws BlockStoreException {
        List<StoredOutput> outputList = new LinkedList<>();
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement(
                        "SELECT tx_index,time_spent,value,script_bytes,block_height,is_coinbase "+
                        "FROM TxOutputs WHERE tx_hash=? ORDER BY tx_index ASC")) {
            s.setBytes(1, txHash.getBytes());
            ResultSet r = s.executeQuery();
            while (r.next()) {
                int txIndex = r.getShort(1);
                long timeSpent = r.getLong(2);
                BigInteger value = BigInteger.valueOf(r.getLong(3));
                byte[] scriptBytes = r.getBytes(4);
                int blockHeight = r.getInt(5);
                boolean isCoinbase = r.getBoolean(6);
                StoredOutput output = new StoredOutput(txIndex, value, scriptBytes,
                                                       isCoinbase, (timeSpent!=0), blockHeight);
                outputList.add(output);
            }
        } catch (SQLException exc) {
            log.error(String.format("Unable to get transaction outputs\n  Tx %s", txHash), exc);
            throw new BlockStoreException("Unable to get transaction outputs", txHash);
        }
        return outputList;
    }

    /**
     * Deletes spent transaction outputs that are older than the maximum transaction age
     *
     * @throws      BlockStoreException     Unable to delete spent transaction outputs
     */
    @Override
    public void deleteSpentTxOutputs() throws BlockStoreException {
        Connection conn = getConnection();
        long ageLimit = Math.max(chainTime-MAX_TX_AGE, 0);
        int deletedCount = 0;
        //
        // Delete spent outputs in increments of 1000 to reduce the time that other
        // transactions are locked out of the database
        //
        log.info("Deleting spent transaction outputs");
        try (PreparedStatement s = conn.prepareStatement("DELETE FROM TxOutputs WHERE db_id IN "
                            + "(SELECT db_id FROM TxSpentOutputs WHERE time_spent<? LIMIT 1000)")) {
            s.setLong(1, ageLimit);
            deletedCount = s.executeUpdate();
            s.close();
        } catch (SQLException exc) {
            log.error(String.format("Unable to delete spent transaction outputs", exc));
            throw new BlockStoreException("Unable to delete spent transaction outputs");
        }
        log.info(String.format("Deleted %d spent transaction outputs", deletedCount));
    }

    /**
     * Returns the chain list from the block following the start block up to the stop
     * block.  A maximum of 500 blocks will be returned.  The list will start with the
     * genesis block if the start block is not found.
     *
     * @param       startBlock              The start block
     * @param       stopBlock               The stop block
     * @return                              Block inventory list
     * @throws      BlockStoreException     Unable to get blocks from database
     */
    @Override
    public List<InventoryItem> getChainList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                            throws BlockStoreException {
        //
        // Get the block height for the start block
        //
        int blockHeight = 0;
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT block_height FROM Blocks WHERE block_hash=?")) {
            s.setBytes(1, startBlock.getBytes());
            ResultSet r = s.executeQuery();
            if (r.next())
                blockHeight = Math.max(r.getInt(1), 0);
        } catch (SQLException exc) {
            log.error(String.format("Unable to get start block\n  Block %s", startBlock), exc);
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
     * @param       startHeight             Start block height
     * @param       stopBlock               Stop block
     * @return                              Block inventory list
     * @throws      BlockStoreException     Unable to get blocks from database
     */
    @Override
    public List<InventoryItem> getChainList(int startHeight, Sha256Hash stopBlock)
                                            throws BlockStoreException {
        List<InventoryItem> chainList = new LinkedList<>();
        //
        // Get the chain list starting at the block following the start block and continuing
        // for a maximum of 500 blocks.
        //
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("SELECT block_hash FROM Blocks "+
                        "WHERE block_height>? AND block_height<=? ORDER BY block_height ASC")) {
            s.setInt(1, startHeight);
            s.setInt(2, startHeight+500);
            ResultSet r = s.executeQuery();
            while (r.next()) {
                Sha256Hash blockHash = new Sha256Hash(r.getBytes(1));
                chainList.add(new InventoryItem(InventoryItem.INV_BLOCK, blockHash));
                if (blockHash.equals(stopBlock))
                    break;
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
     * genesis block if the start block is not found.
     *
     * @param       startBlock              The start block
     * @param       stopBlock               The stop block
     * @return                              Block header list
     * @throws      BlockStoreException     Unable to get data from the database
     */
    @Override
    public List<BlockHeader> getHeaderList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                            throws BlockStoreException {
        List<BlockHeader> headerList = new LinkedList<>();
        //
        // Get the start block
        //
        int blockHeight = 0;
        try {
            Connection conn = getConnection();
            ResultSet r;
            try (PreparedStatement s = conn.prepareStatement("SELECT block_height FROM Blocks WHERE block_hash=?")) {
                s.setBytes(1, startBlock.getBytes());
                r = s.executeQuery();
                if (r.next())
                    blockHeight = Math.max(r.getInt(1), 0);
            }
            //
            // If we found the start block, we will start at the block following it.  Otherwise,
            // we will start at the block following the genesis block.
            //
            try (PreparedStatement s = conn.prepareStatement(
                            "SELECT file_number,file_offset,block_height FROM Blocks "+
                            "WHERE block_height>? AND block_height<=? ORDER BY block_height ASC")) {
                s.setInt(1, blockHeight);
                s.setInt(2, blockHeight+2000);
                r = s.executeQuery();
                while (r.next()) {
                    int fileNumber = r.getInt(1);
                    int fileOffset = r.getInt(2);
                    Block block = getBlock(fileNumber, fileOffset);
                    headerList.add(new BlockHeader(block.getBytes(), false));
                }
            }
        } catch (EOFException | SQLException | VerificationException exc) {
            log.error("Unable to get header list", exc);
            throw new BlockStoreException("Unable to get header list");
        }
        return headerList;
    }

    /**
     * Releases a held block for processing
     *
     * @param       blockHash               Block hash
     * @throws      BlockStoreException     Unable to release the block
     */
    @Override
    public void releaseBlock(Sha256Hash blockHash) throws BlockStoreException {
        Connection conn = getConnection();
        try (PreparedStatement s = conn.prepareStatement("UPDATE Blocks SET on_hold=false WHERE block_hash=?")) {
            s.setBytes(1, blockHash.getBytes());
            s.executeUpdate();
        } catch (SQLException exc) {
            log.error(String.format("Unable to release held block\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to release held block");
        }
    }

    /**
     * Stores a block in the database
     *
     * @param       storedBlock             Block to be stored
     * @throws      BlockStoreException     Unable to store the block
     */
    @Override
    public void storeBlock(StoredBlock storedBlock) throws BlockStoreException {
        Block block = storedBlock.getBlock();
        synchronized(lock) {
            //
            // Add the block to the current block file
            //
            int[] fileLocation = storeBlock(block);
            Connection conn = getConnection();
            try (PreparedStatement s1 = conn.prepareStatement(
                        "INSERT INTO Blocks (block_hash,prev_hash,block_height,timestamp,"+
                        "chain_work,on_hold,file_number,file_offset) VALUES(?,?,?,?,?,?,?,?)")) {
                //
                // Store the block in the Blocks table
                //
                s1.setBytes(1, block.getHash().getBytes());
                s1.setBytes(2, block.getPrevBlockHash().getBytes());
                s1.setInt(3, storedBlock.isOnChain() ? storedBlock.getHeight() : -1);
                s1.setLong(4, block.getTimeStamp());
                s1.setBytes(5, storedBlock.getChainWork().toByteArray());
                s1.setBoolean(6, storedBlock.isOnHold());
                s1.setInt(7, fileLocation[0]);
                s1.setInt(8, fileLocation[1]);
                s1.executeUpdate();
            } catch (SQLException exc) {
                log.error(String.format("Unable to store block in database\n  Block %s", storedBlock.getHash()), exc);
                rollback();
                truncateBlockFile(fileLocation);
                throw new BlockStoreException("Unable to store block in database");
            }
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
     * @param       chainHash                   The block hash of the chain head
     * @return                                  List of blocks in the chain leading to the new head
     * @throws      BlockNotFoundException      A block in the chain was not found
     * @throws      BlockStoreException         Unable to get blocks from the database
     * @throws      ChainTooLongException       The block chain is too long
     */
    @Override
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
                PreparedStatement s1;
                try {
                    Sha256Hash prevHash;
                    boolean onHold;
                    int fileNumber;
                    int fileOffset;
                    int blockHeight;
                    BigInteger blockWork;
                    Connection conn = getConnection();
                    ResultSet r;
                    s1 = conn.prepareStatement(
                                "SELECT prev_hash,on_hold,chain_work,block_height,file_number,file_offset "+
                                "FROM Blocks WHERE block_hash=?");
                    while (!onChain) {
                        s1.setBytes(1, blockHash.getBytes());
                        r = s1.executeQuery();
                        if (r.next()) {
                            prevHash = new Sha256Hash(r.getBytes(1));
                            onHold = r.getBoolean(2);
                            blockWork = new BigInteger(r.getBytes(3));
                            blockHeight = r.getInt(4);
                            fileNumber = r.getInt(5);
                            fileOffset = r.getInt(6);
                            onChain = (blockHeight>=0);
                            r.close();
                            if (!onChain) {
                                if (chainList.size() >= 144) {
                                    log.warn(String.format("Chain length exceeds 144 blocks\n  Restart %s", blockHash));
                                    throw new ChainTooLongException("Chain length too long", blockHash);
                                }
                                block = getBlock(fileNumber, fileOffset);
                                chainStoredBlock = new StoredBlock(block, BigInteger.ZERO, -1, false, onHold);
                                blockHash = block.getPrevBlockHash();
                            } else {
                                chainStoredBlock = new StoredBlock(blockHash, prevHash, blockWork, blockHeight);
                            }
                            chainList.add(0, chainStoredBlock);
                        } else {
                            log.warn(String.format("Chain block is not available\n  Block %s", blockHash));
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
     * chain intersect.  A VerificationException will be thrown if a block in the new chain is
     * for a checkpoint block and the block hash doesn't match the checkpoint hash.
     *
     * @param       chainList                   List of all chain blocks starting with the junction block
     *                                          up to and including the new chain head
     * @throws      BlockStoreException         Unable to update the database
     * @throws      VerificationException       Chain verification failed
     */
    @Override
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
                                                    RejectMessage.REJECT_CHECKPOINT, storedBlock.getHash());
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
            PreparedStatement s5 = null;
            PreparedStatement s6 = null;
            try {
                Connection conn = getConnection();
                conn.setAutoCommit(false);
                ResultSet r;
                //
                // The ideal case is where the new block links to the current chain head.
                // If this is not the case, we need to remove all blocks from the block
                // chain following the junction block.
                //
                if (!chainHead.equals(storedBlock.getPrevBlockHash())) {
                    s1 = conn.prepareStatement("SELECT file_number,file_offset FROM Blocks WHERE block_hash=?");
                    s2 = conn.prepareStatement("DELETE FROM TxOutputs WHERE tx_hash=?");
                    s3 = conn.prepareStatement("UPDATE TxOutputs SET time_spent=0 WHERE tx_hash=? AND tx_index=?");
                    s4 = conn.prepareStatement("UPDATE Blocks SET block_height=-1 WHERE block_hash=?");
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
                            log.error(String.format("Chain block not found in Blocks database\n  Block %s", blockHash));
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
                                s3.setShort(2, (short)outIndex);
                                s3.executeUpdate();
                            }
                        }
                        //
                        // Update the block status in the Blocks table
                        //
                        s4.setBytes(1, blockHash.getBytes());
                        s4.executeUpdate();
                        log.info(String.format("Block removed from block chain\n  Block %s", blockHash));
                        //
                        // Advance to the block before this block
                        //
                        blockHash = block.getPrevBlockHash();
                    }
                }
                //
                // Now add the new blocks to the block chain starting with the
                // block following the junction block
                //
                s1 = conn.prepareStatement("SELECT tx_index FROM TxOutputs WHERE tx_hash=? LIMIT 1");
                s2 = conn.prepareStatement("INSERT INTO TxOutputs (tx_hash,tx_index,block_hash,"
                            + "block_height,time_spent,value,script_bytes,is_coinbase) VALUES(?,?,?,0,0,?,?,?)");
                s3 = conn.prepareStatement("UPDATE TxOutputs SET time_spent=?,block_height=? WHERE db_id=?");
                s4 = conn.prepareStatement("UPDATE Blocks SET block_height=?,chain_work=? WHERE block_hash=?");
                s5 = conn.prepareStatement("INSERT INTO TxSpentOutputs (time_spent,db_id) VALUES(?,?)");
                s6 = conn.prepareStatement("SELECT db_id FROM TxOutputs WHERE tx_hash=? AND tx_index=?");
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
                                                                RejectMessage.REJECT_DUPLICATE, txHash);
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
                                    s2.setShort(2, (short)txOutput.getIndex());
                                    s2.setBytes(3, blockHash.getBytes());
                                    s2.setLong(4, txOutput.getValue().longValue());
                                    s2.setBytes(5, txOutput.getScriptBytes());
                                    s2.setBoolean(6, tx.isCoinBase());
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
                        List<TransactionInput> txInputs = tx.getInputs();
                        for (TransactionInput txInput : txInputs) {
                            OutPoint op = txInput.getOutPoint();
                            Sha256Hash outHash = op.getHash();
                            int outIndex = op.getIndex();
                            s6.setBytes(1, outHash.getBytes());
                            s6.setShort(2, (short)outIndex);
                            r = s6.executeQuery();
                            if (!r.next()) {
                                log.error(String.format("Transaction output not found\n  Tx %s",
                                                        tx.getHashAsString()));
                                throw new BlockStoreException("Transaction output not found");
                            }
                            int dbId = r.getInt(1);
                            s3.setLong(1, block.getTimeStamp());
                            s3.setInt(2, blockHeight);
                            s3.setInt(3, dbId);
                            s3.executeUpdate();
                            s5.setLong(1, block.getTimeStamp());
                            s5.setInt(2, dbId);
                            s5.executeUpdate();
                        }
                    }
                    //
                    // Update the block status in the Blocks database
                    //
                    s4.setInt(1, blockHeight);
                    s4.setBytes(2, blockWork.toByteArray());
                    s4.setBytes(3, blockHash.getBytes());
                    s4.executeUpdate();
                    log.info(String.format("Block added to block chain at height %d\n  Block %s",
                                           blockHeight, block.getHashAsString()));
                }
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
        boolean tableExists;
        Connection conn = getConnection();
        try (Statement s = conn.createStatement()) {
            s.executeQuery("SELECT 1 FROM "+table+" WHERE 1 = 2");
            tableExists = true;
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
        Connection conn = getConnection();
        try (Statement s = conn.createStatement()) {
            conn.setAutoCommit(false);
            s.executeUpdate(Settings_Table);
            s.executeUpdate(TxOutputs_Table);
            s.executeUpdate(TxOutputs_IX1);
            s.executeUpdate(TxSpentOutputs_Table);
            s.executeUpdate(TxSpentOutputs_IX1);
            s.executeUpdate(Blocks_Table);
            s.executeUpdate(Blocks_IX1);
            s.executeUpdate(Blocks_IX2);
            s.executeUpdate(Blocks_IX3);
            s.executeUpdate(Alerts_Table);
            s.executeUpdate(Alerts_IX1);
            conn.commit();
            conn.setAutoCommit(true);
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
     * @throws      BlockStoreException     Unable to initialize the database tables
     */
    private void initTables() throws BlockStoreException {
        Connection conn = getConnection();
         try {
            conn.setAutoCommit(false);
            //
            // Initialize the block chain with the genesis block
            //
            Block genesisBlock = new Block(Parameters.GENESIS_BLOCK_BYTES, 0,
                                                Parameters.GENESIS_BLOCK_BYTES.length, false);
            chainHead = genesisBlock.getHash();
            prevChainHead = Sha256Hash.ZERO_HASH;
            chainHeight = 0;
            chainWork = BigInteger.ONE;
            targetDifficulty = NetParams.MAX_TARGET_DIFFICULTY;
            blockFileNumber = 0;
            chainTime = genesisBlock.getTimeStamp();
            //
            // Initialize the Settings table
            //
            try (PreparedStatement s = conn.prepareStatement(
                            "INSERT INTO Settings (schema_name,schema_version) VALUES(?,?)")) {
                s.setString(1, schemaName);
                s.setInt(2, schemaVersion);
                s.executeUpdate();
            }
            //
            // Add the genesis block to the Blocks table
            //
            try (PreparedStatement s = conn.prepareStatement(
                        "INSERT INTO Blocks(block_hash,prev_hash,block_height,timestamp,chain_work,on_hold,"+
                                           "file_number,file_offset) VALUES(?,?,0,?,?,false,0,0)")) {
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
            try (FileOutputStream outFile = new FileOutputStream(blockFile)) {
                byte[] prefixBytes = new byte[8];
                Utils.uint32ToByteArrayLE(NetParams.MAGIC_NUMBER, prefixBytes, 0);
                Utils.uint32ToByteArrayLE(Parameters.GENESIS_BLOCK_BYTES.length, prefixBytes, 4);
                outFile.write(prefixBytes);
                outFile.write(Parameters.GENESIS_BLOCK_BYTES);
            }
            //
            // All done - commit the updates
            //
            conn.commit();
            conn.setAutoCommit(true);
            log.info(String.format("Database initialized with schema version %d.%d",
                                   schemaVersion/100, schemaVersion%100));
        } catch (IOException | SQLException | VerificationException exc) {
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
        Connection conn = getConnection();
        ResultSet r;
        int version = 0;
        try {
            //
            // Get the initial values from the Settings table
            //
            try (PreparedStatement s = conn.prepareStatement("SELECT schema_version FROM Settings "
                            + "WHERE schema_name=?")) {
                s.setString(1, schemaName);
                r = s.executeQuery();
                if (!r.next())
                    throw new BlockStoreException("Incorrect database schema");
                version = r.getInt(1);
                if (version != schemaVersion)
                    throw new BlockStoreException(String.format("Schema version %d.%d is not supported",
                                                                version/100, version%100));
            }
            //
            // Get the current chain values from the chain head block
            //
            try (Statement s = conn.createStatement()) {
                r = s.executeQuery("SELECT block_hash,prev_hash,block_height,chain_work,timestamp,"
                            + "file_number,file_offset "
                            + "FROM Blocks WHERE block_height=(SELECT MAX(block_height) FROM Blocks)");
                if (!r.next())
                    throw new BlockStoreException("Unable to get chain head block");
                chainHead = new Sha256Hash(r.getBytes(1));
                prevChainHead = new Sha256Hash(r.getBytes(2));
                chainHeight = r.getInt(3);
                chainWork = new BigInteger(r.getBytes(4));
                chainTime = r.getLong(5);
                int fileNumber = r.getInt(6);
                int fileOffset = r.getInt(7);
                Block block = getBlock(fileNumber, fileOffset);
                targetDifficulty = block.getTargetDifficulty();
            }
            //
            // Get the cuurrent block file number
            //
            File blockDir = new File(String.format("%s%sBlocks", dataPath, Main.fileSeparator));
            String[] fileList = blockDir.list();
            for (String fileName : fileList) {
                int sep = fileName.lastIndexOf('.');
                if (sep >= 0 && fileName.substring(0, 3).equals("blk") && fileName.substring(sep).equals(".dat"))
                    blockFileNumber = Math.max(blockFileNumber, Integer.parseInt(fileName.substring(3, sep)));
            }
            BigInteger networkDifficulty =
                            NetParams.PROOF_OF_WORK_LIMIT.divide(Utils.decodeCompactBits(targetDifficulty));
            log.info(String.format("Database opened with schema version %d.%d\n"+
                                   "  Chain height %,d, Target difficulty %s, Block File number %d\n"+
                                   "  Chain head %s",
                                   version/100, version%100, chainHeight,
                                   Utils.numberToShortString(networkDifficulty), blockFileNumber, chainHead));
        } catch (SQLException exc) {
            log.error("Unable to get initial table settings", exc);
            throw new BlockStoreException("Unable to get initial table settings");
        }
    }
}
