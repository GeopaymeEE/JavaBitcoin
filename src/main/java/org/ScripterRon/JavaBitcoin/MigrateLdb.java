/*
 * Copyright 2014 Ronald Hoffman.
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

import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBException;
import org.iq80.leveldb.DBIterator;
import org.iq80.leveldb.Options;

import org.fusesource.leveldbjni.JniDBFactory;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.Arrays;
import java.util.Map.Entry;

/**
 * Migrate an existing LevelDB database to an H2 database
 */
public class MigrateLdb {

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
    private static final String TxOutputs_IX2 = "CREATE INDEX TxOutputs_IX2 ON TxOutputs(time_spent)";

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

    /** Blocks database */
    private DB dbBlocks;

    /** Transaction output database */
    private DB dbTxOutputs;

    /** H2 database connection */
    private Connection conn;

    /**
     * Migrate the LevelDB database
     *
     * @param       dataPath                Application data path
     *
     * @throws      BlockStoreException     Unable to migrate database
     */
    public MigrateLdb(String dataPath) throws BlockStoreException {
        //
        // Open the LevelDB database
        //
        Options options = new Options();
        options.createIfMissing(false);
        options.compressionType(CompressionType.NONE);
        String basePath = dataPath+Main.fileSeparator+"LevelDB";
        String dbPath = basePath+Main.fileSeparator;
        try {
            //
            // Open the Blocks database
            //
            options.maxOpenFiles(32);
            File fileBlocks = new File(dbPath+"BlocksDB");
            dbBlocks = JniDBFactory.factory.open(fileBlocks, options);
            //
            // Open the TxOutputs database
            //
            options.maxOpenFiles(768);
            File fileTxOutputs = new File(dbPath+"TxOutputsDB");
            dbTxOutputs = JniDBFactory.factory.open(fileTxOutputs, options);
        } catch (DBException | IOException exc) {
            log.error("Unable to open the LevelDB database", exc);
            throw new BlockStoreException("Unable to open the LevelDB database");
        }
        //
        // Create the H2 database
        //
        try {
            String databasePath = dataPath.replace('\\', '/');
            String connectionURL = String.format("jdbc:h2:%s/Database/bitcoin;MAX_COMPACT_TIME=15000;"
                            + "MV_STORE=TRUE;MVCC=FALSE", databasePath);
            conn = DriverManager.getConnection(connectionURL, "ScripterRon", "");
            try (Statement s = conn.createStatement()) {
                s.executeUpdate(Settings_Table);
                s.executeUpdate(TxOutputs_Table);
                s.executeUpdate(TxOutputs_IX1);
                s.executeUpdate(TxOutputs_IX2);
                s.executeUpdate(TxSpentOutputs_Table);
                s.executeUpdate(TxSpentOutputs_IX1);
                s.executeUpdate(Blocks_Table);
                s.executeUpdate(Blocks_IX1);
                s.executeUpdate(Blocks_IX2);
                s.executeUpdate(Blocks_IX3);
                s.executeUpdate(Alerts_Table);
                s.executeUpdate(Alerts_IX1);
                s.executeUpdate(String.format("INSERT INTO Settings (schema_name,schema_version) VALUES('%s','%s')",
                                              schemaName, schemaVersion));
            }
            log.info("H2 database tables created");
        } catch (SQLException exc) {
            log.error("Unable to create the H2 database", exc);
            throw new BlockStoreException("Unable to create the H2 database");
        }
    }

    /**
     * Migrate the LevelDB database
     *
     * @throws      BlockStoreException     Unable to migrate database
     */
    public void migrateDb() throws BlockStoreException {
        Entry<byte[], byte[]> dbEntry;
        //
        // Migrate the Blocks database
        //
        log.info("Migrating the Blocks database");
        try (PreparedStatement s = conn.prepareStatement("INSERT INTO Blocks "
                + "(block_hash,prev_hash,timestamp,block_height,chain_work,on_hold,file_number,file_offset) "
                + "VALUES(?,?,?,?,?,?,?,?)")) {
            DBIterator it = dbBlocks.iterator();
            it.seekToFirst();
            while (it.hasNext()) {
                dbEntry = it.next();
                byte[] blockHash = dbEntry.getKey();
                BlockEntry blockEntry = new BlockEntry(dbEntry.getValue());
                s.setBytes(1, blockHash);
                s.setBytes(2, blockEntry.getPrevHash().getBytes());
                s.setLong(3, blockEntry.getTimeStamp());
                s.setInt(4, blockEntry.isOnChain() ? blockEntry.getHeight() : -1);
                s.setBytes(5, blockEntry.getChainWork().toByteArray());
                s.setBoolean(6, blockEntry.isOnHold());
                s.setInt(7, blockEntry.getFileNumber());
                s.setInt(8, blockEntry.getFileOffset());
                s.executeUpdate();
            }
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to create the Blocks database", exc);
            throw new BlockStoreException("Unable to create the Blocks database");
        }
        //
        // Migrate the TxOutputs database
        //
        log.info("Migrating the TxOutputs database");
        try (PreparedStatement s1 = conn.prepareStatement("INSERT INTO TxOutputs "
                    + "(tx_hash,tx_index,block_hash,block_height,time_spent,is_coinbase,value,script_bytes) "
                    + "VALUES(?,?,?,?,?,?,?,?)");
                PreparedStatement s2 = conn.prepareStatement("INSERT INTO TxSpentOutputs "
                        + "(time_spent,db_id) VALUES(?,?)")) {
            DBIterator it = dbTxOutputs.iterator();
            it.seekToFirst();
            while (it.hasNext()) {
                dbEntry = it.next();
                TransactionID txId = new TransactionID(dbEntry.getKey());
                TransactionEntry txEntry = new TransactionEntry(dbEntry.getValue());
                s1.setBytes(1, txId.getTxHash().getBytes());
                s1.setShort(2, (short)txId.getTxIndex());
                s1.setBytes(3, txEntry.getBlockHash().getBytes());
                s1.setInt(4, txEntry.getBlockHeight());
                s1.setLong(5, txEntry.getTimeSpent());
                s1.setBoolean(6, txEntry.isCoinBase());
                s1.setLong(7, txEntry.getValue().longValue());
                s1.setBytes(8, txEntry.getScriptBytes());
                s1.executeUpdate();
                if (txEntry.getTimeSpent() > 0) {
                    ResultSet r = s1.getGeneratedKeys();
                    if (!r.next())
                        throw new BlockStoreException("No auto-generated key returned for INSERT");
                    s2.setLong(1, txEntry.getTimeSpent());
                    s2.setInt(2, r.getInt(1));
                    s2.executeUpdate();
                }
            }
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to create the TxOutputs database", exc);
            throw new BlockStoreException("Unable to create the TxOutputs database");
        }
        log.info("LevelDB database migrated");
    }

    /**
     * Close the databases
     */
    public void close() {
        try {
            dbBlocks.close();
            dbTxOutputs.close();
            conn.close();
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to close the databases", exc);
        }
    }

    /**
     * Get the 4-byte key for an integer value.  The key uses big-endian format
     * since LevelDB uses a byte comparator to sort the keys.  This will result
     * in the keys being sorted by ascending value.
     *
     * @param       intVal          Integer value
     * @return      4-byte array containing the integer
     */
    private byte[] getIntegerBytes(int intVal) {
        byte[] intBytes = new byte[4];
        intBytes[0] = (byte)(intVal>>>24);
        intBytes[1] = (byte)(intVal>>>16);
        intBytes[2] = (byte)(intVal>>>8);
        intBytes[3] = (byte)intVal;
        return intBytes;
    }

    /**
     * Get the integer value from the 4-byte key
     *
     * @param       key         Key bytes
     * @return      Integer value
     */
    private int getInteger(byte[] key) {
        return (((int)key[0]&0xff)<<24) | (((int)key[1]&0xff)<<16) | (((int)key[2]&0xff)<<8) | ((int)key[3]&0xff);
    }

    /**
     * Get the 8-byte key for a long value.  The key uses big-endian format
     * since LevelDB uses a byte comparator to sort the keys.  This will result
     * in the keys being sorted by ascending value.
     *
     * @param       longVal         Long value
     * @return                      8-byte array containing the integer
     */
    private byte[] getLongBytes(long longVal) {
        byte[] longBytes = new byte[8];
        longBytes[0] = (byte)(longVal>>>56);
        longBytes[1] = (byte)(longVal>>>48);
        longBytes[2] = (byte)(longVal>>>40);
        longBytes[3] = (byte)(longVal>>>32);
        longBytes[4] = (byte)(longVal>>>24);
        longBytes[5] = (byte)(longVal>>>16);
        longBytes[6] = (byte)(longVal>>>8);
        longBytes[7] = (byte)longVal;
        return longBytes;
    }

    /**
     * Get the long value from the 8-byte key
     *
     * @param       key         Key bytes
     * @return                  Long value
     */
    private long getLong(byte[] key) {
        return (((long)key[0]&0xff)<<56) | (((long)key[1]&0xff)<<48) |
                                (((long)key[2]&0xff)<<40) | (((long)key[3]&0xff)<<32) |
                                (((long)key[4]&0xff)<<24) | (((long)key[5]&0xff)<<16) |
                                (((long)key[6]&0xff)<<8)  |  ((long)key[7]&0xff);
    }

    /**
     * <p>The Blocks database contains an entry for each block stored in one
     * of the block files.  The key is the block hash and the value is an
     * instance of BlockEntry.</p>
     *
     * <p>BlockEntry</p>
     * <pre>
     *   Size       Field           Description
     *   ====       =====           ===========
     *   1 byte     OnChain         Block is on the chain
     *   1 byte     OnHold          Block is on hold
     *  32 bytes    PrevHash        Previous block hash
     *  VarBytes    ChainWork       Chain work
     *   VarInt     TimeStamp       Block timestamp
     *   VarInt     BlockHeight     Block height
     *   VarInt     FileNumber      Block file number
     *   VarInt     FileOffset      Block file offset
     * </pre>
     */
    private class BlockEntry {

        /** Previous block hash */
        private Sha256Hash prevHash;

        /** Block height */
        private int blockHeight;

        /** Chain work */
        private BigInteger chainWork;

        /** Block timestamp */
        private long timeStamp;

        /** Block chain status */
        private boolean onChain;

        /** Block hold status */
        private boolean onHold;

        /** Block file number */
        private int fileNumber;

        /** Block file offset */
        private int fileOffset;

        /**
         * Creates a new BlockEntry
         *
         * @param       prevHash        Previous block hash
         * @param       blockHeight     Block height
         * @param       chainWork       Chain work
         * @param       onChain         TRUE if the block is on the chain
         * @param       onHold          TRUE if the block is held
         * @param       timeStamp       Block timestamp
         * @param       fileNumber      The block file number
         * @param       fileOffset      The block file offset
         */
        public BlockEntry(Sha256Hash prevHash, int blockHeight, BigInteger chainWork,
                                        boolean onChain, boolean onHold, long timeStamp,
                                        int fileNumber, int fileOffset) {
            this.prevHash = prevHash;
            this.blockHeight = blockHeight;
            this.chainWork = chainWork;
            this.onChain = onChain;
            this.onHold = onHold;
            this.timeStamp = timeStamp;
            this.fileNumber = fileNumber;
            this.fileOffset = fileOffset;
        }

        /**
         * Creates a new BlockEntry from the serialized entry data
         *
         * @param       entryData       Serialized entry data
         * @throws      EOFException    End-of-data processing the serialized data
         */
        public BlockEntry(byte[] entryData) throws EOFException {
            if (entryData.length < 34)
                throw new EOFException("End-of-data while processing serialized block entry");
            onChain = (entryData[0]==1);
            onHold = (entryData[1]==1);
            prevHash = new Sha256Hash(entryData, 2, 32);
            int offset = 34;
            // Decode chainWork
            VarInt varInt = new VarInt(entryData, offset);
            int length = varInt.toInt();
            offset += varInt.getEncodedSize();
            if (offset+length > entryData.length)
                throw new EOFException("End-of-data while processing BlockEntry");
            byte[] bytes = Arrays.copyOfRange(entryData, offset, offset+length);
            chainWork = new BigInteger(bytes);
            offset += length;
            // Decode timeStamp
            varInt = new VarInt(entryData, offset);
            timeStamp = varInt.toLong();
            offset += varInt.getEncodedSize();
            // Decode blockHeight
            varInt = new VarInt(entryData, offset);
            blockHeight = varInt.toInt();
            offset += varInt.getEncodedSize();
            // Decode fileNumber
            varInt = new VarInt(entryData, offset);
            fileNumber = varInt.toInt();
            offset += varInt.getEncodedSize();
            // Decode fileOffset
            varInt = new VarInt(entryData, offset);
            fileOffset = varInt.toInt();
        }

        /**
         * Returns the serialized entry data
         *
         * @return      Serialized data stream
         */
        public byte[] getBytes() {
            byte[] heightData = VarInt.encode(blockHeight);
            byte[] workBytes = chainWork.toByteArray();
            byte[] workLength = VarInt.encode(workBytes.length);
            byte[] timeData = VarInt.encode(timeStamp);
            byte[] numberData = VarInt.encode(fileNumber);
            byte[] offsetData = VarInt.encode(fileOffset);
            byte[] entryData = new byte[1+1+32+heightData.length+workLength.length+workBytes.length+
                            timeData.length+numberData.length+offsetData.length];
            entryData[0] = (onChain ? (byte)1 : 0);
            entryData[1] = (onHold ? (byte)1 : 0);
            System.arraycopy(prevHash.getBytes(), 0, entryData, 2, 32);
            int offset = 34;
            // Encode chainWork
            System.arraycopy(workLength, 0, entryData, offset, workLength.length);
            offset += workLength.length;
            System.arraycopy(workBytes, 0, entryData, offset, workBytes.length);
            offset += workBytes.length;
            // Encode timeStamp
            System.arraycopy(timeData, 0, entryData, offset, timeData.length);
            offset += timeData.length;
            // Encode blockHeight
            System.arraycopy(heightData, 0, entryData, offset, heightData.length);
            offset += heightData.length;
            // Encode fileNumber
            System.arraycopy(numberData, 0, entryData, offset, numberData.length);
            offset += numberData.length;
            // Encode fileOffset
            System.arraycopy(offsetData, 0, entryData, offset, offsetData.length);
            return entryData;
        }

        /**
         * Returns the previous block hash
         *
         * @return      Block hash
         */
        public Sha256Hash getPrevHash() {
            return prevHash;
        }

        /**
         * Returns the block timestamp
         *
         * @return      Block timestamp
         */
        public long getTimeStamp() {
            return timeStamp;
        }

        /**
         * Returns the block height
         *
         * @return      Block height
         */
        public int getHeight() {
            return blockHeight;
        }

        /**
         * Sets the block height
         *
         * @param       blockHeight     Tne block height
         */
        public void setHeight(int blockHeight) {
            this.blockHeight = blockHeight;
        }

        /**
         * Returns the chain work
         *
         * @return      Chain work
         */
        public BigInteger getChainWork() {
            return chainWork;
        }

        /**
         * Sets the chain work
         *
         * @param       chainWork       Chain work
         */
        public void setChainWork(BigInteger chainWork) {
            this.chainWork = chainWork;
        }

        /**
         * Returns the block chain status
         *
         * @return      TRUE if the block is on the chain
         */
        public boolean isOnChain() {
            return onChain;
        }

        /**
         * Sets the block chain status
         *
         * @param       onChain         TRUE if the block is on the chain
         */
        public void setChain(boolean onChain) {
            this.onChain = onChain;
        }

        /**
         * Return the block hold status
         *
         * @return      TRUE if the block is held
         */
        public boolean isOnHold() {
            return onHold;
        }

        /**
         * Sets the block hold status
         *
         * @param       onHold          TRUE if the block is held
         */
        public void setHold(boolean onHold) {
            this.onHold = onHold;
        }

        /**
         * Returns the block file number
         *
         * @return      Block file number
         */
        public int getFileNumber() {
            return fileNumber;
        }

        /**
         * Sets the block file number
         *
         * @param       fileNumber      The new block file number
         */
        public void setFileNumber(int fileNumber) {
            this.fileNumber = fileNumber;
        }

        /**
         * Returns the block file offset
         *
         * @return      Block file offset
         */
        public int getFileOffset() {
            return fileOffset;
        }

        /**
         * Sets the block file offset
         *
         * @param       fileOffset      The new block file offset
         */
        public void setFileOffset(int fileOffset) {
            this.fileOffset = fileOffset;
        }
    }

    /**
     * TransactionID consists of the transaction hash plus the transaction output index
     */
    private class TransactionID {

        /** Transaction hash */
        private Sha256Hash txHash;

        /** Transaction output index */
        private int txIndex;

        /**
         * Creates the transaction ID
         *
         * @param       txHash          Transaction hash
         * @param       txIndex         Transaction output index
         */
        public TransactionID(Sha256Hash txHash, int txIndex) {
            this.txHash = txHash;
            this.txIndex = txIndex;
        }

        /**
         * Creates the transaction ID from the serialized key data
         *
         * @param       bytes           Serialized key data
         * @throws      EOFException    End-of-data reached
         */
        public TransactionID(byte[] bytes) throws EOFException {
            if (bytes.length < 33)
                throw new EOFException("End-of-data while processing TransactionID");
            txHash = new Sha256Hash(bytes, 0, 32);
            txIndex = new VarInt(bytes, 32).toInt();
        }

        /**
         * Returns the serialized transaction ID
         *
         * @return      Serialized transaction ID
         */
        public byte[] getBytes() {
            byte[] indexData = VarInt.encode(txIndex);
            byte[] bytes = new byte[32+indexData.length];
            System.arraycopy(txHash.getBytes(), 0, bytes, 0, 32);
            System.arraycopy(indexData, 0, bytes, 32, indexData.length);
            return bytes;
        }

        /**
         * Returns the transaction hash
         *
         * @return                  Transaction hash
         */
        public Sha256Hash getTxHash() {
            return txHash;
        }

        /**
         * Returns the transaction output index
         *
         * @return                  Transaction output index
         */
        public int getTxIndex() {
            return txIndex;
        }

        /**
         * Compares two objects
         *
         * @param       obj         Object to compare
         * @return                  TRUE if the objects are equal
         */
        @Override
        public boolean equals(Object obj) {
            boolean areEqual = false;
            if (obj != null && (obj instanceof TransactionID)) {
                TransactionID cmpObj = (TransactionID)obj;
                areEqual = (cmpObj.txHash.equals(txHash) && cmpObj.txIndex == txIndex);
            }
            return areEqual;
        }

        /**
         * Returns the hash code
         *
         * @return                  Hash code
         */
        @Override
        public int hashCode() {
            return txHash.hashCode();
        }
    }

    /**
     * <p>The Transaction outputs table contains an entry for each transaction with an unspent output.
     * The key is a TransactionID and the value is a TransactionEntry.</p>
     *
     * <p>TransactionEntry</p>
     * <pre>
     *   Size       Field           Description
     *   ====       =====           ===========
     *   32 bytes   BlockHash       Block hash for block containing the transaction
     *   VarInt     TimeSpent       Time the transaction was completely spent
     *   VarInt     BlockHeight     Height of block spending this output
     *   VarBytes   Value           The output value
     *   VarBytes   ScriptBytes     The script bytes
     *   Boolean    isCoinBase      TRUE if this is a coinbase entry
     * </pre>
     */
    private class TransactionEntry {

        /** Block hash for the block containing this transaction */
        private Sha256Hash blockHash;

        /** Time when the output was spent */
        private long timeSpent;

        /** Height of block spending this output */
        private int blockHeight;

        /** Value of this output */
        private BigInteger value;

        /** Script bytes */
        private byte[] scriptBytes;

        /** Coinbase transaction */
        private boolean isCoinBase;

        /**
         * Creates a new TransactionEntry
         *
         * @param       blockHash       Block containing this transaction
         * @param       value           Output value
         * @param       scriptBytes     Script bytes
         * @param       timeSpent       Time when all outputs were spent
         * @param       blockHeight     Height of block spending this output
         * @param       isCoinBase      TRUE if this is a coinbase transaction
         */
        public TransactionEntry(Sha256Hash blockHash, BigInteger value, byte[] scriptBytes,
                                        long timeSpent, int blockHeight, boolean isCoinBase) {
            this.blockHash = blockHash;
            this.timeSpent = timeSpent;
            this.value = value;
            this.scriptBytes = scriptBytes;
            this.blockHeight = blockHeight;
            this.isCoinBase = isCoinBase;
        }

        /**
         * Creates a new TransactionEntry from the serialized entry data
         *
         * @param       entryData       Serialized entry data
         * @throws      EOFException    End-of-data processing serialized data
         */
        public TransactionEntry(byte[] entryData) throws EOFException {
            if (entryData.length < 32)
                throw new EOFException("End-of-data while processing TransactionEntry");
            blockHash = new Sha256Hash(entryData, 0, 32);
            int offset = 32;
            // Decode timespent
            VarInt varInt = new VarInt(entryData, offset);
            timeSpent = varInt.toLong();
            offset += varInt.getEncodedSize();
            // Decode blockHeight
            varInt = new VarInt(entryData, offset);
            blockHeight = varInt.toInt();
            offset += varInt.getEncodedSize();
            // Decode value
            varInt = new VarInt(entryData, offset);
            int length = varInt.toInt();
            offset += varInt.getEncodedSize();
            if (offset+length > entryData.length)
                throw new EOFException("End-of-data while processing TransactionEntry");
            byte[] bytes = Arrays.copyOfRange(entryData, offset, offset+length);
            value = new BigInteger(bytes);
            offset += length;
            // Decode scriptBytes
            varInt = new VarInt(entryData, offset);
            length = varInt.toInt();
            offset += varInt.getEncodedSize();
            if (offset+length > entryData.length)
                throw new EOFException("End-of-data while processing TransactionEntry");
            scriptBytes = Arrays.copyOfRange(entryData, offset, offset+length);
            offset += length;
            // Decode isCoinBase
            if (offset > entryData.length)
                throw new EOFException("End-of-data while processing TransactionEntry");
            isCoinBase = (entryData[offset] == 1);
        }

        /**
         * Returns the serialized data stream
         *
         * @return      Serialized data stream
         * @throws      IOException     Unable to create output stream
         */
        public byte[] getBytes() throws IOException {
            byte[] timeData = VarInt.encode(timeSpent);
            byte[] heightData = VarInt.encode(blockHeight);
            byte[] valueData = value.toByteArray();
            byte[] valueLength = VarInt.encode(valueData.length);
            byte[] scriptLength = VarInt.encode(scriptBytes.length);
            byte[] entryData = new byte[32+timeData.length+heightData.length+valueLength.length+
                            valueData.length+scriptLength.length+scriptBytes.length+1];
            System.arraycopy(blockHash.getBytes(), 0, entryData, 0, 32);
            int offset = 32;
            // Encode timeStamp
            System.arraycopy(timeData, 0, entryData, offset, timeData.length);
            offset += timeData.length;
            // Encode blockHeight
            System.arraycopy(heightData, 0, entryData, offset, heightData.length);
            offset += heightData.length;
            // Encode value
            System.arraycopy(valueLength, 0, entryData, offset, valueLength.length);
            offset += valueLength.length;
            System.arraycopy(valueData, 0, entryData, offset, valueData.length);
            offset += valueData.length;
            // Encode scriptBytes
            System.arraycopy(scriptLength, 0, entryData, offset, scriptLength.length);
            offset += scriptLength.length;
            System.arraycopy(scriptBytes, 0, entryData, offset, scriptBytes.length);
            offset += scriptBytes.length;
            // Encode isCoinBase
            entryData[offset] = isCoinBase ? (byte)1 : 0;
            return entryData;
        }

        /**
         * Returns the block hash
         *
         * @return      Block hash
         */
        public Sha256Hash getBlockHash() {
            return blockHash;
        }

        /**
         * Returns the output value
         *
         * @return      Output value
         */
        public BigInteger getValue() {
            return value;
        }

        /**
         * Returns the script bytes
         *
         * @return      Script bytes
         */
        public byte[] getScriptBytes() {
            return scriptBytes;
        }

        /**
         * Checks if this is a coinbase transaction
         *
         * @return      TRUE if this is a coinbase transaction
         */
        public boolean isCoinBase() {
            return isCoinBase;
        }

        /**
         * Returns the time spent
         *
         * @return      Time spent
         */
        public long getTimeSpent() {
            return timeSpent;
        }

        /**
         * Sets the time spent
         *
         * @param       timeSpent       Time spent or zero if all outputs have not been spent
         */
        public void setTimeSpent(long timeSpent) {
            this.timeSpent = timeSpent;
        }

        /**
         * Returns the height of the spending block
         *
         * @return      Block height
         */
        public int getBlockHeight() {
            return blockHeight;
        }

        /**
         * Sets the height of the spending block
         *
         * @param       blockHeight     Height of the spending block
         */
        public void setBlockHeight(int blockHeight) {
            this.blockHeight = blockHeight;
        }
    }

}
