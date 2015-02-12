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
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Settings_Table;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Blocks_Table;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Blocks_IX1;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Blocks_IX2;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Blocks_IX3;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.TxOutputs_Table;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.TxOutputs_IX1;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.TxSpentOutputs_Table;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.TxSpentOutputs_IX1;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.Alerts_Table;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.schemaName;
import static org.ScripterRon.JavaBitcoin.BlockStoreSql.schemaVersion;

import org.ScripterRon.BitcoinCore.Sha256Hash;

import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBException;
import org.iq80.leveldb.DBIterator;
import org.iq80.leveldb.Options;
import org.fusesource.leveldbjni.JniDBFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map.Entry;

/**
 * Migrate LevelDB to H2 or H2 to LevelDB
 */
public class MigrateDatabase {

    /** LevelDB BlockChain database */
    private static DB dbBlockChain;

    /** LevelDB Blocks database */
    private static DB dbBlocks;

    /** LevelDB Child database */
    private static DB dbChild;

    /** LevelDB TxOutputs database */
    private static DB dbTxOutputs;

    /** LevelDB TxSpent database */
    private static DB dbTxSpent;

    /** LevelDB Alert database */
    private static DB dbAlert;

    /** H2 database connection */
    private static Connection conn;

    /**
     * Migrate the H2 database to the H2 database
     *
     * @param       dataPath                Application data path
     * @throws      BlockStoreException     Unable to migrate database
     */
    public static void migrateSql(String dataPath) throws BlockStoreException {
        long chainTime = 0;
        ResultSet r;
        //
        // Open the H2 database
        //
        try {
            String databasePath = dataPath.replace('\\', '/');
            String connectionURL = String.format("jdbc:h2:%s/Database/bitcoin;MAX_COMPACT_TIME=15000",
                                                 databasePath);
            conn = DriverManager.getConnection(connectionURL, "SCRIPTERRON", "Bitcoin");
        } catch (SQLException exc) {
            log.error("Unable to open the H2 database", exc);
            throw new BlockStoreException("Unable to open the H2 database");
        }
        //
        // Create the LevelDB database
        //
        try {
            String dirPath = String.format("%s%sLevelDB", dataPath, Main.fileSeparator);
            String dbPath = dirPath+Main.fileSeparator;
            File dirFile = new File(dirPath);
            if (dirFile.exists())
                deleteDirectory(dirFile);
            dirFile.mkdir();
            Options options = new Options();
            options.createIfMissing(true);
            options.compressionType(CompressionType.NONE);
            //
            // Open the BlockChain database
            //
            options.maxOpenFiles(32);
            File fileBlockChain = new File(dbPath+"BlockChainDB");
            dbBlockChain = JniDBFactory.factory.open(fileBlockChain, options);
            //
            // Open the Blocks database
            //
            options.maxOpenFiles(32);
            File fileBlocks = new File(dbPath+"BlocksDB");
            dbBlocks = JniDBFactory.factory.open(fileBlocks, options);
            //
            // Open the Child database
            //
            options.maxOpenFiles(32);
            File fileChild = new File(dbPath+"ChildDB");
            dbChild = JniDBFactory.factory.open(fileChild, options);
            //
            // Open the TxOutputs database
            //
            options.maxOpenFiles(768);
            File fileTxOutputs = new File(dbPath+"TxOutputsDB");
            dbTxOutputs = JniDBFactory.factory.open(fileTxOutputs, options);
            //
            // Open the TxSpent database
            //
            options.maxOpenFiles(32);
            File fileTxSpent = new File(dbPath+"TxSpentDB");
            dbTxSpent = JniDBFactory.factory.open(fileTxSpent, options);
            //
            // Open the Alert database
            //
            options.maxOpenFiles(16);
            File fileAlert = new File(dbPath+"AlertDB");
            dbAlert = JniDBFactory.factory.open(fileAlert, options);
        } catch (DBException | IOException exc) {
            log.error("Unable to create the LevelDB database", exc);
            throw new BlockStoreException("Unable to create the LevelDB database");
        }
        //
        // Migrate the Blocks table
        //
        log.info("Migrating the H2 Blocks table");
        try (Statement s = conn.createStatement()) {
            r = s.executeQuery("SELECT block_hash,prev_hash,timestamp,block_height,chain_work,on_hold,"
                                + "file_number,file_offset,header FROM Blocks");
            while (r.next()) {
                Sha256Hash blockHash = new Sha256Hash(r.getBytes(1));
                Sha256Hash prevHash = new Sha256Hash(r.getBytes(2));
                long timestamp = r.getLong(3);
                int blockHeight = r.getInt(4);
                BigInteger chainWork = new BigInteger(r.getBytes(5));
                boolean onChain = (blockHeight>=0);
                boolean onHold = r.getBoolean(6);
                int fileNumber = r.getInt(7);
                int fileOffset = r.getInt(8);
                byte[] header = r.getBytes(9);
                BlockEntry blockEntry = new BlockEntry(prevHash, blockHeight, chainWork, onChain, onHold,
                                                       timestamp, fileNumber, fileOffset, header);
                dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
                if (onChain || dbChild.get(prevHash.getBytes()) == null) {
                    dbChild.put(prevHash.getBytes(), blockHash.getBytes());
                    dbBlockChain.put(getIntegerBytes(blockHeight), blockHash.getBytes());
                    chainTime = Math.max(chainTime, timestamp);
                }
            }
            r.close();
            log.info("H2 Blocks table migrated");
        } catch (DBException | SQLException exc) {
            log.error("Unable to migrate the Blocks database", exc);
            throw new BlockStoreException("Unable to migrate the Blocks database");
        }
        //
        // Migrate the TxOutputs table
        //
        // We need to process the TxOutputs table in segments because it is so large.
        // The db_id column is used to break the table into 1000-row segments.
        //
        log.info("Migrating the H2 TxOutputs table");
        try (Statement s = conn.createStatement()) {
            long pruneTime = chainTime - BlockStore.MAX_TX_AGE;
            r = s.executeQuery("SELECT MIN(db_id),MAX(db_id) FROM TxOutputs");
            if (!r.next()) {
                log.error("No db_id values returned for the TxOutputs table");
                throw new BlockStoreException("No db_id values returned for the TxOutputs table");
            }
            int lowId = r.getInt(1);
            int highId = r.getInt(2);
            r.close();
            for (int id=lowId; id<=highId; id+=1000) {
                r = s.executeQuery(String.format("SELECT tx_hash,tx_index,block_hash,block_height,time_spent,"
                                + "is_coinbase,value,script_bytes FROM TxOutputs WHERE db_id BETWEEN %d AND %d",
                                id, id+999));
                while (r.next()) {
                    Sha256Hash txHash = new Sha256Hash(r.getBytes(1));
                    int txIndex = r.getInt(2);
                    Sha256Hash blockHash = new Sha256Hash(r.getBytes(3));
                    int blockHeight = r.getInt(4);
                    long timeSpent = r.getLong(5);
                    boolean isCoinbase = r.getBoolean(6);
                    BigInteger value = BigInteger.valueOf(r.getLong(7));
                    byte[] scriptBytes = r.getBytes(8);
                    if (timeSpent>0 && timeSpent<pruneTime)
                        continue;
                    TransactionID txId = new TransactionID(txHash, txIndex);
                    TransactionEntry txEntry = new TransactionEntry(blockHash, value, scriptBytes, timeSpent,
                                                                    blockHeight, isCoinbase);
                    dbTxOutputs.put(txId.getBytes(), txEntry.getBytes());
                    if (timeSpent > 0)
                        dbTxSpent.put(txId.getBytes(), getLongBytes(timeSpent));
                }
                r.close();
            }
            log.info("H2 TxOutputs table migrated");
        } catch (DBException | SQLException exc) {
            log.error("Unable to migrate the TxOutputs database", exc);
            throw new BlockStoreException("Unable to migrate the TxOutputs database");
        }
        //
        // Close the databases
        //
        try {
            dbBlockChain.close();
            dbBlocks.close();
            dbChild.close();
            dbTxOutputs.close();
            dbTxSpent.close();
            dbAlert.close();
            conn.close();
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to close the databases", exc);
        }
        log.info("H2 database migrated to LevelDB database");
    }

    /**
     * Migrate the LevelDB database to the H2 database
     *
     * @param       dataPath                Application data path
     *
     * @throws      BlockStoreException     Unable to migrate database
     */
    public static void migrateLdb(String dataPath) throws BlockStoreException {
        Entry<byte[], byte[]> dbEntry;
        long chainTime = 0;
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
            File h2Database = new File(String.format("%s%sDatabase%sbitcoin.h2.db",
                                                dataPath, Main.fileSeparator, Main.fileSeparator));
            if (h2Database.exists())
                h2Database.delete();
            String databasePath = dataPath.replace('\\', '/');
            String connectionURL = String.format("jdbc:h2:%s/Database/bitcoin;MAX_COMPACT_TIME=15000",
                                                 databasePath);
            conn = DriverManager.getConnection(connectionURL, "SCRIPTERRON", "Bitcoin");
            try (Statement s = conn.createStatement()) {
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
                s.executeUpdate(String.format("INSERT INTO Settings (schema_name,schema_version) VALUES('%s','%s')",
                                              schemaName, schemaVersion));
            }
            log.info("H2 database tables created");
        } catch (SQLException exc) {
            log.error("Unable to create the H2 database tables", exc);
            throw new BlockStoreException("Unable to create the H2 database tables");
        }
        //
        // Migrate the Blocks database
        //
        log.info("Migrating the LevelDB Blocks table");
        try (PreparedStatement s = conn.prepareStatement("INSERT INTO Blocks "
                + "(block_hash_index,block_hash,prev_hash_index, prev_hash,timestamp,"
                + "block_height,chain_work,on_hold,file_number,file_offset,header) "
                + "VALUES(?,?,?,?,?,?,?,?,?,?,?)")) {
            DBIterator it = dbBlocks.iterator();
            it.seekToFirst();
            while (it.hasNext()) {
                dbEntry = it.next();
                byte[] blockHash = dbEntry.getKey();
                BlockEntry blockEntry = new BlockEntry(dbEntry.getValue());
                s.setLong(1, getHashIndex(blockHash));
                s.setBytes(2, blockHash);
                s.setLong(3, getHashIndex(blockEntry.getPrevHash().getBytes()));
                s.setBytes(4, blockEntry.getPrevHash().getBytes());
                s.setLong(5, blockEntry.getTimeStamp());
                s.setInt(6, blockEntry.isOnChain() ? blockEntry.getHeight() : -1);
                s.setBytes(7, blockEntry.getChainWork().toByteArray());
                s.setBoolean(8, blockEntry.isOnHold());
                s.setInt(9, blockEntry.getFileNumber());
                s.setInt(10, blockEntry.getFileOffset());
                s.setBytes(11, blockEntry.getHeaderBytes());
                s.executeUpdate();
                if (blockEntry.getHeight() >= 0)
                    chainTime = Math.max(chainTime, blockEntry.getTimeStamp());
            }
            log.info("H2 Blocks table created");
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to create the H2 Blocks table", exc);
            throw new BlockStoreException("Unable to create the H2 Blocks table");
        }
        //
        // Migrate the TxOutputs database
        //
        log.info("Migrating the LevelDB TxOutputs table");
        long pruneTime = chainTime - BlockStore.MAX_TX_AGE;
        try (PreparedStatement s1 = conn.prepareStatement("INSERT INTO TxOutputs "
                    + "(tx_hash_index,tx_hash,tx_index,block_hash,block_height,time_spent,"
                    + "is_coinbase,value,script_bytes) "
                    + "VALUES(?,?,?,?,?,?,?,?,?)");
                PreparedStatement s2 = conn.prepareStatement("INSERT INTO TxSpentOutputs "
                        + "(time_spent,db_id) VALUES(?,?)")) {
            DBIterator it = dbTxOutputs.iterator();
            it.seekToFirst();
            while (it.hasNext()) {
                dbEntry = it.next();
                TransactionID txId = new TransactionID(dbEntry.getKey());
                TransactionEntry txEntry = new TransactionEntry(dbEntry.getValue());
                if (txEntry.getTimeSpent() > 0 && txEntry.getTimeSpent() < pruneTime)
                    continue;
                s1.setLong(1, getHashIndex(txId.getTxHash().getBytes()));
                s1.setBytes(2, txId.getTxHash().getBytes());
                s1.setShort(3, (short)txId.getTxIndex());
                s1.setBytes(4, txEntry.getBlockHash().getBytes());
                s1.setInt(5, txEntry.getBlockHeight());
                s1.setLong(6, txEntry.getTimeSpent());
                s1.setBoolean(7, txEntry.isCoinBase());
                s1.setLong(8, txEntry.getValue().longValue());
                s1.setBytes(9, txEntry.getScriptBytes());
                s1.executeUpdate();
                if (txEntry.getTimeSpent() > 0) {
                    ResultSet r = s1.getGeneratedKeys();
                    if (!r.next())
                        throw new BlockStoreException("No auto-generated key returned for TxOutputs INSERT");
                    s2.setLong(1, txEntry.getTimeSpent());
                    s2.setInt(2, r.getInt(1));
                    r.close();
                    s2.executeUpdate();
                }
            }
            log.info("H2 TxOutputs and TxSpentOutputs tables created");
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to create the H2 TxOutputs table", exc);
            throw new BlockStoreException("Unable to create the H2 TxOutputs table");
        }
        //
        // Close the databases
        //
        try {
            dbBlocks.close();
            dbTxOutputs.close();
            conn.close();
        } catch (DBException | IOException | SQLException exc) {
            log.error("Unable to close the databases", exc);
        }
        log.info("LevelDB database migrated to H2 database");
    }

    /**
     * Delete a directory
     *
     * @param       dirFile                 Directory to delete
     * @throws      IOException             Unable to delete directory
     */
    private static void deleteDirectory(File dirFile) throws IOException {
        if (dirFile.isDirectory()) {
            File[] fileList = dirFile.listFiles();
            if (fileList == null)
                throw new IOException(String.format("Unable to list '%s'", dirFile.getPath()));
            for (File file : fileList)
                deleteDirectory(file);
            if (!dirFile.delete())
                throw new IOException(String.format("Unable to delete '%s'", dirFile.getPath()));
        } else {
            if (!dirFile.delete())
                throw new IOException(String.format("Unable to delete '%s'", dirFile.getPath()));
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
    private static byte[] getIntegerBytes(int intVal) {
        byte[] intBytes = new byte[4];
        intBytes[0] = (byte)(intVal>>>24);
        intBytes[1] = (byte)(intVal>>>16);
        intBytes[2] = (byte)(intVal>>>8);
        intBytes[3] = (byte)intVal;
        return intBytes;
    }

    /**
     * Get the 8-byte key for a long value.  The key uses big-endian format
     * since LevelDB uses a byte comparator to sort the keys.  This will result
     * in the keys being sorted by ascending value.
     *
     * @param       longVal         Long value
     * @return                      8-byte array containing the integer
     */
    private static byte[] getLongBytes(long longVal) {
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
     * Get the hash index for a SHA-256 hash
     *
     * @param       bytes               SHA-256 hash bytes
     * @return                          Hash index
     */
    private static long getHashIndex(byte[] bytes) {
        return (((long)bytes[24]&0xffL)<<56) | (((long)bytes[25]&0xffL)<<48) |
                        (((long)bytes[26]&0xffL)<<40) | (((long)bytes[27]&0xffl)<<32) |
                        (((long)bytes[28]&0xffL)<<24) | (((long)bytes[29]&0xffL)<<16) |
                        (((long)bytes[30]&0xffL)<<8)  | ((long)bytes[31]&0xffL);
    }
}
