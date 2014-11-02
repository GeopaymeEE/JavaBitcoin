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
import static org.ScripterRon.JavaBitcoin.Main.log;

import org.ScripterRon.BitcoinCore.Alert;
import org.ScripterRon.BitcoinCore.Block;
import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.OutPoint;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.SerializedBuffer;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionInput;
import org.ScripterRon.BitcoinCore.TransactionOutput;
import org.ScripterRon.BitcoinCore.Utils;
import org.ScripterRon.BitcoinCore.VarInt;
import org.ScripterRon.BitcoinCore.VerificationException;

import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBException;
import org.iq80.leveldb.DBIterator;
import org.iq80.leveldb.Options;
import org.iq80.leveldb.WriteOptions;

import org.fusesource.leveldbjni.JniDBFactory;
import org.fusesource.leveldbjni.internal.JniDB;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * BlockStoreLdb uses LevelDB databases to store blocks and transactions.  Each
 * database is stored in a separate subdirectory.
 *
 * BlockChain database
 *   - Key is serialized chain height
 *   - Value is the block hash
 *
 * Blocks database
 *   - Key is the block hash
 *   - Value is serialized BlockEntry
 *
 * Child database
 *   - Key is the parent block hash
 *   - Value is the child block hash
 *
 * TxOutputs database
 *   - Key is serialized TransactionID
 *   - Value is serialized TransactionEntry
 *
 * TxSpent database
 *   - Key is serialized TransactionID
 *   - Value is serialized time spent
 *
 * Alerts database
 *   - Key is serialized alert ID
 *   - Value is serialized AlertEntry
 */
public class BlockStoreLdb extends BlockStore {

    /** BlockChain database */
    private DB dbBlockChain;

    /** Blocks database */
    private DB dbBlocks;

    /** Child database */
    private DB dbChild;

    /** Transaction output database */
    private DB dbTxOutputs;

    /** Spent transaction output database */
    private DB dbTxSpent;

    /** Alert database */
    private DB dbAlert;

    /**
     * Creates a new LevelDB block store
     *
     * @param       dataPath                Application data path
     * @throws      BlockStoreException     Unable to open database
     */
    public BlockStoreLdb(String dataPath) throws BlockStoreException {
        super(dataPath);
        Options options = new Options();
        options.createIfMissing(true);
        options.compressionType(CompressionType.NONE);
        log.info(String.format("LevelDBJni version %s", JniDBFactory.VERSION));
        //
        // Create the LevelDB base directory
        //
        String basePath = dataPath+Main.fileSeparator+"LevelDB";
        String dbPath = basePath+Main.fileSeparator;
        File databaseDir = new File(basePath);
        if (!databaseDir.exists())
            databaseDir.mkdirs();
        try {
            Entry<byte[], byte[]> dbEntry;
            byte[] entryData;
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
            // Open the Alerts database
            //
            options.maxOpenFiles(16);
            File fileAlert = new File(dbPath+"AlertDB");
            dbAlert = JniDBFactory.factory.open(fileAlert, options);
            //
            // Get the initial values from the database
            //
            try (DBIterator it = dbBlockChain.iterator()) {
                it.seekToLast();
                if (it.hasNext()) {
                    dbEntry = it.next();
                    //
                    // Get the current chain head from the BlockChain database
                    //
                    chainHeight = getInteger(dbEntry.getKey());
                    chainHead = new Sha256Hash(dbEntry.getValue());
                    //
                    // Get the chain head block from the Blocks database
                    //
                    entryData = dbBlocks.get(chainHead.getBytes());
                    if (entryData == null) {
                        log.error(String.format("Chain head block not found in Blocks database\n  Block %s",
                                                chainHead));
                        throw new BlockStoreException("Chain head block not found in Blocks database", chainHead);
                    }
                    BlockEntry blockEntry = new BlockEntry(entryData);
                    prevChainHead = blockEntry.getPrevHash();
                    chainWork = blockEntry.getChainWork();
                    chainTime = blockEntry.getTimeStamp();
                    int fileNumber = blockEntry.getFileNumber();
                    int fileOffset = blockEntry.getFileOffset();
                    Block block = getBlock(fileNumber, fileOffset);
                    if (block == null) {
                        log.error(String.format("Unable to get chain header from block file %d, offset %d\n  %s",
                                                fileNumber, fileOffset, chainHead));
                        throw new BlockStoreException("Unable to get chain header from block file", chainHead);
                    }
                    targetDifficulty = block.getTargetDifficulty();
                    //
                    // Add block headers to the database if necessary
                    //
                    if (blockEntry.getHeaderBytes().length == 0)
                        dbUpgrade100();
                    //
                    // Get the cuurrent block file number
                    //
                    File blockDir = new File(String.format("%s%sBlocks", dataPath, Main.fileSeparator));
                    String[] fileList = blockDir.list();
                    for (String fileName : fileList) {
                        int sep = fileName.lastIndexOf('.');
                        if (sep >= 0) {
                            if (fileName.substring(0, 3).equals("blk") && fileName.substring(sep).equals(".dat")) {
                                blockFileNumber = Math.max(blockFileNumber,
                                                           Integer.parseInt(fileName.substring(3, sep)));
                            }
                        }
                    }
                    //
                    // Initialization complete
                    //
                    BigInteger networkDifficulty =
                            NetParams.PROOF_OF_WORK_LIMIT.divide(Utils.decodeCompactBits(targetDifficulty));
                    String displayDifficulty = Utils.numberToShortString(networkDifficulty);
                    log.info(String.format("Database initialized\n"+
                                           "  Chain height %d, Target difficulty %s, Block file number %d\n"+
                                           "  Chain head %s",
                                           chainHeight, displayDifficulty, blockFileNumber, chainHead));
                } else {
                    //
                    // We are creating a new database, so delete any existing block files
                    //
                    File dirFile = new File(String.format("%s%sBlocks", dataPath, Main.fileSeparator));
                    if (dirFile == null)
                        throw new BlockStoreException("Unable to delete existing block files");
                    File[] fileList = dirFile.listFiles();
                    for (File file : fileList)
                        file.delete();
                    //
                    // Get the genesis block
                    //
                    Block genesisBlock = new Block(Parameters.GENESIS_BLOCK_BYTES, 0,
                                                   Parameters.GENESIS_BLOCK_BYTES.length, false);
                    //
                    // Initialize values based on the genesis block
                    //
                    chainHead = genesisBlock.getHash();
                    prevChainHead = Sha256Hash.ZERO_HASH;
                    chainHeight = 0;
                    chainWork = BigInteger.ONE;
                    targetDifficulty = NetParams.MAX_TARGET_DIFFICULTY;
                    chainTime = genesisBlock.getTimeStamp();
                    blockFileNumber = 0;
                    //
                    // Store the genesis block and add its entry to the Blocks database
                    //
                    storeBlock(genesisBlock);
                    BlockEntry blockEntry = new BlockEntry(prevChainHead, chainHeight, chainWork,
                                                           true, false, chainTime, 0, 0,
                                                           genesisBlock.getHeaderBytes());
                    dbBlocks.put(chainHead.getBytes(), blockEntry.getBytes());
                    //
                    // Add an entry to the BlockChain database for the genesis block
                    //
                    dbBlockChain.put(getIntegerBytes(0), chainHead.getBytes());
                    //
                    // Databases created
                    //
                    log.info("LevelDB databases created");
                }
            }
        } catch (DBException | IOException | BlockStoreException | VerificationException exc) {
            log.error("Unable to initialize block store", exc);
            throw new BlockStoreException("Unable to initialize block store");
        }
    }

    /**
     * Closes the database
     */
    @Override
    public void close() {
        try {
            if (dbBlockChain != null)
                dbBlockChain.close();
            if (dbBlocks != null)
                dbBlocks.close();
            if (dbChild != null)
                dbChild.close();
            if (dbTxOutputs != null)
                dbTxOutputs.close();
            if (dbTxSpent != null)
                dbTxSpent.close();
            if (dbAlert != null)
                dbAlert.close();
        } catch (DBException | IOException exc) {
            log.error("Unable to close LevelDB databases", exc);
        }
    }

    /**
     * Compacts the database tables
     *
     * @throws      BlockStoreException     Unable to compact database
     */
    @Override
    public void compactDatabase() throws BlockStoreException {
        synchronized(lock) {
            try {
                //
                // Compact the database
                //
                log.info("Compacting BlockChain database");
                ((JniDB)dbBlockChain).compactRange(null, null);
                log.info("Compacting Blocks database");
                ((JniDB)dbBlocks).compactRange(null, null);
                log.info("Compacting Child database");
                ((JniDB)dbChild).compactRange(null, null);
                log.info("Compacting TxSpent database");
                ((JniDB)dbTxSpent).compactRange(null, null);
                log.info("Compacting TxOutputs database");
                ((JniDB)dbTxOutputs).compactRange(null, null);
                log.info("Compacting Alert database");
                ((JniDB)dbAlert).compactRange(null, null);
                log.info("Finished compacting databases");
            } catch (DBException exc) {
                log.error("Unable to compact database", exc);
                throw new BlockStoreException("Unable to compact database");
            }
        }
    }

    /**
     * Checks if the alert is already in our database
     *
     * @param       alertID             Alert identifier
     * @return                          TRUE if this is a new alert
     * @throws      BlockStoreException Unable to get the alert status
     */
    @Override
    public boolean isNewAlert(int alertID) throws BlockStoreException {
        boolean newAlert;
        try {
            newAlert = (dbAlert.get(getIntegerBytes(alertID)) == null);
        } catch (DBException exc) {
            log.error(String.format("Unable to check alert status for %d", alertID), exc);
            throw new BlockStoreException("Unable to check alert status");
        }
        return newAlert;
    }

    /**
     * Returns a list of all alerts in the database
     *
     * @return                          List of all alerts
     * @throws      BlockStoreException Unable to get alerts from database
     */
    @Override
    public List<Alert> getAlerts() throws BlockStoreException {
        List<Alert> alerts = new ArrayList<>();
        try {
            try (DBIterator it = dbAlert.iterator()) {
                it.seekToFirst();
                while (it.hasNext()) {
                    Entry<byte[], byte[]> dbEntry = it.next();
                    byte[] entryData = dbEntry.getValue();
                    AlertEntry alertEntry = new AlertEntry(entryData);
                    Alert alert = new Alert(alertEntry.getPayload(), alertEntry.getSignature());
                    alert.setCancel(alertEntry.isCanceled());
                    alerts.add(alert);
                }
            }
        } catch (DBException | IOException exc) {
            log.error("Unable to get alerts from database", exc);
            throw new BlockStoreException("Unable to get alerts from database");
        }
        return alerts;
    }

    /**
     * Stores an alert in out database
     *
     * @param       alert               The alert
     * @throws      BlockStoreException Unable to store the alert
     */
    @Override
    public void storeAlert(Alert alert) throws BlockStoreException {
        try {
            AlertEntry alertEntry = new AlertEntry(alert.getPayload(), alert.getSignature(),
                                                   alert.isCanceled());
            dbAlert.put(getIntegerBytes(alert.getID()), alertEntry.getBytes());
        } catch (DBException exc) {
            log.error("Unable to store alert in Alerts database", exc);
            throw new BlockStoreException("Unable to store alert in Alerts database");
        }
    }

    /**
     * Cancels an alert
     *
     * @param       alertID             Alert identifier
     * @throws      BlockStoreException Unable to update the alert
     */
    @Override
    public void cancelAlert(int alertID) throws BlockStoreException {
        try {
            byte[] idBytes = getIntegerBytes(alertID);
            byte[] entryData = dbAlert.get(idBytes);
            if (entryData != null) {
                AlertEntry alertEntry = new AlertEntry(entryData);
                alertEntry.setCancel(true);
                dbAlert.put(idBytes, alertEntry.getBytes());
            }
        } catch (DBException | IOException exc) {
            log.error("Unable to update the alert in the Alerts database", exc);
            throw new BlockStoreException("Unable to update the alert in the Alerts database");
        }
    }

    /**
     * Checks if the block is already in our database
     *
     * @param       blockHash           The block to check
     * @return                          TRUE if this is a new block
     * @throws      BlockStoreException Unable to get the block status
     */
    @Override
    public boolean isNewBlock(Sha256Hash blockHash) throws BlockStoreException {
        boolean newBlock;
        try {
            newBlock = (dbBlocks.get(blockHash.getBytes()) == null);
        } catch (DBException exc) {
            log.error(String.format("Unable to check block status\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return newBlock;
    }

    /**
     * Checks if the block is on the main chain
     *
     * @param       blockHash           The block to check
     * @return                          TRUE if the block is on the main chain
     * @throws      BlockStoreException Unable to get the block status
     */
    @Override
    public boolean isOnChain(Sha256Hash blockHash) throws BlockStoreException {
        boolean onChain = false;
        try {
            byte[] entryData = dbBlocks.get(blockHash.getBytes());
            if (entryData != null) {
                BlockEntry blockEntry = new BlockEntry(entryData);
                if (blockEntry.isOnChain())
                    onChain = true;
            }
        } catch (DBException | EOFException exc) {
            log.error(String.format("Unable to check block status\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to check block status", blockHash);
        }
        return onChain;
    }

    /**
     * Returns a block that was stored in the database.  The returned block contains the
     * block data sent over the wire and does not include any information about the
     * block location within the block chain.
     *
     * @param       blockHash           Block hash
     * @return                          The block or null if the block is not found
     * @throws      BlockStoreException Unable to get block from database
     */
    @Override
    public Block getBlock(Sha256Hash blockHash) throws BlockStoreException {
        Block block = null;
        try {
            byte[] entryData = dbBlocks.get(blockHash.getBytes());
            if (entryData != null) {
                BlockEntry blockEntry = new BlockEntry(entryData);
                int fileNumber = blockEntry.getFileNumber();
                int fileOffset = blockEntry.getFileOffset();
                block = getBlock(fileNumber, fileOffset);
            }
        } catch (DBException | EOFException exc) {
            log.error(String.format("Unable to get block from database\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get block from database", blockHash);
        }
        return block;
    }

    /**
     * Returns the block hash for the block stored at the specified height.
     *
     * @param       height                  Chain height
     * @return                              The block hash or null if the block is not found
     * @throws      BlockStoreException     Unable to get block from database
     */
    @Override
    public Sha256Hash getBlockId(int height) throws BlockStoreException {
        Sha256Hash blockHash = null;
        try {
            byte[] value = dbBlockChain.get(getIntegerBytes(height));
            if (value != null)
                blockHash = new Sha256Hash(value);
        } catch (DBException exc) {
            log.error(String.format("Unable to get block hash from database: Height %d", height), exc);
            throw new BlockStoreException("Unable to get block hash from database");
        }
        return blockHash;
    }

    /**
     * Returns a block that was stored in the database.  The returned block contains
     * the protocol block plus information about its current location within the block chain.
     *
     * @param       blockHash               The block hash
     * @return                              The stored block or null if the block is not found
     * @throws      BlockStoreException     Unable to store block
     */
    @Override
    public StoredBlock getStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock storedBlock = null;
        try {
            byte[] entryData = dbBlocks.get(blockHash.getBytes());
            if (entryData != null) {
                BlockEntry blockEntry = new BlockEntry(entryData);
                int blockHeight = blockEntry.getHeight();
                BigInteger blockWork = blockEntry.getChainWork();
                boolean onChain = blockEntry.isOnChain();
                boolean onHold = blockEntry.isOnHold();
                int fileNumber = blockEntry.getFileNumber();
                int fileOffset = blockEntry.getFileOffset();
                Block block = getBlock(fileNumber, fileOffset);
                if (block != null)
                    storedBlock = new StoredBlock(block, blockWork, blockHeight, onChain, onHold);
            }
        } catch (DBException | EOFException exc) {
            log.error(String.format("Unable to get block from database\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get block from database", blockHash);
        }
        return storedBlock;
    }

    /**
     * Returns the child block for the specified block
     *
     * @param       blockHash           The parent block hash
     * @return                          The stored block or null if the block is not found
     * @throws      BlockStoreException Unable to get block
     */
    @Override
    public StoredBlock getChildStoredBlock(Sha256Hash blockHash) throws BlockStoreException {
        StoredBlock childStoredBlock = null;
        try {
            byte[] childData = dbChild.get(blockHash.getBytes());
            if (childData != null)
                childStoredBlock = getStoredBlock(new Sha256Hash(childData));
        } catch (DBException exc) {
            log.error(String.format("Unable to get child block\n  Block %s", blockHash), exc);
            throw new BlockStoreException("Unable to get child block");
        }
        return childStoredBlock;
    }

    /**
     * Returns the block status for the most recent blocks in the database.  The maximum
     * number is a guideline and may be exceeded if there are orphan blocks in the database.
     *
     * @param       maxCount            The maximum number of blocks to be returned
     * @return                          A list of BlockStatus objects
     * @throws      BlockStoreException Unable to get block status
     */
    @Override
    public List<BlockStatus> getBlockStatus(int maxCount) throws BlockStoreException {
        List<BlockStatus> blockList = new ArrayList<>(maxCount);
        synchronized(lock) {
            try {
                byte[] entryData;
                Entry<byte[], byte[]> dbEntry;
                BlockEntry blockEntry;
                Sha256Hash blockHash;
                BlockStatus blockStatus;
                //
                // Determine the earliest block time based on the current chain height
                //
                int startHeight = Math.max(chainHeight-maxCount+1, 0);
                entryData = dbBlockChain.get(getIntegerBytes(startHeight));
                if (entryData == null)
                    throw new BlockStoreException("Block chain database is not initialized");
                entryData = dbBlocks.get(entryData);
                if (entryData == null)
                    throw new BlockStoreException("Block database is not initialized");
                blockEntry = new BlockEntry(entryData);
                long earliestBlockTime = blockEntry.getTimeStamp();
                //
                // Get the blocks
                //
                try (DBIterator it = dbBlocks.iterator()) {
                    it.seekToFirst();
                    while (it.hasNext()) {
                        dbEntry = it.next();
                        blockHash = new Sha256Hash(dbEntry.getKey());
                        blockEntry = new BlockEntry(dbEntry.getValue());
                        if (blockEntry.getTimeStamp() >= earliestBlockTime) {
                            blockStatus = new BlockStatus(blockHash, blockEntry.getTimeStamp(),
                                                      blockEntry.getHeight(), blockEntry.isOnChain(),
                                                      blockEntry.isOnHold());
                            blockList.add(blockStatus);
                        }
                    }
                }
            } catch (DBException | IOException exc) {
                log.error("Unable to get block status", exc);
                throw new BlockStoreException("Unable to get block status");
            }
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
        boolean isNew = true;
        try {
            Entry<byte[], byte[]> dbEntry;
            try (DBIterator it = dbTxOutputs.iterator()) {
                it.seek(txHash.getBytes());
                if (it.hasNext()) {
                    dbEntry = it.next();
                    TransactionID txID = new TransactionID(dbEntry.getKey());
                    if (txID.getTxHash().equals(txHash))
                        isNew = false;
                }
            }
        } catch (DBException | IOException exc) {
            log.error(String.format("Unable to check transaction status\n  Tx %s", txHash), exc);
            throw new BlockStoreException("Unable to check transaction status");
        }
        return isNew;
    }

    /**
     * Returns the transaction depth.  A depth of 0 indicates the transaction is not in a block
     * on the current chain.
     *
     * @param       txHash                  Transaction hash
     * @return                              Transaction depth
     * @throws      BlockStoreException     Unable to get transaction depth
     */
    @Override
    public int getTxDepth(Sha256Hash txHash) throws BlockStoreException {
        int txDepth = 0;
        synchronized(lock) {
            try {
                try (DBIterator it = dbTxOutputs.iterator()) {
                    it.seek(txHash.getBytes());
                    if (it.hasNext()) {
                        Entry<byte[], byte[]> dbEntry = it.next();
                        TransactionID txID = new TransactionID(dbEntry.getKey());
                        if (txID.getTxHash().equals(txHash)) {
                            TransactionEntry txEntry = new TransactionEntry(dbEntry.getValue());
                            Sha256Hash blockHash = txEntry.getBlockHash();
                            byte[] entryData = dbBlocks.get(blockHash.getBytes());
                            if (entryData != null) {
                                BlockEntry blockEntry = new BlockEntry(entryData);
                                if (blockEntry.isOnChain())
                                    txDepth = chainHeight - blockEntry.getHeight() + 1;
                            }
                        }
                    }
                }
            } catch (DBException | IOException exc) {
                log.error(String.format("Unable to get transaction depth\n  Tx %s", txHash), exc);
                throw new BlockStoreException("Unable to get transaction depth");
            }
        }
        return txDepth;
    }

    /**
     * Returns the requested transaction output
     *
     * @param       outPoint                Transaction outpoint
     * @return                              Transaction output or null if the transaction is not found
     * @throws      BlockStoreException     Unable to get transaction output status
     */
    @Override
    public StoredOutput getTxOutput(OutPoint outPoint) throws BlockStoreException {
        StoredOutput output = null;
        try {
            TransactionID txID = new TransactionID(outPoint.getHash(), outPoint.getIndex());
            byte[] entryData = dbTxOutputs.get(txID.getBytes());
            if (entryData != null) {
                TransactionEntry txEntry = new TransactionEntry(entryData);
                output = new StoredOutput(outPoint.getIndex(), txEntry.getValue(), txEntry.getScriptBytes(),
                                          txEntry.isCoinBase(), txEntry.getTimeSpent()!=0,
                                          txEntry.getBlockHeight());
            }
        } catch (DBException | EOFException exc) {
            log.error(String.format("Unable to get transaction output\n  Tx %s : %d",
                                    outPoint.getHash(), outPoint.getIndex()), exc);
            throw new BlockStoreException("Unable to get transaction output");
        }
        return output;
    }

    /**
     * Returns the outputs for the specified transaction
     *
     * @param       txHash              Transaction hash
     * @return                          Stored output list or null if the transaction is not found
     * @throws      BlockStoreException Unable to get transaction outputs
     */
    @Override
    public List<StoredOutput> getTxOutputs(Sha256Hash txHash) throws BlockStoreException {
        List<StoredOutput> outputList = null;
        synchronized(lock) {
            try {
                Entry<byte[], byte[]> dbEntry;
                StoredOutput output;
                try (DBIterator it = dbTxOutputs.iterator()) {
                    it.seek(txHash.getBytes());
                    while (it.hasNext()) {
                        dbEntry = it.next();
                        TransactionID txID = new TransactionID(dbEntry.getKey());
                        if (!txID.getTxHash().equals(txHash))
                            break;
                        if (outputList == null)
                            outputList = new ArrayList<>();
                        TransactionEntry txEntry = new TransactionEntry(dbEntry.getValue());
                        output = new StoredOutput(txID.getTxIndex(), txEntry.getValue(),
                                                  txEntry.getScriptBytes(), txEntry.isCoinBase(),
                                                  txEntry.getTimeSpent()!=0, txEntry.getBlockHeight());
                        outputList.add(output);
                    }
                }
            } catch (DBException | IOException exc) {
                log.error(String.format("Unable to get transaction outputs\n  Tx %s", txHash), exc);
                throw new BlockStoreException("Unable to get transaction outputs");
            }
        }
        return outputList;
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
        List<InventoryItem> chainList;
        try {
            int blockHeight = 0;
            byte[] blockData = dbBlocks.get(startBlock.getBytes());
            if (blockData != null) {
                BlockEntry blockEntry = new BlockEntry(blockData);
                if (blockEntry.isOnChain())
                    blockHeight = blockEntry.getHeight();
            }
            chainList = getChainList(blockHeight, stopBlock);
        } catch (DBException | EOFException exc) {
            log.error("Unable to get data from the block chain", exc);
            throw new BlockStoreException("Unable to get data from the block chain");
        }
        return chainList;
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
        List<InventoryItem> chainList = new ArrayList<>(500);
        synchronized(lock) {
            try {
                try (DBIterator it = dbBlockChain.iterator()) {
                    it.seek(getIntegerBytes(startHeight+1));
                    while (it.hasNext()) {
                        Entry<byte[], byte[]> dbEntry = it.next();
                        Sha256Hash blockHash = new Sha256Hash(dbEntry.getValue());
                        chainList.add(new InventoryItem(InventoryItem.INV_BLOCK, blockHash));
                        if (blockHash.equals(stopBlock) || chainList.size() >= 500)
                            break;
                    }
                }
            } catch (DBException | IOException exc) {
                log.error("Unable to get data from the block chain", exc);
                throw new BlockStoreException("Unable to get data from the block chain");
            }
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
     * @return                              Block header list (empty list if one or more blocks not found)
     * @throws      BlockStoreException     Unable to get data from the database
     */
    @Override
    public List<BlockHeader> getHeaderList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                        throws BlockStoreException {
        List<BlockHeader> headerList = new ArrayList<>(2000);
        synchronized(lock) {
            try {
                //
                // Get the height of the start block
                //
                int blockHeight = 0;
                byte[] entryData = dbBlocks.get(startBlock.getBytes());
                if (entryData != null) {
                    BlockEntry blockEntry = new BlockEntry(entryData);
                    if (blockEntry.isOnChain())
                        blockHeight = blockEntry.getHeight();
                }
                //
                // Iterate through the block chain starting with the block following
                // the start block
                //
                try (DBIterator it = dbBlockChain.iterator()) {
                    it.seek(getIntegerBytes(blockHeight+1));
                    while (it.hasNext()) {
                        //
                        // Get the next entry from the BlockChain database
                        //
                        Entry<byte[], byte[]> dbEntry = it.next();
                        Sha256Hash blockHash = new Sha256Hash(dbEntry.getValue());
                        //
                        // Get the block entry from the Blocks database
                        //
                        entryData = dbBlocks.get(blockHash.getBytes());
                        BlockEntry blockEntry = new BlockEntry(entryData);
                        //
                        // Add the block header to the list
                        //
                        headerList.add(new BlockHeader(blockEntry.getHeaderBytes(), false));
                        if (blockHash.equals(stopBlock) || headerList.size() >= 2000)
                            break;
                    }
                }
            } catch (DBException | IOException | VerificationException exc) {
                log.error("Unable to get data from the block chain", exc);
                throw new BlockStoreException("Unable to get data from the block chain");
            }
        }
        return headerList;
    }

    /**
     * Releases a held block for processing
     *
     * @param       blockHash           Block hash
     * @throws      BlockStoreException Unable to release the block
     */
    @Override
    public void releaseBlock(Sha256Hash blockHash) throws BlockStoreException {
        synchronized(lock) {
            try {
                byte[] entryData = dbBlocks.get(blockHash.getBytes());
                if (entryData != null) {
                    BlockEntry blockEntry = new BlockEntry(entryData);
                    blockEntry.setHold(false);
                    dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
                }
            } catch (DBException | EOFException exc) {
                log.error(String.format("Unable to update block status\n  Block %s", blockHash), exc);
                throw new BlockStoreException("Unable to update block status");
            }
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
        synchronized(lock) {
            try {
                Sha256Hash blockHash = storedBlock.getHash();
                Block block = storedBlock.getBlock();
                //
                // Make sure the block is not already in the database
                //
                byte[] entryData = dbBlocks.get(blockHash.getBytes());
                if (entryData != null) {
                    log.error(String.format("Block already exists in the database\n  Block %s", blockHash));
                    throw new BlockStoreException("Block already exists");
                }
                //
                // Store the block in the current block file
                //
                int[] fileLocation = storeBlock(block);
                int fileNumber = fileLocation[0];
                int fileOffset = fileLocation[1];
                //
                // Add an entry to the Blocks database
                //
                BlockEntry blockEntry = new BlockEntry(block.getPrevBlockHash(), storedBlock.getHeight(),
                                                       storedBlock.getChainWork(), storedBlock.isOnChain(),
                                                       storedBlock.isOnHold(), block.getTimeStamp(),
                                                       fileNumber, fileOffset, block.getHeaderBytes());
                dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
                //
                // Add an entry to the Child database if this is the first child block.  There can be
                // multiple child blocks for a chain fork, in which case the child database will be
                // updated when a block is added to the chain.  But we want to make an entry at this
                // point so that we can find children while building the block chain.
                //
                if (dbChild.get(block.getPrevBlockHash().getBytes()) == null)
                    dbChild.put(block.getPrevBlockHash().getBytes(), blockHash.getBytes());
            } catch (DBException exc) {
                log.error(String.format("Unable to store block\n  Block %s", storedBlock.getHash()), exc);
                throw new BlockStoreException("Unable to store block", storedBlock.getHash());
            }
        }
    }

    /**
     * Deletes spent transaction outputs that are older than the maximum transaction age
     *
     * @return                              The number of deleted outputs
     * @throws      BlockStoreException     Unable to delete spent transaction outputs
     */
    @Override
    public int deleteSpentTxOutputs() throws BlockStoreException {
        long ageLimit = chainTime - MAX_TX_AGE;
        int txPurged = 0;
        List<byte[]> purgeList = new ArrayList<>(1000);
        synchronized(lock) {
            try {
                //
                // Delete spent transaction outputs
                //
                log.info("Deleting spent transaction outputs");
                try (DBIterator it = dbTxSpent.iterator()) {
                    it.seekToFirst();
                    while (it.hasNext() && purgeList.size()<2000) {
                        Entry<byte[], byte[]> dbEntry = it.next();
                        long timeSpent = getLong(dbEntry.getValue());
                        if (timeSpent < ageLimit) {
                            purgeList.add(dbEntry.getKey());
                            txPurged++;
                        }
                    }
                }
                WriteOptions options = new WriteOptions();
                options.sync(false);
                for (byte[] purgeList1 : purgeList) {
                    dbTxSpent.delete(purgeList1, options);
                    dbTxOutputs.delete(purgeList1, options);
                }
                log.info(String.format("%,d spent transaction outputs deleted", txPurged));
            } catch (DBException | IOException exc) {
                log.error("Unable to remove spent transactions", exc);
                throw new BlockStoreException("Unable to remove spent transactions");
            }
        }
        return txPurged;
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
     * @return                              List of blocks in the chain leading to the new head
     * @throws      BlockNotFoundException  A block in the chain was not found
     * @throws      BlockStoreException     Unable to get blocks from the database
     * @throws      ChainTooLongException   The block chain is too long
     */
    @Override
    public List<StoredBlock> getJunction(Sha256Hash chainHash)
                         throws BlockNotFoundException, BlockStoreException, ChainTooLongException {
        List<StoredBlock> chainList = new ArrayList<>(150);
        Sha256Hash blockHash = chainHash;
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
                try {
                    boolean onChain = false;
                    while (!onChain) {
                        byte[] entryData = dbBlocks.get(blockHash.getBytes());
                        if (entryData != null) {
                            BlockEntry blockEntry = new BlockEntry(entryData);
                            onChain = blockEntry.isOnChain();
                            boolean onHold = blockEntry.isOnHold();
                            int fileNumber = blockEntry.getFileNumber();
                            int fileOffset = blockEntry.getFileOffset();
                            if (!onChain) {
                                if (chainList.size() >= 25)
                                    throw new ChainTooLongException("Chain length too long", blockHash);
                                Block block = getBlock(fileNumber, fileOffset);
                                if (block == null) {
                                    log.error(String.format("Chain block file %d is not available\n  Block %s",
                                                            fileNumber, blockHash));
                                    throw new BlockNotFoundException("Unable to resolve block chain", blockHash);
                                }
                                chainStoredBlock = new StoredBlock(block, BigInteger.ZERO, 0, false, onHold);
                                blockHash = block.getPrevBlockHash();
                            } else {
                                int blockHeight = blockEntry.getHeight();
                                BigInteger blockWork = blockEntry.getChainWork();
                                chainStoredBlock = new StoredBlock(blockHash, blockEntry.getPrevHash(),
                                                                   blockWork, blockHeight);
                            }
                            chainList.add(0, chainStoredBlock);
                        } else {
                            log.warn(String.format("Chain block is not available\n  Block %s", blockHash));
                            throw new BlockNotFoundException("Unable to resolve block chain", blockHash);
                        }
                    }
                } catch (EOFException | DBException exc) {
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
    @Override
    public void setChainHead(List<StoredBlock> chainList) throws BlockStoreException, VerificationException {
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
        StoredBlock storedBlock = chainList.get(chainList.size()-1);
        //
        // Make the new block the chain head
        //
        synchronized (lock) {
            Sha256Hash blockHash = null;
            Block block;
            BlockEntry blockEntry;
            TransactionEntry txEntry;
            TransactionID txID;
            Sha256Hash txHash;
            byte[] entryData;
            try {
                //
                // The ideal case is where the new block links to the current chain head.
                // If this is not the case, we need to remove all blocks from the block
                // chain following the junction block.
                //
                if (!chainHead.equals(storedBlock.getPrevBlockHash())) {
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
                        entryData = dbBlocks.get(blockHash.getBytes());
                        if (entryData == null) {
                            log.error(String.format("Chain block not found in Blocks database\n  Block %s", blockHash));
                            throw new BlockStoreException("Chain block not found in Blocks database");
                        }
                        blockEntry = new BlockEntry(entryData);
                        //
                        // Get the block from the block file
                        //
                        int fileNumber = blockEntry.getFileNumber();
                        int fileOffset = blockEntry.getFileOffset();
                        block = getBlock(fileNumber, fileOffset);
                        if (block == null) {
                            log.error(String.format("Chain block file %d is not available\n  Block %s",
                                                    fileNumber, blockHash));
                            throw new BlockStoreException("Chain block is not available");
                        }
                        //
                        // Process each transaction in the block
                        //
                        List<Transaction> txList = block.getTransactions();
                        for (Transaction tx : txList) {
                            txHash = tx.getHash();
                            //
                            // Delete the transaction from the TxOutputs database.  It is possible
                            // that the transaction outputs are no longer in the database
                            // if they have been pruned.
                            //
                            int maxIndex = tx.getOutputs().size();
                            for (int i=0; i<maxIndex; i++) {
                                txID = new TransactionID(txHash, i);
                                byte[] idBytes = txID.getBytes();
                                dbTxSpent.delete(idBytes);
                                dbTxOutputs.delete(idBytes);
                            }
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
                                txID = new TransactionID(op.getHash(), op.getIndex());
                                byte[] idBytes = txID.getBytes();
                                entryData = dbTxOutputs.get(idBytes);
                                if (entryData == null)
                                    continue;
                                txEntry = new TransactionEntry(entryData);
                                txEntry.setTimeSpent(0);
                                txEntry.setBlockHeight(0);
                                dbTxOutputs.put(idBytes, txEntry.getBytes());
                                dbTxSpent.delete(idBytes);
                            }
                        }
                        //
                        // Delete the block from the BlockChain database
                        //
                        dbBlockChain.delete(getIntegerBytes(blockEntry.getHeight()));
                        //
                        // Update the block status in the Blocks database
                        //
                        blockEntry.setChain(false);
                        blockEntry.setChainWork(BigInteger.ZERO);
                        blockEntry.setHeight(0);
                        dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
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
                for (int i=1; i<chainList.size(); i++) {
                    storedBlock = chainList.get(i);
                    block = storedBlock.getBlock();
                    blockHash = block.getHash();
                    List<Transaction> txList = block.getTransactions();
                    Map<TransactionID, TransactionEntry> txUpdates = new HashMap<>(txList.size());
                    //
                    // Add the block transactions to the TxOutputs database.  We will skip
                    // unspendable transaction outputs since they will never be spent.
                    //
                    // Unfortunately, before BIP 30 was implemented, there were several
                    // cases where a block contained the same coinbase transaction.  So
                    // we need to check the TxOutputs database first to make sure the transaction
                    // output is not already in the table for a coinbase transaction.  We will
                    // allow a duplicate coinbase transaction if it is in a block before 250,000.
                    //
                    for (Transaction tx : txList) {
                        txHash = tx.getHash();
                        List<TransactionOutput> txOutputs = tx.getOutputs();
                        for (TransactionOutput txOutput : txOutputs) {
                            txID = new TransactionID(txHash, txOutput.getIndex());
                            entryData = dbTxOutputs.get(txID.getBytes());
                            if (entryData != null) {
                                if (!tx.isCoinBase() || storedBlock.getHeight() >= 250000) {
                                    log.error(String.format(
                                            "Height %d: Transaction outputs already in TxOutputs database\n"+
                                            "  Block %s\n  Tx %s",
                                            storedBlock.getHeight(), block.getHashAsString(), txHash));
                                    throw new VerificationException(
                                            "Transaction outputs already in TxOutputs database",
                                            RejectMessage.REJECT_DUPLICATE, txHash);
                                }
                            } else if (txOutput.isSpendable()) {
                                txEntry = new TransactionEntry(blockHash, txOutput.getValue(),
                                                               txOutput.getScriptBytes(), 0, 0,
                                                               tx.isCoinBase());
                                txUpdates.put(txID, txEntry);
                            }
                        }
                        //
                        // Connect transaction inputs to transaction outputs and mark them spent.
                        //
                        // We need to ignore inputs for coinbase transactions since they are not
                        // used for spending coins.
                        //
                        // We will also ignore transaction inputs that point to non-existent transaction
                        // outputs.  This is for the case where transactions are not being verified
                        // during an initial block chain load.  Otherwise, the transactions would have
                        // been verified before we were called.
                        //
                        if (tx.isCoinBase())
                            continue;
                        List<TransactionInput> txInputs = tx.getInputs();
                        for (TransactionInput txInput : txInputs) {
                            OutPoint op = txInput.getOutPoint();
                            txID = new TransactionID(op.getHash(), op.getIndex());
                            txEntry = txUpdates.get(txID);
                            if (txEntry == null) {
                                entryData = dbTxOutputs.get(txID.getBytes());
                                if (entryData == null) {
                                    log.warn(String.format(
                                            "Height %d, No mapping found for transaction output\n"+
                                            "  Tx %s\n  Connected output %s : %d",
                                            storedBlock.getHeight(), txHash, op.getHash(), op.getIndex()));
                                    continue;
                                }
                                txEntry = new TransactionEntry(entryData);
                                txUpdates.put(txID, txEntry);
                            }
                            txEntry.setTimeSpent(block.getTimeStamp());
                            txEntry.setBlockHeight(storedBlock.getHeight());
                        }
                    }
                    //
                    // Get the block entry from the Blocks database
                    //
                    entryData = dbBlocks.get(blockHash.getBytes());
                    if (entryData == null) {
                        log.error(String.format("New chain block not found in Blocks database\n  Block %s", blockHash));
                        throw new BlockStoreException("New chain block not found in Blocks database");
                    }
                    blockEntry = new BlockEntry(entryData);
                    //
                    // Write the updated transactions to the Tx database
                    //
                    Set<Entry<TransactionID, TransactionEntry>> updates = txUpdates.entrySet();
                    Iterator<Entry<TransactionID, TransactionEntry>> it = updates.iterator();
                    WriteOptions options = new WriteOptions();
                    options.sync(false);
                    while (it.hasNext()) {
                        Entry<TransactionID, TransactionEntry> entry = it.next();
                        byte[] idBytes = entry.getKey().getBytes();
                        txEntry = entry.getValue();
                        dbTxOutputs.put(idBytes, txEntry.getBytes(), options);
                        if (txEntry.getTimeSpent() != 0)
                            dbTxSpent.put(idBytes, getLongBytes(txEntry.getTimeSpent()), options);
                    }
                    //
                    // Update the block status in the Blocks database
                    //
                    blockEntry.setChain(true);
                    blockEntry.setHeight(storedBlock.getHeight());
                    blockEntry.setChainWork(storedBlock.getChainWork());
                    dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
                    //
                    // Add the block to the chain
                    //
                    int blockHeight = storedBlock.getHeight();
                    dbBlockChain.put(getIntegerBytes(blockHeight), blockHash.getBytes());
                    log.info(String.format("Block added to block chain at height %d\n  Block %s",
                                           storedBlock.getHeight(), blockHash));
                    //
                    // Update the child database in case there are multiple children
                    //
                    dbChild.put(block.getPrevBlockHash().getBytes(), block.getHash().getBytes());
                    //
                    // Update chain head values for the block we just added
                    //
                    chainHead = storedBlock.getHash();
                    prevChainHead = storedBlock.getPrevBlockHash();
                    chainHeight = storedBlock.getHeight();
                    chainWork = storedBlock.getChainWork();
                    targetDifficulty = storedBlock.getBlock().getTargetDifficulty();
                    chainTime = block.getTimeStamp();
                }
            } catch (IOException | DBException exc) {
                log.error("Unable to update block chain", exc);
                throw new BlockStoreException("Unable to update block chain", blockHash);
            }
        }
    }

    /**
     * Upgrade the database from Version 1.00 to 1.01
     *
     * @throws      BlockStoreException     Unable to upgrade the database
     */
    private void dbUpgrade100() throws BlockStoreException {
        try {
            log.info("Upgrading LevelDB database from Version 1.00 to Version 1.01");
            //
            // Build the block list
            //
            Entry<byte[], byte[]> dbEntry;
            List<Sha256Hash> blockList = new ArrayList<>(chainHeight+256);
            try (DBIterator it = dbBlocks.iterator()) {
                it.seekToFirst();
                while (it.hasNext()) {
                    dbEntry = it.next();
                    blockList.add(new Sha256Hash(dbEntry.getKey()));
                }
            }
            //
            // Add the block header for each block to the database
            //
            for (Sha256Hash blockHash : blockList) {
                byte[] entryBytes = dbBlocks.get(blockHash.getBytes());
                BlockEntry blockEntry = new BlockEntry(entryBytes);
                int fileNumber = blockEntry.getFileNumber();
                int fileOffset = blockEntry.getFileOffset();
                Block block = getBlock(fileNumber, fileOffset);
                if (block == null) {
                    log.error(String.format("Block in file %d at position %d is unavailable", fileNumber, fileOffset));
                    throw new BlockStoreException("Unable to upgrade database due to unavailable block");
                }
                blockEntry.setHeaderBytes(block.getHeaderBytes());
                dbBlocks.put(blockHash.getBytes(), blockEntry.getBytes());
            }
            log.info("LevelDB database upgrade completed");
        } catch (IOException | DBException exc) {
            log.error("Unable to upgrade database", exc);
            throw new BlockStoreException("Unable to upgrade database");
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
     *  80 bytes    Header          Block header
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

        /** Block header */
        private byte[] header;

        /**
         * Creates a new BlockEntry
         *
         * @param       prevHash        Previous block hash
         * @param       blockHeight     Block height
         * @param       chainWork       Chain work
         * @param       onChain         TRUE if the block is on the chain
         * @param       onHold          TRUE if the block is held
         * @param       timeStamp       Block timestamp
         * @param       fileNumber      Block file number
         * @param       fileOffset      Block file offset
         * @param       header          Block header
         */
        public BlockEntry(Sha256Hash prevHash, int blockHeight, BigInteger chainWork,
                                        boolean onChain, boolean onHold, long timeStamp,
                                        int fileNumber, int fileOffset, byte[] header) {
            this.prevHash = prevHash;
            this.blockHeight = blockHeight;
            this.chainWork = chainWork;
            this.onChain = onChain;
            this.onHold = onHold;
            this.timeStamp = timeStamp;
            this.fileNumber = fileNumber;
            this.fileOffset = fileOffset;
            this.header = header;
        }

        /**
         * Creates a new BlockEntry from the serialized entry data
         *
         * @param       entryData       Serialized entry data
         * @throws      EOFException    End-of-data processing the serialized data
         */
        public BlockEntry(byte[] entryData) throws EOFException {
            SerializedBuffer inBuffer = new SerializedBuffer(entryData);
            onChain = inBuffer.getBoolean();
            onHold = inBuffer.getBoolean();
            prevHash = new Sha256Hash(inBuffer.getBytes(32));
            chainWork = new BigInteger(inBuffer.getBytes());
            timeStamp = inBuffer.getVarLong();
            blockHeight = inBuffer.getVarInt();
            fileNumber = inBuffer.getVarInt();
            fileOffset = inBuffer.getVarInt();
            if (inBuffer.available() >= BlockHeader.HEADER_SIZE)
                header = inBuffer.getBytes(BlockHeader.HEADER_SIZE);
            else
                header = new byte[0];
        }

        /**
         * Returns the serialized entry data
         *
         * @return      Serialized data stream
         */
        public byte[] getBytes() {
            byte[] workBytes = chainWork.toByteArray();
            SerializedBuffer outBuffer = new SerializedBuffer();
            outBuffer.putBoolean(onChain)
                     .putBoolean(onHold)
                     .putBytes(prevHash.getBytes())
                     .putVarInt(workBytes.length)
                     .putBytes(workBytes)
                     .putVarLong(timeStamp)
                     .putVarInt(blockHeight)
                     .putVarInt(fileNumber)
                     .putVarInt(fileOffset)
                     .putBytes(header);
            return outBuffer.toByteArray();
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

        /**
         * Return the block header bytes
         *
         * @return                      Header bytes
         */
        public byte[] getHeaderBytes() {
            return header;
        }

        /**
         * Set the block header bytes
         *
         * @param       headerBytes     Header bytes
         */
        public void setHeaderBytes(byte[] headerBytes) {
            header = headerBytes;
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
            return (obj!=null && (obj instanceof TransactionID) &&
                            txHash.equals(((TransactionID)obj).txHash) && txIndex==((TransactionID)obj).txIndex);
        }

        /**
         * Returns the hash code
         *
         * @return                  Hash code
         */
        @Override
        public int hashCode() {
            return txHash.hashCode()^txIndex;
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
            SerializedBuffer inBuffer = new SerializedBuffer(entryData);
            blockHash = new Sha256Hash(inBuffer.getBytes(32));
            timeSpent = inBuffer.getVarLong();
            blockHeight = inBuffer.getVarInt();
            value = new BigInteger(inBuffer.getBytes());
            scriptBytes = inBuffer.getBytes();
            isCoinBase = inBuffer.getBoolean();
        }

        /**
         * Returns the serialized data stream
         *
         * @return      Serialized data stream
         */
        public byte[] getBytes() {
            byte[] valueData = value.toByteArray();
            SerializedBuffer outBuffer = new SerializedBuffer();
            outBuffer.putBytes(blockHash.getBytes())
                     .putVarLong(timeSpent)
                     .putVarInt(blockHeight)
                     .putVarInt(valueData.length)
                     .putBytes(valueData)
                     .putVarInt(scriptBytes.length)
                     .putBytes(scriptBytes)
                     .putBoolean(isCoinBase);
            return outBuffer.toByteArray();
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

    /**
     * <p>The Alerts table contains an entry for each alert that we have received.  The
     * key is the alert ID and the value is an instance of AlertEntry.</p>
     *
     * <p>AlertEntry</p>
     * <pre>
     *   Size       Field           Description
     *   ====       =====           ===========
     *   1 byte     IsCanceled      TRUE if the alert has been canceled
     *   VarInt     PayloadLength   Length of the alert payload
     *   Variable   Payload         Alert payload
     *   VarInt     SigLength       Length of the payload signature
     *   Variable   Signature       Alert signature
     * </pre>
     */
    private class AlertEntry {

        /** Cancel status */
        private boolean isCanceled;

        /** Alert payload */
        private final byte[] payload;

        /** Alert signature */
        private final byte[] signature;

        /**
         * Creates a new AlertEntry
         *
         * @param       payload         Alert payload
         * @param       signature       Alert signature
         * @param       isCanceled      TRUE if the alert has been canceled
         */
        public AlertEntry(byte[] payload, byte[] signature, boolean isCanceled) {
            this.isCanceled = isCanceled;
            this.payload = payload;
            this.signature = signature;
        }

        /**
         * Creates a new TransactionEntry
         *
         * @param       entryData       Serialized entry data
         * @throws      EOFException    End-of-data processing serialized data
         */
        public AlertEntry(byte[] entryData) throws EOFException {
            SerializedBuffer inBuffer = new SerializedBuffer(entryData);
            isCanceled = inBuffer.getBoolean();
            payload = inBuffer.getBytes();
            signature = inBuffer.getBytes();
        }

        /**
         * Returns the serialized data stream
         *
         * @return      Serialized data stream
         */
        public byte[] getBytes() {
            SerializedBuffer outBuffer = new SerializedBuffer();
            outBuffer.putBoolean(isCanceled)
                     .putVarInt(payload.length)
                     .putBytes(payload)
                     .putVarInt(signature.length)
                     .putBytes(signature);
            return outBuffer.toByteArray();
        }

        /**
         * Returns the payload
         *
         * @return      Alert payload
         */
        public byte[] getPayload() {
            return payload;
        }

        /**
         * Returns the signature
         *
         * @return      Alert signature
         */
        public byte[] getSignature() {
            return signature;
        }

        /**
         * Checks if the alert has been canceled
         *
         * @return      TRUE if the alert has been canceled
         */
        public boolean isCanceled() {
            return isCanceled;
        }

        /**
         * Set the alert cancel status
         *
         * @param       isCanceled      TRUE if the alert has been canceled
         */
        public void setCancel(boolean isCanceled) {
            this.isCanceled = isCanceled;
        }
    }
}
