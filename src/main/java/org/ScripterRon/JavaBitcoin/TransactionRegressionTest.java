/*
 * Copyright 20132014 Ronald Hoffman.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.iq80.leveldb.CompressionType;
import org.iq80.leveldb.DB;
import org.iq80.leveldb.DBException;
import org.iq80.leveldb.Options;

import org.fusesource.leveldbjni.JniDBFactory;
import org.fusesource.leveldbjni.internal.JniDB;

import java.io.File;
import java.io.IOException;

import java.math.BigInteger;

import java.util.Arrays;
import java.util.List;

/**
 * Perform a regression test by verifying the scripts for all transactions in the block chain
 */
public class TransactionRegressionTest {
    
    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(TransactionRegressionTest.class);
        
    /**
     * Perform the transaction regression test
     * 
     * @param       dataPath            Application data path
     * @param       startHeight         Starting block height
     * @param       stopHeight          Stop block height
     */
    public static void start(String dataPath, int startHeight, int stopHeight) {
        log.info(String.format("Starting regression test at block height %d", startHeight));
        Sha256Hash blockHash = Sha256Hash.ZERO_HASH;
        int blockHeight = Math.max(startHeight-1, 0);
        int chainHeight = Math.min(Parameters.blockStore.getChainHeight(), stopHeight);
        DB dbTxScripts = null;
        try {
            //
            // We will keep the output scripts in a LevelDB database for quick access
            //
            Options options = new Options();
            options.createIfMissing(true);
            options.compressionType(CompressionType.NONE);
            options.maxOpenFiles(512);
            File fileTxScripts = new File(String.format("%s%sLevelDB%sTxScripts",
                                          dataPath, Main.fileSeparator, Main.fileSeparator));
            dbTxScripts = JniDBFactory.factory.open(fileTxScripts, options);
            log.info("Compacting output scripts database");
            ((JniDB)dbTxScripts).compactRange(null, null);
            log.info("Compacting completed");
            while (blockHeight < chainHeight) {
                //
                // Get the next block list
                //
                List<Sha256Hash> chainList = Parameters.blockStore.getChainList(blockHeight, Sha256Hash.ZERO_HASH);
                //
                // Process each block in the list
                //
                for (Sha256Hash chainHash : chainList) {
                    blockHeight++;
                    if (blockHeight > chainHeight)
                        break;
                    if (blockHeight%1000 == 0)
                        log.info(String.format("Regression test status: At block height %d", blockHeight));
                    blockHash = chainHash;
                    Block block = Parameters.blockStore.getBlock(blockHash);
                    if (block == null) {
                        log.error(String.format("Chain block not found\n  Block %s", blockHash.toString()));
                        throw new BlockStoreException("Chain block not found", blockHash);
                    }
                    List<Transaction> txList = block.getTransactions();
                    //
                    // Process each transaction in the block
                    //
                    for (Transaction tx : txList) {
                        Sha256Hash txHash = tx.getHash();
                        //
                        // Add the transaction output scripts to our database
                        //
                        List<TransactionOutput> txOutputs = tx.getOutputs();
                        for (int i=0; i<txOutputs.size(); i++) {
                            TransactionOutput txOutput = txOutputs.get(i);
                            byte[] txID = getTxID(txHash, i);
                            if (dbTxScripts.get(txID) == null)
                                dbTxScripts.put(txID, txOutput.getScriptBytes());
                        }
                        //
                        // Coinbase transaction does not have an input script
                        //
                        if (tx.isCoinBase())
                            continue;
                        List<TransactionInput> txInputs = tx.getInputs();
                        //
                        // Process each transaction input
                        //
                        for (TransactionInput txInput : txInputs) {
                            OutPoint outPoint = txInput.getOutPoint();
                            Sha256Hash outTxHash = outPoint.getHash();
                            int outTxIndex = outPoint.getIndex();
                            byte[] txID = getTxID(outTxHash, outTxIndex);
                            byte[] scriptBytes = dbTxScripts.get(txID);
                            if (scriptBytes == null) {
                                log.error(String.format("Connected output script not found\n"+
                                                        "  Input Tx: %s\n  Input Index: %d\n"+
                                                        "  Output Tx: %s\n  Output Index: %d\n",
                                                        txHash.toString(), txInput.getIndex(),
                                                        outTxHash.toString(), outTxIndex));
                                throw new VerificationException("Connected output script not found", txHash);
                            }
                            StoredOutput output = new StoredOutput(outTxIndex, BigInteger.ZERO,
                                                                   scriptBytes, false);
                            boolean isValid = tx.verifyInput(txInput, output);
                            if (!isValid) {
                                log.error(String.format("Signature verification failed on block %d\n"+
                                                        "  Input Tx: %s\n  Input Index: %d\n"+
                                                        "  Output Tx: %s\n  Output Index: %d",
                                                        blockHeight, txHash.toString(), txInput.getIndex(),
                                                        outTxHash.toString(), outTxIndex));
                                throw new VerificationException("Signature verification failed", txHash);
                            }
                        }
                    }
                }
            }
        } catch (BlockStoreException exc) {
            log.error(String.format("Unable to retrieve data\n  Hash %s", exc.getHash()), exc);
        } catch (DBException exc) {
            log.error("Unable to retrieve script from LevelDB database", exc);
        } catch (VerificationException exc) {
            log.error(String.format("Unable to verify transaction\n  Tx %s", exc.getHash()), exc);
        } catch (Exception exc) {
            log.error("Exception during transaction regression test", exc);
        } finally {
            try {
                if (dbTxScripts != null)
                    dbTxScripts.close();
            } catch (IOException exc) {
                // Nothing we can do at this point
            }
        }
        log.info("Transaction regression test completed");
    }
    
    /**
     * Return the transaction ID byte array
     *
     * @param       txHash              Transaction hash
     * @param       txIndex             Transaction index
     * @return                          Database key
     */
    private static byte[] getTxID(Sha256Hash txHash, int txIndex) {
        byte[] bytes = Arrays.copyOf(txHash.getBytes(), 32+4);
        bytes[32] = (byte)(txIndex>>>24);
        bytes[33] = (byte)(txIndex>>>16);
        bytes[34] = (byte)(txIndex>>>8);
        bytes[35] = (byte)txIndex;
        return bytes;
    }
}
