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

import java.util.ArrayList;
import java.util.List;

/**
 * The database handler processes blocks placed on the database queue.  When a
 * block is received, the database handler validates the block and adds it
 * to the database.  This can result in the block chain being reorganized because
 * a better chain is now available.
 *
 * The database handler terminates when its shutdown() method is called.
 */
public class DatabaseHandler implements Runnable {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(DatabaseHandler.class);

    /**
     * Creates the database listener
     */
    public DatabaseHandler() {
    }

    /**
     * Starts the database listener running
     */
    @Override
    public void run() {
        log.info("Database handler started");
        //
        // Process blocks until the shutdown() method is called
        //
        try {
            while (true) {
                Block block = Parameters.databaseQueue.take();
                if (block instanceof ShutdownDatabase)
                    break;
                processBlock(block);
                System.gc();
            }
        } catch (InterruptedException exc) {
            log.warn("Database handler interrupted", exc);
        } catch (Throwable exc) {
            log.error("Runtime exception while processing blocks", exc);
        }
        //
        // Stopping
        //
        log.info("Database handler stopped");
    }

    /**
     * Process a block
     *
     * @param       block           Block to process
     */
    private void processBlock(Block block) {
        PeerRequest request = null;
        try {
            //
            // Mark the associated request as being processed so it won't timeout while
            // we are working on it
            //
            synchronized(Parameters.lock) {
                for (PeerRequest chkRequest : Parameters.processedRequests) {
                    if (chkRequest.getType()==Parameters.INV_BLOCK &&
                                                chkRequest.getHash().equals(block.getHash())) {
                        chkRequest.setProcessing(true);
                        request = chkRequest;
                        break;
                    }
                }
            }
            //
            // Process the new block
            //
            if (Parameters.blockStore.isNewBlock(block.getHash())) {
                //
                // Store the block in our database
                //
                List<StoredBlock> chainList = Parameters.blockChain.storeBlock(block);
                //
                // Notify our peers that we have added new blocks to the chain and then
                // see if we have a child block which can now be processed.  To avoid
                // flooding peers with blocks they have already seen, we won't send an
                // 'inv' message if we are more than 3 blocks behind the best network chain.
                //
                if (chainList != null) {
                    for (StoredBlock storedBlock : chainList) {
                        Block chainBlock = storedBlock.getBlock();
                        if (chainBlock != null) {
                            updateTxPool(chainBlock);
                            int chainHeight = storedBlock.getHeight();
                            Parameters.networkChainHeight = Math.max(chainHeight, Parameters.networkChainHeight);
                            if (chainHeight >= Parameters.networkChainHeight-3)
                                notifyPeers(storedBlock);
                        }
                    }
                    StoredBlock parentBlock = chainList.get(chainList.size()-1);
                    while (parentBlock != null)
                        parentBlock = processChildBlock(parentBlock);
                }
            }
            //
            // Remove the request from the processedRequests list
            //
            if (request != null) {
                synchronized(Parameters.lock) {
                    Parameters.processedRequests.remove(request);
                }
            }
        } catch (BlockStoreException exc) {
            log.error(String.format("Unable to store block in database\n  %s",
                                    block.getHashAsString()), exc);
        }
    }

    /**
     * Process a child block and see if it can now be added to the chain
     *
     * @param       storedBlock         The updated block
     * @return                          Next parent block or null
     * @throws      BlockStoreException
     */
    private StoredBlock processChildBlock(StoredBlock storedBlock) throws BlockStoreException {
        StoredBlock parentBlock = null;
        StoredBlock childStoredBlock = Parameters.blockStore.getChildStoredBlock(storedBlock.getHash());
        if (childStoredBlock != null && !childStoredBlock.isOnChain()) {
            //
            // Update the chain with the child block
            //
            Parameters.blockChain.updateBlockChain(childStoredBlock);
            if (childStoredBlock.isOnChain()) {
                updateTxPool(childStoredBlock.getBlock());
                //
                // Notify our peers about this block.  To avoid
                // flooding peers with blocks they have already seen, we won't send an
                // 'inv' message if we are more than 3 blocks behind the best network chain.
                //
                int chainHeight = childStoredBlock.getHeight();
                Parameters.networkChainHeight = Math.max(chainHeight, Parameters.networkChainHeight);
                if (chainHeight >= Parameters.networkChainHeight-3)
                    notifyPeers(childStoredBlock);
                //
                // Continue working our way up the chain
                //
                parentBlock = storedBlock;
            }
        }
        return parentBlock;
    }

    /**
     * Remove the transactions in the current block from the memory pool
     *
     * @param       block           The current block
     */
    private void updateTxPool(Block block) {
        List<Transaction> txList = block.getTransactions();
        synchronized(Parameters.lock) {
            for (Transaction tx : txList) {
                Sha256Hash txHash = tx.getHash();
                StoredTransaction storedTx = Parameters.txMap.get(txHash);
                if (storedTx != null) {
                    Parameters.txPool.remove(storedTx);
                    Parameters.txMap.remove(txHash);
                }
            }
        }
    }

    /**
     * Notify peers when a block has been added to the chain
     *
     * @param       storedBlock     The stored block added to the chain
     */
    private void notifyPeers(StoredBlock storedBlock) {
        Block block = storedBlock.getBlock();
        List<Sha256Hash> blockList = new ArrayList<>(1);
        blockList.add(block.getHash());
        Message invMsg = InventoryMessage.buildInventoryMessage(null, Parameters.INV_BLOCK, blockList);
        Parameters.networkListener.broadcastMessage(invMsg);
    }
}
