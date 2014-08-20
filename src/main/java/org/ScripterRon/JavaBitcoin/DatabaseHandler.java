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

import org.ScripterRon.BitcoinCore.Block;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.InventoryMessage;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionInput;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

/**
 * The database handler processes blocks placed on the database queue.  When a
 * block is received, the database handler validates the block and adds it
 * to the database.  This can result in the block chain being reorganized because
 * a better chain is now available.
 *
 * The database handler terminates when its shutdown() method is called.
 */
public class DatabaseHandler implements Runnable {

    /** Database timer */
    private Timer timer;

    /** Database shutdown requested */
    private boolean databaseShutdown = false;

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
        // Create a timer to delete spent transaction outputs every 5 minutes
        //
        timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                try {
                    Parameters.blockStore.deleteSpentTxOutputs();
                } catch (BlockStoreException exc) {
                    log.error("Unable to delete spent transaction outputs", exc);
                }
            }
        }, 5*60*1000, 5*60*1000);
        //
        // Process blocks until the shutdown() method is called
        //
        try {
            while (true) {
                Block block = Parameters.databaseQueue.take();
                if (databaseShutdown)
                    break;
                processBlock(block);
            }
        } catch (InterruptedException exc) {
            log.warn("Database handler interrupted", exc);
        } catch (Throwable exc) {
            log.error("Runtime exception while processing blocks", exc);
        }
        //
        // Stopping
        //
        timer.cancel();
        log.info("Database handler stopped");
    }

    /**
     * Shutdown the database handler
     */
    public void shutdown() {
        try {
            databaseShutdown = true;
            Parameters.databaseQueue.put(new ShutdownDatabase());
        } catch (InterruptedException exc) {
            log.warn("Database handler shutdown interrupted", exc);
        }
    }

    /**
     * Process a block
     *
     * @param       block           Block to process
     */
    private void processBlock(Block block) {
        try {
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
            synchronized(Parameters.pendingRequests) {
                Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
                while (it.hasNext()) {
                    PeerRequest request = it.next();
                    if (request.getType()==InventoryItem.INV_BLOCK && request.getHash().equals(block.getHash())) {
                        it.remove();
                        break;
                    }
                }
            }
        } catch (BlockStoreException exc) {
            log.error(String.format("Unable to store block in database\n  Block %s",
                                    block.getHashAsString()), exc);
        }
    }

    /**
     * Process a child block and see if it can now be added to the chain
     *
     * @param       storedBlock             The updated block
     * @return                              Next parent block or null
     * @throws      BlockStoreException     Database error occurred
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
                parentBlock = childStoredBlock;
            }
        }
        return parentBlock;
    }

    /**
     * Remove the transactions in the current block from the memory pool, update the spent outputs map,
     * and retry orphan transactions
     *
     * @param       block                   The current block
     * @throws      BlockStoreException     Database error occurred
     */
    private void updateTxPool(Block block) throws BlockStoreException {
        List<Transaction> txList = block.getTransactions();
        List<StoredTransaction> retryList = new ArrayList<>();
        synchronized(Parameters.txMap) {
            txList.stream().forEach((tx) -> {
                Sha256Hash txHash = tx.getHash();
                //
                // Remove the transaction from the transaction maps
                //
                Parameters.txMap.remove(txHash);
                Parameters.recentTxMap.remove(txHash);
                //
                // Remove spent outputs from the map since they are now updated in the database
                //
                List<TransactionInput> txInputs = tx.getInputs();
                txInputs.stream().forEach((txInput) -> Parameters.spentOutputsMap.remove(txInput.getOutPoint()));
                //
                // Get orphan transactions dependent on this transaction
                //
                List<StoredTransaction> orphanList = Parameters.orphanTxMap.remove(txHash);
                if (orphanList != null)
                    retryList.addAll(orphanList);
            });
        }
        //
        // Retry orphan transactions that are not in the database
        //
        for (StoredTransaction orphan : retryList) {
            if (Parameters.blockStore.isNewTransaction(orphan.getHash()))
                Parameters.networkMessageListener.retryOrphanTransaction(orphan.getTransaction());
        }
    }

    /**
     * Notify peers when a block has been added to the chain
     *
     * @param       storedBlock     The stored block added to the chain
     */
    private void notifyPeers(StoredBlock storedBlock) {
        List<InventoryItem> invList = new ArrayList<>(1);
        invList.add(new InventoryItem(InventoryItem.INV_BLOCK, storedBlock.getHash()));
        Message invMsg = InventoryMessage.buildInventoryMessage(null, invList);
        invMsg.setInventoryType(InventoryItem.INV_BLOCK);
        Parameters.networkHandler.broadcastMessage(invMsg);
    }
}
