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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.List;

/**
 * The 'block' message represents a block which isn't in the database yet and consists
 * of a single serialized block.
 */
public class BlockMessage {

    /**
     * Processes a 'block' message
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            Serialized data is too short
     * @throws      InterruptedException    Thread interrupted
     * @throws      IOException             Error reading input stream
     * @throws      VerificationException   Block verification failed
     */
    public static void processBlockMessage(Message msg, ByteArrayInputStream inStream)
                                            throws EOFException, InterruptedException,
                                                   IOException, VerificationException{
        //
        // Deserialize the block
        //
        int blockLength = inStream.available();
        byte[] msgBytes = new byte[blockLength];
        inStream.read(msgBytes);
        Block block = new Block(msgBytes, 0, blockLength, true);
        //
        // Indicate the request is being processed so it won't timeout while
        // the database handler is busy
        //
        synchronized(Parameters.lock) {
            for (PeerRequest chkRequest : Parameters.processedRequests) {
                if (chkRequest.getType()==Parameters.INV_BLOCK &&
                                    chkRequest.getHash().equals(block.getHash())) {
                    chkRequest.setProcessing(true);
                    break;
                }
            }
        }
        //
        // Remove the block transactions from the transaction pool
        //
        List<Transaction> txList = block.getTransactions();
        synchronized(Parameters.lock) {
            txList.stream().map((tx) -> tx.getHash()).map((txHash) -> {
                StoredTransaction storedTx = Parameters.txMap.get(txHash);
                if (storedTx != null) {
                    Parameters.txPool.remove(storedTx);
                    Parameters.txMap.remove(txHash);
                }
                return txHash;
            }).filter((txHash) -> (Parameters.recentTxMap.get(txHash) == null)).map((txHash) -> {
                Parameters.recentTxList.add(txHash);
                return txHash;
            }).forEach((txHash) -> {
                Parameters.recentTxMap.put(txHash, txHash);
            });
            Parameters.blocksReceived++;
        }
        //
        // Add the block to the database handler queue
        //
        Parameters.databaseQueue.put(block);
    }
}
