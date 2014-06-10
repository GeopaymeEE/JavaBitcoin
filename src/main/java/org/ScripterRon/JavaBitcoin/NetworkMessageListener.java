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

import java.util.List;
import org.ScripterRon.BitcoinCore.AddressMessage;
import org.ScripterRon.BitcoinCore.BloomFilter;
import org.ScripterRon.BitcoinCore.Message;
import static org.ScripterRon.JavaBitcoin.Main.log;

/**
 *
 * @author Ronald Hoffman
 */
public class NetworkMessageListener {

    //**********************************************************************************
    // Receive version message
    //                    VersionAckMessage.buildVersionResponse(msg);
                    peer.incVersionCount();
                    address.setServices(peer.getServices());
                    log.info(String.format("Peer %s: Protocol level %d, Services %d, Agent %s, Height %d, "+
                                           "Relay blocks %s, Relay tx %s",
                             address.toString(), peer.getVersion(), peer.getServices(),
                             peer.getUserAgent(), peer.getHeight(),
                             peer.shouldRelayBlocks()?"Yes":"No",
                             peer.shouldRelayTx()?"Yes":"No"));

    //*********************************************************************************
    // Process verack
    //
                    peer.incVersionCount();

     //*********************************************************************************
     // Process getaddr
     //
     Message addrMsg = AddressMessage.buildAddressMessage(peer, Parameters.peerAddresses,
                                                                         Parameters.listenAddress,
                                                                         Parameters.networkMessageListener);
                    msg.setBuffer(addrMsg.getBuffer());
                    msg.setCommand(addrMsg.getCommand());

    //****************************************************************
    // Process pong message
    //
                    peer.setPing(false);
                    log.info(String.format("'pong' response received from %s", address.toString()));

    //******************************************************************
    // Process the 'filterclear' command
    //
                    BloomFilter filter = peer.getBloomFilter();
                    peer.setBloomFilter(null);
                    if (filter != null) {
                        synchronized(Parameters.lock) {
                            Parameters.bloomFilters.remove(filter);
                        }
                    }
                    log.info(String.format("Bloom filter cleared for peer %s", address.toString()));

    //**********************************************************************************
    // Process AddressMessage
    //
    // Process the addresses and keep any node addresses that are not too old
    //
    long oldestTime = System.currentTimeMillis()/1000 - (30*60);
        for (int i=0; i<addrCount; i++) {
            PeerAddress peerAddress = new PeerAddress(inBuffer);
            if (peerAddress.getTimeStamp() < oldestTime ||
                                    (peerAddress.getServices()&Parameters.NODE_NETWORK) == 0 ||
                                     peerAddress.getAddress().equals(Parameters.listenAddress))
                continue;
            synchronized(Parameters.lock) {
                PeerAddress mapAddress = Parameters.peerMap.get(peerAddress);
                if (mapAddress == null) {
                    boolean added = false;
                    long timeStamp = peerAddress.getTimeStamp();
                    for (int j=0; j<Parameters.peerAddresses.size(); j++) {
                        PeerAddress chkAddress = Parameters.peerAddresses.get(j);
                        if (chkAddress.getTimeStamp() < timeStamp) {
                            Parameters.peerAddresses.add(j, peerAddress);
                            Parameters.peerMap.put(peerAddress, peerAddress);
                            added = true;
                            break;
                        }
                    }
                    if (!added) {
                        Parameters.peerAddresses.add(peerAddress);
                        Parameters.peerMap.put(peerAddress, peerAddress);
                    }
                } else {
                    mapAddress.setTimeStamp(Math.max(mapAddress.getTimeStamp(), peerAddress.getTimeStamp()));
                    mapAddress.setServices(peerAddress.getServices());
                }
            }
        }

    //********************************************************************************************
    // Process AlertMessage
    //
                if (Parameters.blockStore.isNewAlert(alert.getID())) {
            //
            // Store the alert in our database
            //
            Parameters.blockStore.storeAlert(alert);
            //
            // Process alert cancels
            //
            int cancelID = alert.getCancelID();
            if (cancelID != 0)
                Parameters.blockStore.cancelAlert(cancelID);
            List<Integer> cancelSet = alert.getCancelSet();
            for (Integer id : cancelSet)
                Parameters.blockStore.cancelAlert(id.intValue());
            //
            // Broadcast the alert to our peers
            //
            if (alert.getRelayTime() > System.currentTimeMillis()/1000) {
                Message alertMsg = buildAlertMessage(null, alert);
                Parameters.networkListener.broadcastMessage(alertMsg);
            }
        }

    //****************************************************************************************************
    // Process BlockMessage
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
            txList.stream().map((tx) -> tx.getHash())
                .map((txHash) -> {
                    StoredTransaction storedTx = Parameters.txMap.get(txHash);
                    if (storedTx != null) {
                        Parameters.txPool.remove(storedTx);
                        Parameters.txMap.remove(txHash);
                    }
                    return txHash;
                })
                .filter((txHash) -> (Parameters.recentTxMap.get(txHash) == null))
                .forEach((txHash) -> {
                    Parameters.recentTxList.add(txHash);
                    Parameters.recentTxMap.put(txHash, txHash);
                });
            Parameters.blocksReceived++;
        }
        //
        // Add the block to the database handler queue
        //
        Parameters.databaseQueue.put(block);

    //*************************************************************************
    // Filter load message
    //
    // Add the filter to the list of Bloom filters
    //
        synchronized(Parameters.lock) {
            if (oldFilter != null)
                Parameters.bloomFilters.remove(filter);
            Parameters.bloomFilters.add(filter);
        }

    //****************************************************************************
    // Get blocks message
    //
    // Check each locator until we find one that is on the main chain
    //
        if (varCount < 0 || varCount > 500)
            throw new VerificationException(String.format("'getblocks' message contains more than 500 locators"));
        try {
            boolean foundJunction = false;
            Sha256Hash blockHash = null;
            inStream.mark(0);
            for (int i=0; i<varCount; i++) {
                count = inStream.read(bytes, 0, 32);
                if (count < 32)
                    throw new EOFException("End-of-data processing 'getblocks' message");
                blockHash = new Sha256Hash(Utils.reverseBytes(bytes));
                if (Parameters.blockStore.isOnChain(blockHash)) {
                    foundJunction = true;
                    break;
                }
            }
            //
            // We go back to the genesis block if none of the supplied locators are on the main chain
            //
            if (!foundJunction)
                blockHash = new Sha256Hash(Parameters.GENESIS_BLOCK_HASH);
            //
            // Get the stop block
            //
            inStream.reset();
            inStream.skip(varCount*32);
            count = inStream.read(bytes, 0, 32);
            if (count < 32)
                throw new EOFException("End-of-data processing 'getblocks' message");
            Sha256Hash stopHash = new Sha256Hash(bytes);
            //
            // Get the chain list
            //
            List<Sha256Hash> chainList = Parameters.blockStore.getChainList(blockHash, stopHash);
            if (chainList.size() >= InventoryMessage.MAX_INV_ENTRIES)
                peer.setIncomplete(true);
            //
            // Build the 'inv' response
            //
            Message invMsg = InventoryMessage.buildInventoryMessage(peer, Parameters.INV_BLOCK, chainList);
            msg.setBuffer(invMsg.getBuffer());
            msg.setCommand(MessageHeader.INVBLOCK_CMD);
        } catch (BlockStoreException exc) {
            //
            // Can't access the database, so just ignore the 'getblocks' request
            //
        }

    //***************************************************************************
    // Process getdata
    //
    // Process each request
    //
    // If this is a restarted request, we need to skip over the requests that have already
    // been processed as indicated by the restart index contained in the message.
    //
        List<byte[]> notFound = new ArrayList<>(25);
        byte[] invBytes = new byte[36];
        int restart = msg.getRestartIndex();
        msg.setRestartIndex(0);
        if (restart != 0)
            inStream.skip(restart*36);
        for (int i=restart; i<varCount; i++) {
            //
            // Defer the request if we have sent 25 blocks in the current batch
            //
            if (blocksSent == 25) {
                msg.setRestartIndex(i);
                break;
            }
            int count = inStream.read(invBytes);
            if (count < 36)
                throw new EOFException("End-of-data while processing 'getdata' message");
            int invType = (int)Utils.readUint32LE(invBytes, 0);
            Sha256Hash hash = new Sha256Hash(Utils.reverseBytes(invBytes, 4, 32));
            if (invType == Parameters.INV_TX) {
                //
                // Send a transaction from the transaction memory pool.  We won't send more
                // than 500 transactions for a single 'getdata' request
                //
                if (txSent < 500) {
                    StoredTransaction tx;
                    synchronized(Parameters.lock) {
                        tx = Parameters.txMap.get(hash);
                    }
                    if (tx != null) {
                        txSent++;
                        ByteBuffer buffer = MessageHeader.buildMessage("tx", tx.getBytes());
                        Message txMsg = new Message(buffer, peer, MessageHeader.TX_CMD);
                        Parameters.networkListener.sendMessage(txMsg);
                        synchronized(Parameters.lock) {
                            Parameters.txSent++;
                        }
                    } else {
                        notFound.add(Arrays.copyOf(invBytes, 36));
                    }
                } else {
                    notFound.add(Arrays.copyOf(invBytes, 36));
                }
            } else if (invType == Parameters.INV_BLOCK) {
                //
                // Send a block from the database or an archive file.  We will send the
                // blocks in increments of 10 to avoid running out of storage.  If more
                // then 10 blocks are requested, the request will be deferred until 10
                // have been sent, then the request will resume with the next 10 blocks.
                //
                try {
                    Block block = Parameters.blockStore.getBlock(hash);
                    if (block != null) {
                        blocksSent++;
                        ByteBuffer buffer = MessageHeader.buildMessage("block", block.bitcoinSerialize());
                        Message blockMsg = new Message(buffer, peer, MessageHeader.BLOCK_CMD);
                        Parameters.networkListener.sendMessage(blockMsg);
                        synchronized(Parameters.lock) {
                            Parameters.blocksSent++;
                        }
                    } else {
                        notFound.add(Arrays.copyOf(invBytes, 36));
                    }
                } catch (BlockStoreException exc) {
                    notFound.add(Arrays.copyOf(invBytes, 36));
                }
            } else if (invType == Parameters.INV_FILTERED_BLOCK) {
                //
                // Send a filtered block if the peer has loaded a Bloom filter
                //
                BloomFilter filter = peer.getBloomFilter();
                if (filter == null)
                    continue;
                //
                // Get the block from the database and return not found if we don't have it
                //
                Block block;
                try {
                    block = Parameters.blockStore.getBlock(hash);
                } catch (BlockStoreException exc) {
                    block = null;
                }
                if (block == null) {
                    //
                    // Change the inventory type to INV_BLOCK so the client doesn't choke
                    // on the 'notfound' message
                    //
                    Utils.uint32ToByteArrayLE(Parameters.INV_BLOCK, invBytes, 0);
                    notFound.add(Arrays.copyOf(invBytes, 36));
                    continue;
                }
                //
                // Find any matching transactions in the block
                //
                List<Sha256Hash> matches = filter.findMatches(block);
                //
                // Send a 'merkleblock' message followed by 'tx' messages for the matches
                //
                sendMatchedTransactions(peer, block, matches);
            } else {
                //
                // Unrecognized message type
                //
                notFound.add(Arrays.copyOf(invBytes, 36));
            }
        }
        //
        // Create a 'notfound' response if we didn't find all of the requested items
        //
        if (!notFound.isEmpty()) {
            varCount = notFound.size();
            byte[] varBytes = VarInt.encode(varCount);
            byte[] msgData = new byte[varCount*36+varBytes.length];
            System.arraycopy(varBytes, 0, msgData, 0, varBytes.length);
            int offset = varBytes.length;
            for (byte[] invItem : notFound) {
                System.arraycopy(invItem, 0, msgData, offset, 36);
                offset += 36;
            }
            ByteBuffer buffer = MessageHeader.buildMessage("notfound", msgData);
            msg.setBuffer(buffer);
            msg.setCommand(MessageHeader.NOTFOUND_CMD);
        }
    }

//**********************************************
// GetHeaders message
        //
        // Check each locator until we find one that is on the main chain
        //
        try {
            boolean foundJunction = false;
            Sha256Hash blockHash = null;
            inStream.mark(0);
            for (int i=0; i<varCount; i++) {
                count = inStream.read(bytes, 0, 32);
                if (count < 32)
                    throw new EOFException("End-of-data processing 'getheaders' message");
                blockHash = new Sha256Hash(Utils.reverseBytes(bytes));
                if (Parameters.blockStore.isOnChain(blockHash)) {
                    foundJunction = true;
                    break;
                }
            }
            //
            // We go back to the genesis block if none of the supplied locators are on the main chain
            //
            if (!foundJunction)
                blockHash = new Sha256Hash(Parameters.GENESIS_BLOCK_HASH);
            //
            // Get the stop block
            //
            inStream.reset();
            inStream.skip(varCount*32);
            count = inStream.read(bytes, 0, 32);
            if (count < 32)
                throw new EOFException("End-of-data processing 'getheaders' message");
            Sha256Hash stopHash = new Sha256Hash(bytes);
            //
            // Get the chain list
            //
            List<byte[]> chainList = Parameters.blockStore.getHeaderList(blockHash, stopHash);
            //
            // Build the 'headers' response
            //
            Message hdrMsg = HeadersMessage.buildHeadersMessage(peer, chainList);
            msg.setBuffer(hdrMsg.getBuffer());
            msg.setCommand(MessageHeader.HEADERS_CMD);
        } catch (BlockStoreException exc) {
            //
            // Can't access the database, so just ignore the 'getheaders' request
            //
        }
        //********************************************************************************
        // Process INV message
        //
        // Process the inventory vectors
        //
        for (int i=0; i<invCount; i++) {
            int count = inStream.read(bytes);
            if (count < 36)
                throw new EOFException("End-of-data processing 'inv' message");
            int type = (int)Utils.readUint32LE(bytes, 0);
            Sha256Hash hash = new Sha256Hash(Utils.reverseBytes(bytes, 4, 32));
            PeerRequest request = new PeerRequest(hash, type, peer);
            if (type == Parameters.INV_TX) {
                //
                // Ignore large transaction broadcasts (bad clients are sending large
                // inventory lists with unknown transactions over and over again)
                //
                if (invCount > 100)
                    throw new VerificationException("More than 100 tx entries in 'inv' message",
                                                    Parameters.REJECT_INVALID);
                //
                // Ignore known bad transactions
                //
                if (badTransactions.contains(hash))
                    continue;
                //
                // Skip the transaction if we have already seen it
                //
                boolean newTx = false;
                synchronized(Parameters.lock) {
                    if (Parameters.recentTxMap.get(hash) == null)
                        newTx = true;
                }
                if (!newTx)
                    continue;
                //
                // Ignore transactions if we are down-level since they will be orphaned
                // until we catch up to the rest of the network
                //
                if (Parameters.blockStore.getChainHeight() < Parameters.networkChainHeight-100)
                    continue;
                //
                // Request the transaction if it is not in the transaction memory pool
                // and has not been requested.  We add the request at the front of the
                // queue so it does not get stuck behind pending block requests.
                //
                try {
                    if (Parameters.blockStore.isNewTransaction(hash)) {
                        synchronized(Parameters.lock) {
                            if (Parameters.recentTxMap.get(hash) == null &&
                                                !Parameters.pendingRequests.contains(request) &&
                                                !Parameters.processedRequests.contains(request)) {
                                Parameters.pendingRequests.add(0, request);
                            }
                        }
                    }
                } catch (BlockStoreException exc) {
                    // Unable to check database - wait for another inventory broadcast
                }
            } else if (type == Parameters.INV_BLOCK) {
                //
                // Request the block if it is not in the database and has not been requested.
                // Block requests are added to the end of the queue so that we don't hold
                // up transaction requests while we update the block chain.
                //
                try {
                    if (Parameters.blockStore.isNewBlock(hash)) {
                        synchronized(Parameters.lock) {
                            if (!Parameters.pendingRequests.contains(request) &&
                                            !Parameters.processedRequests.contains(request)) {
                                Parameters.pendingRequests.add(request);
                            }
                        }
                    }
                } catch (BlockStoreException exc) {
                    // Unable to check database - wait for another inventory broadcast
                }
            }
        }
//******************************************************************************
// Process a transaction
        //
        // Remove the request from the processedRequests list
        //
        synchronized(Parameters.lock) {
            Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
            while (it.hasNext()) {
                PeerRequest request = it.next();
                if (request.getType()==Parameters.INV_TX && request.getHash().equals(txHash)) {
                    it.remove();
                    break;
                }
            }
        }
        //
        // Ignore the transaction if we have already seen it.  Otherwise, add it to
        // the recent transaction list
        //
        boolean duplicateTx = false;
        synchronized(Parameters.lock) {
            if (Parameters.recentTxMap.get(txHash) != null) {
                duplicateTx = true;
            } else {
                Parameters.recentTxList.add(txHash);
                Parameters.recentTxMap.put(txHash, txHash);
            }
        }
        if (duplicateTx)
            return;
        //
        // Don't relay the transaction if the version is not 1 (BIP0034)
        //
        if (tx.getVersion() != 1)
            throw new VerificationException(String.format("Transaction version %d is not valid", tx.getVersion()),
                                            Parameters.REJECT_NONSTANDARD, txHash);
        //
        // Verify the transaction
        //
        tx.verify(true);
        //
        // Coinbase transaction cannot be relayed
        //
        if (tx.isCoinBase())
            throw new VerificationException("Coinbase transaction cannot be relayed",
                                            Parameters.REJECT_INVALID, txHash);
        //
        // Validate the transaction
        //
        if (!validateTx(tx))
            return;
        //
        // Broadcast the transaction to our peers
        //
        broadcastTx(tx);
        //
        // Process orphan transactions that were waiting on this transaction
        //
        List<StoredTransaction> orphanTxList;
        synchronized(Parameters.lock) {
            orphanTxList = Parameters.orphanTxMap.remove(txHash);
            if (orphanTxList != null) {
                orphanTxList.stream().forEach((orphanStoredTx) -> {
                    Parameters.orphanTxList.remove(orphanStoredTx);
                });
            }
        }
        if (orphanTxList != null) {
            for (StoredTransaction orphanStoredTx : orphanTxList) {
                Transaction orphanTx = orphanStoredTx.getTransaction();
                if (validateTx(orphanTx))
                    broadcastTx(orphanTx);
            }
        }
        //
        // Purge transactions from the memory pool after 15 minutes.  We will limit the
        // transaction lists to 5000 entries each.
        //
        synchronized(Parameters.lock) {
            long oldestTime = System.currentTimeMillis()/1000 - (15*60);
            // Clean up the transaction pool
            while (!Parameters.txPool.isEmpty()) {
                StoredTransaction poolTx = Parameters.txPool.get(0);
                if (poolTx.getTimeStamp()>=oldestTime && Parameters.txPool.size()<=5000)
                    break;
                Parameters.txPool.remove(0);
                Parameters.txMap.remove(poolTx.getHash());
            }
            // Clean up the recent transaction list
            while (Parameters.recentTxList.size() > 5000) {
                Sha256Hash poolHash = Parameters.recentTxList.remove(0);
                Parameters.recentTxMap.remove(poolHash);
            }
            // Clean up the spent outputs list
            while (Parameters.spentOutputsList.size() > 5000) {
                OutPoint outPoint = Parameters.spentOutputsList.remove(0);
                Parameters.spentOutputsMap.remove(outPoint);
            }
            // Clean up the orphan transactions list
            while (Parameters.orphanTxList.size() > 1000) {
                StoredTransaction poolTx = Parameters.orphanTxList.remove(0);
                Parameters.orphanTxMap.remove(poolTx.getParent());
            }
        }
    }
/****************************************
 * mempool message
 *         //
        // Get the list of transaction identifiers in the memory pool (return a maximum
        // of MAX_INV_ENTRIES)
        //
        List<Sha256Hash> txList;
        synchronized(Parameters.lock) {
            txList = new ArrayList<>(Parameters.txPool.size());
            for (StoredTransaction tx : Parameters.txPool) {
                txList.add(tx.getHash());
                if (txList.size() == InventoryMessage.MAX_INV_ENTRIES)
                    break;
            }
        }
        //
        // Build the 'inv' message
        //
        Message invMsg = InventoryMessage.buildInventoryMessage(msg.getPeer(), Parameters.INV_TX, txList);
        msg.setBuffer(invMsg.getBuffer());
        msg.setCommand(invMsg.getCommand());
    }
 */
/***********************
 * ping message received
 *                                         throws EOFException, IOException {
        //
        // BIP0031 adds the 'pong' message and requires an 8-byte nonce in the 'ping'
        // message.  If we receive a 'ping' without a payload, we do not return a
        // 'pong' since the client has not implemented BIP0031.
        //
        if (inStream.available() < 8)
            return;
        byte[] bytes = new byte[8];
        inStream.read(bytes);
        //
        // Build the 'pong' response
        //
        ByteBuffer buffer = MessageHeader.buildMessage("pong", bytes);
        msg.setBuffer(buffer);
        msg.setCommand(MessageHeader.PONG_CMD);
 */
/***************************************
 * reject message received
 *
 *         //
        // Log the message
        //
        log.error(String.format("Message rejected by %s\n  Command %s, Reason %s - %s\n  %s",
                                msg.getPeer().getAddress().toString(), cmd, reason, desc,
                                hash!=null ? Utils.bytesToHexString(hash) : "N/A"));
 */
}

    /**
     * Sends a 'merkleblock' message followed by 'tx' messages for the matched transaction
     *
     * @param       peer            Destination peer
     * @param       block           Block containing the transactions
     * @param       matches         List of matching transactions
     * @throws      IOException     Error creating serialized data stream
     */
    public static void sendMatchedTransactions(Peer peer, Block block, List<Sha256Hash> matches)
                                    throws IOException {
        //
        // Build the index list for the matching transactions
        //
        List<Integer> txIndexes;
        List<Transaction> txList = null;
        if (matches.isEmpty()) {
            txIndexes = new ArrayList<>();
        } else {
            txIndexes = new ArrayList<>(matches.size());
            txList = block.getTransactions();
            int index = 0;
            for (Transaction tx : txList) {
                if (matches.contains(tx.getHash()))
                    txIndexes.add(index);
                index++;
            }
        }
        //
        // Build and send the 'merkleblock' message
        //
        Message blockMsg = MerkleBlockMessage.buildMerkleBlockMessage(peer, block, txIndexes);
        Parameters.networkListener.sendMessage(blockMsg);
        synchronized(Parameters.lock) {
            Parameters.filteredBlocksSent++;
        }
        //
        // Send 'tx' messages for each matching transaction
        //
        for (Integer txIndex : txIndexes) {
            Transaction tx = txList.get(txIndex.intValue());
            byte[] txData = tx.getBytes();
            ByteBuffer buffer = MessageHeader.buildMessage("tx", txData);
            Message txMsg = new Message(buffer, peer, MessageHeader.TX_CMD);
            Parameters.networkListener.sendMessage(txMsg);
            synchronized(Parameters.lock) {
                Parameters.txSent++;
            }
        }
    }

    /**
     * Retry an orphan transaction
     *
     * @param       tx                      Transaction
     */
    public static void retryOrphanTransaction(Transaction tx) {
        try {
            if (validateTx(tx))
                broadcastTx(tx);
        } catch (EOFException | VerificationException exc) {
           // Ignore the transaction since it is no longer valid
        }
    }

    /**
     * Validates the transaction
     *
     * @param       tx                      Transaction
     * @return                              TRUE if the transaction is valid
     * @throws      EOFException            End-of-data processing script
     * @throws      VerificationException   Transaction validation failed
     */
    private static boolean validateTx(Transaction tx) throws EOFException, VerificationException {
        Sha256Hash txHash = tx.getHash();
        BigInteger totalInput = BigInteger.ZERO;
        BigInteger totalOutput = BigInteger.ZERO;
        //
        // Validate the transaction outputs
        //
        List<TransactionOutput> outputs = tx.getOutputs();
        for (TransactionOutput output : outputs) {
            // Dust transactions are not relayed - a dust transaction is one where the minimum
            // relay fee is greater than 1/3 of the output value, assuming a single 148-byte input
            // to spend the output
            BigInteger chkValue = output.getValue().multiply(BigInteger.valueOf(1000)).divide(
                                        BigInteger.valueOf(3*(output.getScriptBytes().length+9+148)));
            if (chkValue.compareTo(Parameters.MIN_TX_RELAY_FEE) < 0)
                throw new VerificationException("Dust transactions are not relayed",
                                                Parameters.REJECT_DUST, tx.getHash());
            // Non-standard payment types are not relayed
            int paymentType = Script.getPaymentType(output.getScriptBytes());
            if (paymentType != ScriptOpCodes.PAY_TO_PUBKEY_HASH &&
                                    paymentType != ScriptOpCodes.PAY_TO_PUBKEY &&
                                    paymentType != ScriptOpCodes.PAY_TO_SCRIPT_HASH &&
                                    paymentType != ScriptOpCodes.PAY_TO_MULTISIG &&
                                    paymentType != ScriptOpCodes.PAY_TO_NOBODY) {
                Main.dumpData("Failing Script", output.getScriptBytes());
                throw new VerificationException("Non-standard payment types are not relayed",
                                                Parameters.REJECT_NONSTANDARD, txHash);
            }
            // Add the output value to the total output value for the transaction
            totalOutput = totalOutput.add(output.getValue());
        }
        //
        // Validate the transaction inputs
        //
        List<OutPoint> spentOutputs = new ArrayList<>();
        List<TransactionInput> inputs = tx.getInputs();
        boolean orphanTx = false;
        boolean duplicateTx = false;
        Sha256Hash orphanHash = null;
        for (TransactionInput input : inputs) {
            // Script size must not exceed 500 bytes
            if (input.getScriptBytes().length > 500)
                throw new VerificationException("Input script size greater than 500 bytes",
                                                Parameters.REJECT_NONSTANDARD, txHash);
            // Connected output must not be spent
            OutPoint outPoint = input.getOutPoint();
            StoredOutput output = null;
            Sha256Hash spendHash;
            boolean outputSpent = false;
            synchronized(Parameters.lock) {
                spendHash = Parameters.spentOutputsMap.get(outPoint);
            }
            if (spendHash == null) {
                // Connected output is not in the recently spent list, check the memory pool
                StoredTransaction outTx;
                synchronized(Parameters.lock) {
                    outTx = Parameters.txMap.get(outPoint.getHash());
                }
                if (outTx != null) {
                    // Transaction is in the memory pool, get the connected output
                    Transaction poolTx = outTx.getTransaction();
                    List<TransactionOutput> txOutputs = poolTx.getOutputs();
                    for (TransactionOutput txOutput : txOutputs) {
                        if (txOutput.getIndex() == outPoint.getIndex()) {
                            totalInput = totalInput.add(txOutput.getValue());
                            output = new StoredOutput(txOutput.getIndex(), txOutput.getValue(),
                                                      txOutput.getScriptBytes(), poolTx.isCoinBase());
                            break;
                        }
                    }
                    if (output == null)
                        throw new VerificationException(String.format(
                                "Transaction references non-existent output\n  %s", txHash.toString()),
                                Parameters.REJECT_INVALID, txHash);
                } else {
                    // Transaction is not in the memory pool, check the database
                    try {
                        output = Parameters.blockStore.getTxOutput(outPoint);
                        if (output == null) {
                            orphanTx = true;
                            orphanHash = outPoint.getHash();
                        } else if (output.isSpent()) {
                            outputSpent = true;
                        } else {
                            totalInput = totalInput.add(output.getValue());
                        }
                    } catch (BlockStoreException exc) {
                        orphanTx = true;
                        orphanHash = outPoint.getHash();
                    }
                }
            } else if (!spendHash.equals(txHash)) {
                outputSpent = true;
            } else {
                duplicateTx = true;
            }
            // Stop now if we have a problem
            if (duplicateTx || orphanTx)
                break;
            // Error if the output has been spent
            if (outputSpent)
                throw new VerificationException("Input already spent", Parameters.REJECT_DUPLICATE, txHash);
            // Check for immature coinbase transaction
            if (output.isCoinBase()) {
                try {
                    int txDepth = Parameters.blockStore.getTxDepth(outPoint.getHash());
                    txDepth += Parameters.networkChainHeight - Parameters.blockStore.getChainHeight();
                    if (txDepth < Parameters.COINBASE_MATURITY)
                        throw new VerificationException("Spending immature coinbase output",
                                                        Parameters.REJECT_INVALID, txHash);
                } catch (BlockStoreException exc) {
                    // Can't check transaction depth - let it go
                }
            }
            // Check for canonical signatures and public keys
            int paymentType = Script.getPaymentType(output.getScriptBytes());
            List<byte[]> dataList = Script.getData(input.getScriptBytes());
            int canonicalType = 0;
            switch (paymentType) {
                case ScriptOpCodes.PAY_TO_PUBKEY:
                    // First data element is signature
                    if (dataList.isEmpty() || !ECKey.isSignatureCanonical(dataList.get(0)))
                        canonicalType = 1;
                    break;
                case ScriptOpCodes.PAY_TO_PUBKEY_HASH:
                    // First data element is signature, second data element is public key
                    if (dataList.isEmpty() || !ECKey.isSignatureCanonical(dataList.get(0)))
                        canonicalType = 1;
                    else if (dataList.size() < 2 || !ECKey.isPubKeyCanonical(dataList.get(1)))
                        canonicalType = 2;
                    break;
                case ScriptOpCodes.PAY_TO_MULTISIG:
                    // All data elements are public keys
                    for (byte[] sigBytes : dataList) {
                        if (!ECKey.isSignatureCanonical(sigBytes)) {
                            canonicalType = 1;
                            break;
                        }
                    }
            }
            if (canonicalType == 1)
                throw new VerificationException(String.format("Non-canonical signature",
                                                txHash.toString()), Parameters.REJECT_NONSTANDARD, txHash);
            if (canonicalType == 2)
                throw new VerificationException(String.format("Non-canonical public key",
                                                txHash.toString()), Parameters.REJECT_NONSTANDARD, txHash);
            // Add the output to the spent outputs list
            spentOutputs.add(outPoint);
        }
        //
        // Ignore a duplicate transaction (race condition among message handler threads)
        //
        if (duplicateTx)
            return false;
        //
        // Save an orphan transaction for later
        //
        if (orphanTx) {
            StoredTransaction storedTx = new StoredTransaction(tx);
            storedTx.setParent(orphanHash);
            synchronized(Parameters.lock) {
                Parameters.orphanTxList.add(storedTx);
                List<StoredTransaction> orphanList = Parameters.orphanTxMap.get(orphanHash);
                if (orphanList == null) {
                    orphanList = new ArrayList<>();
                    orphanList.add(storedTx);
                    Parameters.orphanTxMap.put(orphanHash, orphanList);
                } else {
                    orphanList.add(storedTx);
                }
            }
            return false;
        }
        //
        // Check for insufficient transaction fee
        //
        BigInteger totalFee = totalInput.subtract(totalOutput);
        if (totalFee.signum() < 0)
            throw new VerificationException("Transaction output value exceeds transaction input value",
                                            Parameters.REJECT_INVALID, txHash);
        int txLength = tx.getBytes().length;
        int feeMultiplier = txLength/1000;
        if (txLength > Parameters.MAX_FREE_TX_SIZE) {
            BigInteger minFee = Parameters.MIN_TX_RELAY_FEE.multiply(BigInteger.valueOf(feeMultiplier+1));
            if (totalFee.compareTo(minFee) < 0)
                throw new VerificationException("Insufficient transaction fee",
                                                Parameters.REJECT_INSUFFICIENT_FEE, txHash);
        }
        //
        // Store the transaction in the memory pool (maximum size we will store is 50KB)
        //
        if (txLength <= 50*1024) {
            StoredTransaction storedTx = new StoredTransaction(tx);
            synchronized(Parameters.lock) {
                if (Parameters.txMap.get(txHash) == null) {
                    Parameters.txPool.add(storedTx);
                    Parameters.txMap.put(txHash, storedTx);
                    Parameters.txReceived++;
                    for (OutPoint outPoint : spentOutputs) {
                        Parameters.spentOutputsList.add(outPoint);
                        Parameters.spentOutputsMap.put(outPoint, txHash);
                    }
                }
            }
        }
        return true;
    }

    /**
     * Broadcasts the transaction
     *
     * @param       tx                  Transaction
     * @throws      EOFException        End-of-data processing script
     */
    private static void broadcastTx(Transaction tx) throws EOFException {
        Sha256Hash txHash = tx.getHash();
        //
        // Send an 'inv' message to the broadcast peers
        //
        List<Sha256Hash> txList = new ArrayList<>(1);
        txList.add(txHash);
        Message invMsg = InventoryMessage.buildInventoryMessage(null, Parameters.INV_TX, txList);
        Parameters.networkListener.broadcastMessage(invMsg);
        //
        // Copy the current list of Bloom filters
        //
        List<BloomFilter> filters;
        synchronized(Parameters.lock) {
            filters = new ArrayList<>(Parameters.bloomFilters.size());
            filters.addAll(Parameters.bloomFilters);
        }
        //
        // Check each filter for a match
        //
        for (BloomFilter filter : filters) {
            Peer peer = filter.getPeer();
            //
            // Remove the filter if the peer is no longer connected
            //
            if (!peer.isConnected()) {
                synchronized(Parameters.lock) {
                    Parameters.bloomFilters.remove(filter);
                }
                continue;
            }
            //
            // Check the transaction against the filter and send an 'inv' message if it is a match
            //
            if (filter.checkTransaction(tx)) {
                invMsg = InventoryMessage.buildInventoryMessage(peer, Parameters.INV_TX, txList);
                Parameters.networkListener.sendMessage(invMsg);
            }
        }
    }
}