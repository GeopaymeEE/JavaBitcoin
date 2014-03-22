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
package JavaBitcoin;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>The 'getblocks' message is sent by a peer when it does not have the latest block chain
 * and needs a list of the blocks required to get to the latest block.</p>
 *
 * <p>When a node is down-level, it attempts to get current by sending a 'getblocks' request.
 * This works as long as the node is within 500 blocks of the current chain head since it
 * will receive a complete block list in the 'inv' response.  However, if it needs more than 500 blocks,
 * it doesn't repeat the 'getblocks' request to continue receiving blocks (although it should know
 * that it is still down-level based on the chain height returned in the 'version' message).
 * Instead, it waits for an 'inv' message advertising the current chain head to make it realize
 * that it is still down-level.  So, to keep the blocks flowing, we need to send an 'inv' message for the
 * chain head after we receive the 'getdata' message requesting the initial blocks.</p>
 *
 * <p>GetBlocks Message</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   4 bytes    Version             Negotiated protocol version
 *   VarInt     Count               Number of locator hash entries
 *   Variable   Entries             Locator hash entries
 *  32 bytes    Stop                Hash of the last desired block or zero to get as many as possible
 * </pre>
 */
public class GetBlocksMessage {

    /**
     * Build a 'getblocks' message
     *
     * We will request blocks starting with the current chain head and working backwards to
     * a maximum depth of 500 blocks.
     *
     * @param       peer            Destination peer
     * @return      Message to send to the peer
     */
    public static Message buildGetBlocksMessage(Peer peer) {
        List<Sha256Hash> invList = new ArrayList<>(500);
        try {
            //
            // Get the chain list
            //
            int chainHeight = Parameters.blockStore.getChainHeight();
            int blockHeight = Math.max(0, chainHeight-500);
            List<Sha256Hash> chainList = Parameters.blockStore.getChainList(blockHeight, Sha256Hash.ZERO_HASH);
            //
            // Build the locator list starting with the chain head and working backwards towards
            // the genesis block
            //
            int step = 1;
            int loop = 0;
            int pos = chainList.size()-1;
            while (pos >= 0) {
                invList.add(chainList.get(pos));
                if (loop == 10) {
                    step = step*2;
                    pos = pos-step;
                } else {
                    loop++;
                    pos--;
                }
            }
        } catch (BlockStoreException exc) {
            //
            // We can't query the database, so just locate the chain head and hope we
            // are on the main chain
            //
            invList.add(Parameters.blockStore.getChainHead());
        }
        //
        // Build the message payload
        //
        // The protocol version will be set to the lesser of our version and the peer version
        // The stop locator will be set to zero since we don't know the network chain head.
        //
        int varCount = invList.size();
        byte[] varBytes = VarInt.encode(varCount);
        byte[] msgData = new byte[4+varBytes.length+varCount*32+32];
        Utils.uint32ToByteArrayLE(Math.min(Parameters.PROTOCOL_VERSION, peer.getVersion()), msgData, 0);
        System.arraycopy(varBytes, 0, msgData, 4, varBytes.length);
        int offset = 4+varBytes.length;
        for (Sha256Hash blockHash : invList) {
            System.arraycopy(Utils.reverseBytes(blockHash.getBytes()), 0, msgData, offset, 32);
            offset+=32;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("getblocks", msgData);
        return new Message(buffer, peer, MessageHeader.GETBLOCKS_CMD);
    }

    /**
     * Process the 'getblocks' message and return an 'inv' message
     *
     * @param       msg             Message
     * @param       inStream        Message data stream
     * @throws      EOFException
     * @throws      IOException
     * @throws      VerificationException
     */
    public static void processGetBlocksMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        Peer peer = msg.getPeer();
        //
        // Get the protocol version
        //
        byte[] bytes = new byte[32];
        int count = inStream.read(bytes, 0, 4);
        if (count < 4)
            throw new EOFException("End-of-data processing 'getblocks' message");
        int version = (int)Utils.readUint32LE(bytes, 0);
        if (version < Parameters.MIN_PROTOCOL_VERSION)
            throw new VerificationException(String.format("Protocol version %d is not supported", version));
        //
        // Get the number of locator entries
        //
        int varCount = new VarInt(inStream).toInt();
        if (varCount < 0 || varCount > 500)
            throw new VerificationException(String.format("'getblocks' message contains more than 500 locators"));
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
    }
}
