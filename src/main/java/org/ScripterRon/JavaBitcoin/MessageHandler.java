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

import org.ScripterRon.BitcoinCore.AddressMessage;
import org.ScripterRon.BitcoinCore.AlertMessage;
import org.ScripterRon.BitcoinCore.BlockMessage;
import org.ScripterRon.BitcoinCore.FilterAddMessage;
import org.ScripterRon.BitcoinCore.FilterClearMessage;
import org.ScripterRon.BitcoinCore.FilterLoadMessage;
import org.ScripterRon.BitcoinCore.GetAddressMessage;
import org.ScripterRon.BitcoinCore.GetBlocksMessage;
import org.ScripterRon.BitcoinCore.GetDataMessage;
import org.ScripterRon.BitcoinCore.GetHeadersMessage;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.InventoryMessage;
import org.ScripterRon.BitcoinCore.MempoolMessage;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageHeader;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.NotFoundMessage;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.PingMessage;
import org.ScripterRon.BitcoinCore.PongMessage;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.SerializedBuffer;
import org.ScripterRon.BitcoinCore.TransactionMessage;
import org.ScripterRon.BitcoinCore.VerificationException;
import org.ScripterRon.BitcoinCore.VersionAckMessage;
import org.ScripterRon.BitcoinCore.VersionMessage;

import java.io.EOFException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * A message handler processes incoming messages on a separate dispatching thread.
 * It creates a response message if needed and then calls the network handler to
 * process the message completion.
 *
 * The message handler continues running until its shutdown() method is called.  It
 * receives messages from the messageQueue list, blocking if necessary until a message
 * is available.
 */
public class MessageHandler implements Runnable {

    /**
     * Creates a message handler
     */
    public MessageHandler() {
    }

    /**
     * Processes messages and returns responses
     */
    @Override
    public void run() {
        log.info("Message handler started");
        //
        // Process messages until we are shutdown
        //
        try {
            while (true) {
                Message msg = Parameters.messageQueue.take();
                if (msg instanceof ShutdownMessage)
                    break;
                processMessage(msg);
            }
        } catch (InterruptedException exc) {
            log.warn("Message handler interrupted", exc);
        } catch (Throwable exc) {
            log.error("Runtime exception while processing messages", exc);
        }
        //
        // Stopping
        //
        log.info("Message handler stopped");
    }

    /**
     * Process a message and return a response
     *
     * @param       msg             Message
     */
    private void processMessage(Message msg) throws InterruptedException {
        Peer peer = msg.getPeer();
        if (peer == null) {
            Main.dumpData("Message With No Peer", msg.getBuffer().array());
            return;
        }
        PeerAddress address = peer.getAddress();
        String cmd = "N/A";
        int cmdOp = 0;
        int reasonCode = 0;
        try {
            ByteBuffer msgBuffer = msg.getBuffer();
            SerializedBuffer inBuffer = new SerializedBuffer(msgBuffer.array());
            msg.setBuffer(null);
            //
            // Process the message header and get the command name
            //
            cmd = MessageHeader.processMessage(inBuffer);
            Integer cmdLookup = MessageHeader.cmdMap.get(cmd);
            if (cmdLookup != null)
                cmdOp = cmdLookup;
            msg.setCommand(cmdOp);
            //
            // Close the connection if the peer starts sending messages before the
            // handshake has been completed
            //
            if (peer.getVersionCount() < 2 && cmdOp != MessageHeader.VERSION_CMD &&
                                              cmdOp != MessageHeader.VERACK_CMD) {
                peer.setBanScore(Parameters.MAX_BAN_SCORE);
                throw new VerificationException("Non-version message before handshake completed",
                                                Parameters.REJECT_INVALID);
            }
            //
            // Process the message
            //
            switch (cmdOp) {
                case MessageHeader.VERSION_CMD:
                    //
                    // Process the 'version' message
                    //
                    VersionMessage.processVersionMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.VERACK_CMD:
                    //
                    // Process the 'verack' message
                    //
                    VersionAckMessage.processVersionAckMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.ADDR_CMD:
                    //
                    // Process the 'addr' message
                    //
                    AddressMessage.processAddressMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.INV_CMD:
                    //
                    // Process the 'inv' message
                    //
                    InventoryMessage.processInventoryMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.BLOCK_CMD:
                    //
                    // Process the 'block' message
                    //
                    BlockMessage.processBlockMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.TX_CMD:
                    //
                    // Process the 'tx' message
                    //
                    TransactionMessage.processTransactionMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.GETADDR_CMD:
                    //
                    // Process the 'getaddr' message
                    //
                    GetAddressMessage.processGetAddressMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.GETDATA_CMD:
                    //
                    // Process the 'getdata' message
                    //
                    // We will ignore a 'getdata' message if we are still processing a
                    // previous 'getdata' message (the reference client sends multiple
                    // requests when it is loading the block chain)
                    //
                    if (peer.getDeferredMessage() == null) {
                        GetDataMessage.processGetDataMessage(msg, inBuffer, Parameters.networkMessageListener);
                        //
                        // The 'getdata' command sends data in batches, so we need
                        // to check if it needs to be restarted.  If it does, we will
                        // reset the message buffer so that it will be processed again
                        // when the request is restarted.
                        //
                        if (msg.getRestartIndex() != 0) {
                            msgBuffer.rewind();
                            msg.setRestartBuffer(msgBuffer);
                            synchronized(Parameters.lock) {
                                peer.setDeferredMessage(msg);
                            }
                        }
                    }
                    //
                    // Send an 'inv' message for the current chain head to restart
                    // the peer download if the previous 'getblocks' was incomplete.
                    //
                    if (peer.isIncomplete() && msg.getBuffer()==null && peer.getDeferredMessage()==null) {
                        peer.setIncomplete(false);
                        List<InventoryItem> blockList = new ArrayList<>(1);
                        blockList.add(new InventoryItem(NetParams.INV_BLOCK, Parameters.blockStore.getChainHead()));
                        Message invMessage = InventoryMessage.buildInventoryMessage(peer, blockList);
                        msg.setBuffer(invMessage.getBuffer());
                        msg.setCommand(invMessage.getCommand());
                    }
                    break;
                case MessageHeader.GETBLOCKS_CMD:
                    //
                    // Process the 'getblocks' message
                    //
                    // We will ignore a 'getblocks' message if we are still processing a
                    // previous 'getdata' message (the reference client sends multiple
                    // requests when it is loading the block chain)
                    //
                    if (peer.getDeferredMessage() == null)
                        GetBlocksMessage.processGetBlocksMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.NOTFOUND_CMD:
                    //
                    // Process the 'notfound' message
                    //
                    NotFoundMessage.processNotFoundMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.PING_CMD:
                    //
                    // Process the 'ping' message
                    //
                    PingMessage.processPingMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.PONG_CMD:
                    //
                    // Process the 'pong' message
                    //
                    PongMessage.processPongMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.GETHEADERS_CMD:
                    //
                    // Process the 'getheaders' message
                    //
                    GetHeadersMessage.processGetHeadersMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.MEMPOOL_CMD:
                    //
                    // Process the 'mempool' message
                    //
                    MempoolMessage.processMempoolMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.FILTERLOAD_CMD:
                    //
                    // Process the 'filterload' message
                    //
                    FilterLoadMessage.processFilterLoadMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.FILTERADD_CMD:
                    //
                    // Process the 'filteradd' message
                    //
                    FilterAddMessage.processFilterAddMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.FILTERCLEAR_CMD:
                    //
                    // Process the 'filterclear' message
                    //
                    FilterClearMessage.processFilterClearMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.REJECT_CMD:
                    //
                    // Process the 'reject' message
                    //
                    RejectMessage.processRejectMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                case MessageHeader.ALERT_CMD:
                    //
                    // Process the 'alert' message
                    //
                    AlertMessage.processAlertMessage(msg, inBuffer, Parameters.networkMessageListener);
                    break;
                default:
                    log.error(String.format("Unrecognized '%s' message from %s", cmd, address.toString()));
            }
        } catch (EOFException exc) {
            log.error(String.format("End-of-data while processing '%s' message from %s",
                                    cmd, address.toString()), exc);
            reasonCode = Parameters.REJECT_MALFORMED;
            if (cmdOp == MessageHeader.TX_CMD)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode, exc.getMessage());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        } catch (VerificationException exc) {
            log.error(String.format("Message verification failed for '%s' message from %s\n  %s\n  %s",
                                    cmd, address.toString(), exc.getMessage(), exc.getHash().toString()));
            reasonCode = exc.getReason();
            if (cmdOp == MessageHeader.TX_CMD)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode,
                                                                     exc.getMessage(), exc.getHash());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        }
        //
        // Add the message to the completed message list and wakeup the network listener.  We will
        // bump the banscore for the peer if the message was rejected because it was malformed
        // or invalid.
        //
        synchronized(Parameters.lock) {
            Parameters.completedMessages.add(msg);
            if (reasonCode != 0) {
                if (reasonCode == Parameters.REJECT_MALFORMED || reasonCode == Parameters.REJECT_INVALID) {
                    int banScore = peer.getBanScore() + 5;
                    peer.setBanScore(banScore);
                    if (banScore >= Parameters.MAX_BAN_SCORE)
                        peer.setDisconnect(true);
                }
            }
        }
        Parameters.networkHandler.wakeup();
    }
}
