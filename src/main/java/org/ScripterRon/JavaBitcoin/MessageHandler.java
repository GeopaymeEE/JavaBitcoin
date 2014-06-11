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

import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageHeader;
import org.ScripterRon.BitcoinCore.MessageProcessor;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.RejectMessage;
import org.ScripterRon.BitcoinCore.VerificationException;

import java.io.EOFException;

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
        int reasonCode = 0;
        try {
            MessageProcessor.processMessage(msg, Parameters.networkMessageListener);
            msg.setBuffer(null);
        } catch (EOFException exc) {
            MessageHeader.MessageCommand cmdOp = msg.getCommand();
            String cmdName = (cmdOp!=null ? cmdOp.toString().toLowerCase() : "N/A");
            log.error(String.format("End-of-data while processing '%s' message from %s",
                                    cmdName, address), exc);
            reasonCode = RejectMessage.REJECT_MALFORMED;
            if (cmdOp == MessageHeader.MessageCommand.TX)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.MessageCommand.VERSION)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmdName, reasonCode, exc.getMessage());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            } else {
                msg.setBuffer(null);
            }
        } catch (VerificationException exc) {
            MessageHeader.MessageCommand cmdOp = msg.getCommand();
            String cmdName = (cmdOp!=null ? cmdOp.toString().toLowerCase() : "N/A");
            log.error(String.format("Message verification failed for '%s' message from %s\n  %s\n  %s",
                                    cmdName, address, exc.getMessage(), exc.getHash()));
            reasonCode = exc.getReason();
            if (cmdOp == MessageHeader.MessageCommand.TX)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.MessageCommand.VERSION)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmdName, reasonCode,
                                                                     exc.getMessage(), exc.getHash());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            } else {
                msg.setBuffer(null);
            }
        }
        //
        // Add the message to the completed message list and wakeup the network listener.  We will
        // bump the banscore for the peer if the message was rejected because it was malformed
        // or invalid.
        //
        synchronized(Parameters.lock) {
            Parameters.completedMessages.add(msg);
            if (reasonCode == RejectMessage.REJECT_MALFORMED || reasonCode == RejectMessage.REJECT_INVALID) {
                int banScore = peer.getBanScore() + 5;
                peer.setBanScore(banScore);
                if (banScore >= Parameters.MAX_BAN_SCORE)
                    peer.setDisconnect(true);
            }
        }
        Parameters.networkHandler.wakeup();
    }
}
