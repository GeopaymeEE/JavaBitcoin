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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

import java.net.InetAddress;

import java.nio.ByteBuffer;

/**
 * <p>The 'version' message is exchanged when two nodes connect.  It identifies
 * the services provided by the nodes and the latest block each has seen.  A node
 * responds with a 'verack' message if it accepts the connection, otherwise the
 * node will close the connection.</p>
 *
 * <p>Version Message:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   4 bytes    Version             Protocol version
 *   8 bytes    Services            Supported services (bit field)
 *   8 bytes    Timestamp           Time in seconds since the epoch
 *  26 bytes    RemoteAddress       Remote node address
 *  26 bytes    LocalAddress        Local node address
 *   8 bytes    Nonce               Random value to identify sending node
 *  VarString   UserAgent           Identification string
 *   4 bytes    BlockHeight         Last block received by sending node
 *   1 byte     TxRelay             TRUE if remote peer should relay transactions
 * </pre>
 *
 * <p>Network Address:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   8 bytes    Services            Supported services (same as 'version' message)
 *  16 bytes    NetworkAddress      IPv6 address (IPv4 address encoded as IPv6 address)
 *   2 bytes    Port                Port (network byte order)
 * </pre>
 */
public class VersionMessage {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(VersionMessage.class);

    /** Node identifier for this peer execution */
    public static final long NODE_ID = Double.doubleToRawLongBits(Double.valueOf(Math.random()));

    /**
     * Builds a 'version' message
     *
     * @param       peer            The remote peer
     * @param       chainHeight     Current chain height
     * @return                      Message to send to remote peer
     */
    public static Message buildVersionMessage(Peer peer, int chainHeight) {
        PeerAddress peerAddress = peer.getAddress();
        byte[] dstAddress = peerAddress.getAddress().getAddress();
        int dstPort = peerAddress.getPort();
        byte[] srcAddress = Parameters.listenAddress.getAddress();
        String agentName = Parameters.SOFTWARE_NAME;
        //
        // Build the 'version' payload
        //
        byte[] msgData = new byte[4+8+8+26+26+8+1+agentName.length()+4+1];
        Utils.uint32ToByteArrayLE(Parameters.PROTOCOL_VERSION, msgData, 0);
        Utils.uint64ToByteArrayLE(Parameters.SUPPORTED_SERVICES, msgData, 4);
        Utils.uint64ToByteArrayLE(System.currentTimeMillis()/1000, msgData, 12);
        if (dstAddress.length == 16) {
            System.arraycopy(dstAddress, 0, msgData, 28, 16);
        } else {
            System.arraycopy(PeerAddress.IPV6_PREFIX, 0, msgData, 28, 12);
            System.arraycopy(dstAddress, 0, msgData, 40, 4);
        }
        msgData[44] = (byte)(dstPort>>8);
        msgData[45] = (byte)dstPort;
        if (srcAddress.length == 16) {
            System.arraycopy(srcAddress, 0, msgData, 54, 16);
        } else {
            System.arraycopy(PeerAddress.IPV6_PREFIX, 0, msgData, 54, 12);
            System.arraycopy(srcAddress, 0, msgData, 66, 4);
        }
        msgData[70] = (byte)(Parameters.listenPort>>8);
        msgData[71] = (byte)Parameters.listenPort;
        Utils.uint64ToByteArrayLE(NODE_ID, msgData, 72);
        msgData[80] = (byte)agentName.length();
        for (int i=0; i<agentName.length(); i++)
            msgData[81+i] = (byte)agentName.codePointAt(i);
        int offset = agentName.length()+80+1;
        Utils.uint32ToByteArrayLE(chainHeight, msgData, offset);
        msgData[offset+4] = 1;
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("version", msgData);
        return new Message(buffer, peer, MessageHeader.VERSION_CMD);
    }

    /**
     * Processes a 'version' message
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            End-of-data processing message data
     * @throws      IOException             Unable to read message data
     * @throws      VerificationException   Message verification failed
     */
    public static void processVersionMessage(Message msg, ByteArrayInputStream inStream)
                                             throws EOFException, IOException, VerificationException {
        Peer peer = msg.getPeer();
        byte[] bytes = new byte[80];
        int count = inStream.read(bytes);
        if (count < 80)
            throw new EOFException("'version' message is too short");
        //
        // Validate the protocol level
        //
        int version = (int)Utils.readUint32LE(bytes, 0);
        if (version < Parameters.MIN_PROTOCOL_VERSION)
            throw new VerificationException(String.format("Protocol version %d is not supported", version),
                                            Parameters.REJECT_OBSOLETE);
        peer.setVersion(version);
        //
        // Get the peer services
        //
        peer.setServices(Utils.readUint64LE(bytes, 4));
        //
        // If we haven't determined our external IP address yet, we will get it
        // from the 'version' message (if the remote peer set an address)
        //
        if (!Parameters.listenAddressValid) {
            boolean ipv4 = true;
            for (int j=0; j<12; j++) {
                if (bytes[j+28] != PeerAddress.IPV6_PREFIX[j]) {
                    ipv4 = false;
                    break;
                }
            }
            InetAddress address = null;
            if (ipv4 && bytes[40] != 0) {
                byte[] addrBytes = new byte[4];
                System.arraycopy(bytes, 40, addrBytes, 0, 4);
                address = InetAddress.getByAddress(addrBytes);
            } else if (!ipv4 && bytes[28] != 0) {
                byte[] addrBytes = new byte[16];
                System.arraycopy(bytes, 28, addrBytes, 0, 16);
                address = InetAddress.getByAddress(addrBytes);
            }
            if (address != null) {
                Parameters.listenAddress = address;
                Parameters.listenAddressValid = true;
                log.info(String.format("External IP address set to %s", address.toString()));
            }
        }
        //
        // Get the user agent
        //
        int length = new VarInt(inStream).toInt();
        if (length < 0 || length > 256)
            throw new VerificationException("Agent length is greater than 256 characters");
        byte[] agentBytes = new byte[length];
        count = inStream.read(agentBytes);
        if (count < length)
            throw new EOFException("'version' message is too short");
        StringBuilder agentString = new StringBuilder(length);
        for (int i=0; i<length; i++)
            agentString.appendCodePoint(((int)agentBytes[i])&0xff);
        peer.setUserAgent(agentString.toString());
        //
        // Get the chain height
        //
        count = inStream.read(bytes, 0, 5);
        if (count < 4)
            throw new EOFException("'version' message is too short");
        peer.setHeight((int)Utils.readUint32LE(bytes, 0));
        if (peer.getHeight() < 0)
            throw new VerificationException("Invalid chain height in 'version' message", Parameters.REJECT_INVALID);
        //
        // Get the transaction relay mode (this is an optional field and is TRUE if omitted)
        // We will always relay blocks.
        //
        peer.setBlockRelay(true);
        if (count == 5)
            peer.setTxRelay(bytes[4]!=0);
        else
            peer.setTxRelay(true);
    }
}
