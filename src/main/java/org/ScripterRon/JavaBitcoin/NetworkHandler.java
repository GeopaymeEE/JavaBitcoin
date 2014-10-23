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
import org.ScripterRon.BitcoinCore.GetAddressMessage;
import org.ScripterRon.BitcoinCore.GetBlocksMessage;
import org.ScripterRon.BitcoinCore.GetDataMessage;
import org.ScripterRon.BitcoinCore.InventoryItem;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.MessageHeader;
import org.ScripterRon.BitcoinCore.NetParams;
import org.ScripterRon.BitcoinCore.Peer;
import org.ScripterRon.BitcoinCore.PeerAddress;
import org.ScripterRon.BitcoinCore.PingMessage;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Utils;
import org.ScripterRon.BitcoinCore.VersionMessage;

import java.io.InputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

/**
 * The network listener creates outbound connections and adds them to the
 * network selector.  A new outbound connection will be created whenever an
 * existing outbound connection is closed.  If specific peer addresses were specified,
 * then only those peers will be used for outbound connections.  Otherwise, DNS
 * discovery and peer broadcasts will be used to find available peers.
 *
 * The network listener opens a local port and listens for incoming connections.
 * When a connection is received, it creates a socket channel and accepts the
 * connection as long as the maximum number of connections has not been reached.
 * The socket is then added to the network selector.
 *
 * When a message is received from a peer node, it is processed by a message
 * handler executing on a separate thread.  The message handler processes the
 * message and then creates a response message to be returned to the originating node.
 *
 * The network listener terminates when its shutdown() method is called.
 */
public class NetworkHandler implements Runnable {

    /** Maximum number of pending input messages for a single peer */
    private static final int MAX_INPUT_MESSAGES = 10;

    /** Maximum number of pending output messages for a single peer */
    private static final int MAX_OUTPUT_MESSAGES = 500;

    /** Network seed nodes */
    private static final String[] dnsSeeds = new String[] {
            "seed.bitnodes.io",             // bitnodes.io
            "seed.bitcoin.sipa.be",         // Pieter Wuille
            "dnsseed.bluematt.me",          // Matt Corallo
            "seed.bitcoinstats.com",        // bitcoinstats.com
            "bitseed.xf2.org"               // xf2.org
    };

    /** Connection listeners */
    private final List<ConnectionListener> connectionListeners = new ArrayList<>();

    /** Network listener thread */
    private Thread listenerThread;

    /** Network timer */
    private Timer timer;

    /** Maximum number of connections */
    private final int maxConnections;

    /** Maximum number of outbound connections */
    private int maxOutbound;

    /** Current number of outbound connections */
    private int outboundCount;

    /** Host name */
    private final String hostName;

    /** Listen channel */
    private ServerSocketChannel listenChannel;

    /** Listen selection key */
    private SelectionKey listenKey;

    /** Network selector */
    private final Selector networkSelector;

    /** Connections list */
    private final List<Peer> connections = new ArrayList<>(128);

    /** Connection map */
    private final Map<InetAddress, Peer> connectionMap = new HashMap<>();

    /** Banned list */
    private final List<InetAddress> bannedAddresses = new ArrayList<>();

    /** Time of Last peer database update */
    private long lastPeerUpdateTime;

    /** Time of last outbound connection attempt */
    private long lastOutboundConnectTime;

    /** Last statistics output time */
    private long lastStatsTime;

    /** Last connection check time */
    private long lastConnectionCheckTime;

    /** Network shutdown */
    private boolean networkShutdown = false;

    /** Static connections */
    private boolean staticConnections = false;

    /** GetBlock time */
    private long getBlocksTime = 0;

    /**
     * Creates the network listener
     *
     * @param       maxConnections      The maximum number of connections
     * @param       maxOutbound         The maximum number of outbound connections
     * @param       hostName            The host name for this port or null
     * @param       listenPort          The port to listen on
     * @param       staticAddresses     Static peer address
     * @throws      IOException         I/O error
     */
    public NetworkHandler(int maxConnections, int maxOutbound, String hostName, int listenPort,
                                        PeerAddress[] staticAddresses)
                                        throws IOException {
        this.maxConnections = maxConnections;
        this.maxOutbound = maxOutbound;
        this.hostName = hostName;
        Parameters.listenPort = listenPort;
        //
        // Create the selector for listening for network events
        //
        networkSelector = Selector.open();
        //
        // Build the static peer address list
        //
        if (staticAddresses != null) {
            staticConnections = true;
            this.maxOutbound = Math.min(this.maxOutbound, staticAddresses.length);
            for (PeerAddress address : staticAddresses) {
                address.setStatic(true);
                Parameters.peerAddresses.add(0, address);
                Parameters.peerMap.put(address, address);
            }
        }
    }

    /**
     * Processes network events
     */
    @Override
    public void run() {
        log.info(String.format("Network listener started: Port %d, Max connections %d, Max outbound %d",
                               Parameters.listenPort, maxConnections, maxOutbound));
        lastPeerUpdateTime = System.currentTimeMillis()/1000;
        lastOutboundConnectTime = lastPeerUpdateTime;
        lastStatsTime = lastPeerUpdateTime;
        lastConnectionCheckTime = lastPeerUpdateTime;
        listenerThread = Thread.currentThread();
        Parameters.networkChainHeight = Parameters.blockStore.getChainHeight();
        try {
            //
            // Get our external IP address from checkip.dyndns.org
            //
            // The returned string is '<html><body>Current IP Address: n.n.n.n</body></html>'
            //
            getExternalIP();
            //
            // Get the peer nodes DNS discovery if we are not using static connections.
            // The address list will be sorted in descending timestamp order so that the
            // most recent peers appear first in the list.
            //
            if (!staticConnections) {
                dnsDiscovery();
                Collections.sort(Parameters.peerAddresses, (PeerAddress addr1, PeerAddress addr2) -> {
                    long t1 = addr1.getTimeStamp();
                    long t2 = addr2.getTimeStamp();
                    return (t1>t2 ? -1 : (t1<t2 ? 1 : 0));
                });
            }
            //
            // Get the current alerts
            //
            Parameters.alerts.addAll(Parameters.blockStore.getAlerts());
            //
            // Create the listen channel
            //
            listenChannel = ServerSocketChannel.open();
            listenChannel.configureBlocking(false);
            listenChannel.bind(new InetSocketAddress(Parameters.listenPort), 10);
            listenKey = listenChannel.register(networkSelector, SelectionKey.OP_ACCEPT);
            //
            // Create the initial outbound connections to get us started
            //
            while (!networkShutdown && outboundCount < Math.min(maxOutbound, 4) &&
                                       connections.size() < maxConnections &&
                                       connections.size() < Parameters.peerAddresses.size())
                if (!connectOutbound())
                    break;
        } catch (BlockStoreException | IOException exc) {
            log.error("Unable to initialize network listener", exc);
            networkShutdown = true;
        }
        //
        // Create a timer to wake us up every 2 minutes
        //
        timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                wakeup();
            }
        }, 2*60*1000, 2*60*1000);
        //
        // Process network events until shutdown() is called
        //
        try {
            while (!networkShutdown) {
                processEvents();
            }
        } catch (Throwable exc) {
            log.error("Runtime exception while processing network events", exc);
        }
        //
        // Stopping
        //
        timer.cancel();
        log.info("Network listener stopped");
    }

    /**
     * Process network events
     */
    private void processEvents() {
        int count;
        try {
            //
            // Process selectable events
            //
            // Note that you need to remove the key from the selected key
            // set.  Otherwise, the selector will return immediately since
            // it thinks there are still unprocessed events.  Also, accessing
            // a key after the channel is closed will cause an exception to be
            // thrown, so it is best to test for just one event at a time.
            //
            count = networkSelector.select();
            if (count > 0 && !networkShutdown) {
                Set<SelectionKey> selectedKeys = networkSelector.selectedKeys();
                Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
                while (keyIterator.hasNext() && !networkShutdown) {
                    SelectionKey key = keyIterator.next();
                    SelectableChannel channel = key.channel();
                    if (channel.isOpen()) {
                        if (key.isAcceptable())
                            processAccept(key);
                        else if (key.isConnectable())
                            processConnect(key);
                        else if (key.isReadable())
                            processRead(key);
                        else if (key.isWritable())
                            processWrite(key);
                    }
                    keyIterator.remove();
                }
            }

            if (!networkShutdown) {
                //
                // Process completed messages
                //
                if (!Parameters.completedMessages.isEmpty())
                    processCompletedMessages();
                //
                // Process peer requests
                //
                if (!Parameters.pendingRequests.isEmpty() || !Parameters.processedRequests.isEmpty())
                    processRequests();
                //
                // Remove peer addresses that we haven't seen in the last 30 minutes and broadcast
                // new addresses.
                //
                long currentTime = System.currentTimeMillis()/1000;
                if (currentTime > lastPeerUpdateTime + (30*60)) {
                    List<PeerAddress> newAddresses = new ArrayList<>(Parameters.peerAddresses.size());
                    synchronized(Parameters.peerAddresses) {
                        Iterator<PeerAddress> iterator = Parameters.peerAddresses.iterator();
                        while (iterator.hasNext()) {
                            PeerAddress address = iterator.next();
                            if (address.isStatic())
                                continue;
                            if (address.getTimeStamp() < lastPeerUpdateTime) {
                                Parameters.peerMap.remove(address);
                                iterator.remove();
                            } else if (!address.wasBroadcast()) {
                                address.setBroadcast(true);
                                newAddresses.add(address);
                            }
                        }
                    }
                    if (!newAddresses.isEmpty()) {
                        Message addrMsg = AddressMessage.buildAddressMessage(null, newAddresses, Parameters.listenAddress);
                        broadcastMessage(addrMsg);
                        log.info(String.format("%d addresses broadcast to peers", newAddresses.size()));
                    }
                    lastPeerUpdateTime = currentTime;
                }
                //
                // Check for inactive peer connections every 2 minutes
                //
                // Close the connection if the peer hasn't completed the version handshake within 2 minutes.
                // Otherwise, send a 'ping' message.  Close the connection if the peer is still inactive
                // after 4 minutes.
                //
                if (currentTime > lastConnectionCheckTime+2*60) {
                    lastConnectionCheckTime = currentTime;
                    List<Peer> inactiveList = new ArrayList<>();
                    connections.stream().forEach((chkPeer) -> {
                        PeerAddress chkAddress = chkPeer.getAddress();
                        if (chkAddress.getTimeStamp() < currentTime-5*60) {
                            inactiveList.add(chkPeer);
                        } else if (chkAddress.getTimeStamp() < currentTime-2*60) {
                            if (chkPeer.getVersionCount() < 2) {
                                inactiveList.add(chkPeer);
                            } else if (!chkPeer.wasPingSent()) {
                                int banScore = 0;
                                synchronized(chkPeer) {
                                    if (chkPeer.getServices() != 0) {
                                        banScore = chkPeer.getBanScore() + 10;
                                        chkPeer.setBanScore(banScore);
                                    }
                                }
                                if (banScore < Parameters.MAX_BAN_SCORE) {
                                    chkPeer.setPing(true);
                                    Message chkMsg = PingMessage.buildPingMessage(chkPeer);
                                    synchronized(chkPeer) {
                                        chkPeer.getOutputList().add(chkMsg);
                                        SelectionKey chkKey = chkPeer.getKey();
                                        chkKey.interestOps(chkKey.interestOps() | SelectionKey.OP_WRITE);
                                        log.info(String.format("'ping' message sent to %s", chkAddress));
                                    }
                                } else {
                                   inactiveList.add(chkPeer);
                                }
                            }
                        }
                    });
                    inactiveList.stream().forEach((chkPeer) -> {
                        log.info(String.format("Closing connection due to inactivity: %s", chkPeer.getAddress()));
                        closeConnection(chkPeer);
                    });
                }
                //
                // Create a new outbound connection if we have less than the
                // maximum number and we haven't tried for 30 seconds
                //
                if (currentTime > lastOutboundConnectTime+30) {
                    lastOutboundConnectTime = currentTime;
                    while (outboundCount < maxOutbound && connections.size() < maxConnections &&
                                                          connections.size() < Parameters.peerAddresses.size()) {
                        if (!connectOutbound() || outboundCount >= Math.min(maxOutbound, 4))
                            break;
                    }
                }
                //
                // Print statistics every 5 minutes
                //
                if (currentTime > lastStatsTime + (5*60)) {
                    lastStatsTime = currentTime;
                    log.info(String.format("\n"+
                            "=======================================================\n"+
                            "** Chain height: Network %,d, Local %,d\n"+
                            "** Connections: %,d outbound, %,d inbound\n"+
                            "** Addresses: %,d peers, %,d banned\n"+
                            "** Blocks: %,d received, %,d sent, %,d filtered sent\n"+
                            "** Transactions: %,d received, %,d sent, %,d pool, %,d rejected, %,d orphaned\n"+
                            "=======================================================",
                                Parameters.networkChainHeight, Parameters.blockStore.getChainHeight(),
                                outboundCount, connections.size()-outboundCount,
                                Parameters.peerAddresses.size(), bannedAddresses.size(),
                                Parameters.blocksReceived.get(), Parameters.blocksSent.get(),
                                Parameters.filteredBlocksSent.get(), Parameters.txReceived.get(),
                                Parameters.txSent.get(), Parameters.txMap.size(),
                                Parameters.txRejected.get(), Parameters.orphanTxMap.size()));
                    System.gc();
                }
            }
        } catch (ClosedChannelException exc) {
            log.error("Network channel closed unexpectedly", exc);
        } catch (ClosedSelectorException exc) {
            log.error("Network selector closed unexpectedly", exc);
            networkShutdown = true;
        } catch (IOException exc) {
            log.error("I/O error while processing selection event", exc);
        }
    }

    /**
     * Register a connection listener
     *
     * @param       listener        Connection listener
     */
    public void addListener(ConnectionListener listener) {
        connectionListeners.add(listener);
    }

    /**
     * Returns the current connections
     *
     * @return      Peer connections
     */
    public List<Peer> getConnections() {
        //
        // Get the current connection list
        //
        List<Peer> connectionList;
        synchronized(connections) {
            connectionList = new ArrayList<>(connections);
        }
        //
        // Remove pending connections from the list
        //
        Iterator<Peer> it = connectionList.iterator();
        while (it.hasNext()) {
            Peer peer = it.next();
            if (peer.getVersionCount() < 3)
                it.remove();
        }
        return connectionList;
    }

    /**
     * Wakes up the network listener
     */
    public void wakeup() {
        if (Thread.currentThread() != listenerThread)
            networkSelector.wakeup();
    }

    /**
     * Shutdowns the network listener
     */
    public void shutdown() {
        networkShutdown = true;
        wakeup();
    }

    /**
     * Sends a message to a connected peer
     *
     * @param       msg             The message to be sent
     */
    public void sendMessage(Message msg) {
        Peer peer = msg.getPeer();
        if (peer != null) {
            SelectionKey key = peer.getKey();
            PeerAddress address = peer.getAddress();
            synchronized(peer) {
                if (address.isConnected()) {
                    peer.getOutputList().add(msg);
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
            }
            wakeup();
        }
    }

    /**
     * Broadcasts a message to all connected peers
     *
     * Block notifications will be sent to peers that are providing network services.
     * Transaction notifications will be sent to peers that have requested transaction relays.
     * All other notifications will be sent to all connected peers.
     *
     * @param       msg             Message to broadcast
     */
    public void broadcastMessage(Message msg) {
        //
        // Send the message to each connected peer
        //
        synchronized(connections) {
            connections.stream()
                .filter((relayPeer) -> relayPeer.getVersionCount() > 2)
                .forEach((relayPeer) -> {
                    boolean sendMsg = true;
                    MessageHeader.MessageCommand cmd = msg.getCommand();
                    if (cmd == MessageHeader.MessageCommand.INV) {
                        if (msg.getInventoryType() == InventoryItem.INV_BLOCK)
                            sendMsg = relayPeer.shouldRelayBlocks();
                        else if (msg.getInventoryType() == InventoryItem.INV_TX)
                            sendMsg = relayPeer.shouldRelayTx();
                    }
                    if (sendMsg) {
                        synchronized(relayPeer) {
                            relayPeer.getOutputList().add(msg.clone(relayPeer));
                            SelectionKey relayKey = relayPeer.getKey();
                            relayKey.interestOps(relayKey.interestOps() | SelectionKey.OP_WRITE);
                        }
                    }
                });
        }
        //
        // Wakeup the network listener to send the broadcast messages
        //
        wakeup();
    }

    /**
     * Processes an OP_ACCEPT selection event
     *
     * We will accept the connection if we haven't reached the maximum number of connections.
     * The new socket channel will be placed in non-blocking mode and the selection key enabled
     * for read events.  We will not add the peer address to the peer address list since
     * we only want nodes that have advertised their availability on the list.
     */
    private void processAccept(SelectionKey acceptKey) {
        try {
            SocketChannel channel = listenChannel.accept();
            if (channel != null) {
                InetSocketAddress remoteAddress = (InetSocketAddress)channel.getRemoteAddress();
                PeerAddress address = new PeerAddress(remoteAddress);
                if (connections.size() >= maxConnections) {
                    channel.close();
                    log.info(String.format("Max connections reached: Connection rejected from %s", address));
                } else if (bannedAddresses.contains(address.getAddress())) {
                    channel.close();
                    log.info(String.format("Connection rejected from banned address %s", address));
                } else if (connectionMap.get(address.getAddress()) != null) {
                    channel.close();
                    log.info(String.format("Duplicate connection rejected from %s", address));
                } else {
                    address.setTimeConnected(System.currentTimeMillis()/1000);
                    channel.configureBlocking(false);
                    channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
                    SelectionKey key = channel.register(networkSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                    Peer peer = new Peer(address, channel, key);
                    key.attach(peer);
                    peer.setConnected(true);
                    address.setConnected(true);
                    log.info(String.format("Connection accepted from %s", address));
                    Message msg = VersionMessage.buildVersionMessage(peer, Parameters.listenAddress,
                                                                     Parameters.blockStore.getChainHeight());
                    synchronized(connections) {
                        connections.add(peer);
                        connectionMap.put(address.getAddress(), peer);
                        peer.getOutputList().add(msg);
                    }
                    log.info(String.format("Sent 'version' message to %s", address));
                }
            }
        } catch (IOException exc) {
            log.error("Unable to accept connection", exc);
            networkShutdown = true;
        }
    }

    /**
     * Creates a new outbound connection
     *
     * This routine selects the most recent peer from the peer address list.
     * The channel is placed in non-blocking mode and the connection is initiated.  An OP_CONNECT
     * selection event will be generated when the connection has been established or has failed.
     *
     * @return      TRUE if a connection was established
     */
    private boolean connectOutbound() {
        //
        // Get the most recent peer that does not have a connection
        //
        PeerAddress address = null;
        synchronized(Parameters.peerAddresses) {
            for (PeerAddress chkAddress : Parameters.peerAddresses) {
                if (!chkAddress.isConnected() && connectionMap.get(chkAddress.getAddress())==null &&
                                !bannedAddresses.contains(chkAddress.getAddress()) &&
                                (!staticConnections || chkAddress.isStatic())) {
                    address = chkAddress;
                    break;
                }
            }
        }
        if (address == null)
            return false;
        //
        // Create a socket channel for the connection and open the connection
        //
        try {
            SocketChannel channel = SocketChannel.open();
            channel.configureBlocking(false);
            channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
            channel.bind(null);
            SelectionKey key = channel.register(networkSelector, SelectionKey.OP_CONNECT);
            Peer peer = new Peer(address, channel, key);
            key.attach(peer);
            peer.setConnected(true);
            address.setConnected(true);
            address.setOutbound(true);
            channel.connect(address.toSocketAddress());
            outboundCount++;
            synchronized(connections) {
                connections.add(peer);
                connectionMap.put(address.getAddress(), peer);
            }
        } catch (IOException exc) {
            log.error(String.format("Unable to open connection to %s", address), exc);
            networkShutdown = true;
        }
        return true;
    }

    /**
     * Processes an OP_CONNECT selection event
     *
     * We will finish the connection and send a Version message to the remote peer
     *
     * @param       key             The channel selection key
     */
    private void processConnect(SelectionKey key) {
        Peer peer = (Peer)key.attachment();
        PeerAddress address = peer.getAddress();
        SocketChannel channel = peer.getChannel();
        try {
            channel.finishConnect();
            log.info(String.format("Connection established to %s", address));
            address.setTimeConnected(System.currentTimeMillis()/1000);
            Message msg = VersionMessage.buildVersionMessage(peer, Parameters.listenAddress,
                                                             Parameters.blockStore.getChainHeight());
            synchronized(peer) {
                peer.getOutputList().add(msg);
                key.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            }
            log.info(String.format("Sent 'version' message to %s", address));
        } catch (ConnectException | NoRouteToHostException exc) {
            log.info(exc.getLocalizedMessage());
            closeConnection(peer);
            if (!address.isStatic()) {
                synchronized(Parameters.peerAddresses) {
                    if (Parameters.peerMap.get(address) != null) {
                        Parameters.peerAddresses.remove(address);
                        Parameters.peerMap.remove(address);
                    }
                }
            }
        } catch (IOException exc) {
            log.error(String.format("Connection failed to %s", address), exc);
            closeConnection(peer);
        }
    }

    /**
     * Processes an OP_READ selection event
     *
     * @param       key             The channel selection key
     */
    private void processRead(SelectionKey key) {
        Peer peer = (Peer)key.attachment();
        PeerAddress address = peer.getAddress();
        SocketChannel channel = peer.getChannel();
        ByteBuffer buffer = peer.getInputBuffer();
        address.setTimeStamp(System.currentTimeMillis()/1000);
        try {
            int count;
            //
            // Read data until we have a complete message or no more data is available
            //
            while (true) {
                //
                // Allocate a header buffer if no read is in progress
                //
                if (buffer == null) {
                    buffer = ByteBuffer.wrap(new byte[MessageHeader.HEADER_LENGTH]);
                    peer.setInputBuffer(buffer);
                }
                //
                // Fill the input buffer
                //
                if (buffer.position() < buffer.limit()) {
                    count = channel.read(buffer);
                    if (count <= 0) {
                        if (count < 0)
                            closeConnection(peer);
                        break;
                    }
                }
                //
                // Process the message header
                //
                if (buffer.position() == buffer.limit() && buffer.limit() == MessageHeader.HEADER_LENGTH) {
                    byte[] hdrBytes = buffer.array();
                    long magic = Utils.readUint32LE(hdrBytes, 0);
                    long length = Utils.readUint32LE(hdrBytes, 16);
                    if (magic != NetParams.MAGIC_NUMBER) {
                        log.error(String.format("Message magic number %X is incorrect", magic));
                        Main.dumpData("Failing Message Header", hdrBytes);
                        closeConnection(peer);
                        break;
                    }
                    if (length > NetParams.MAX_MESSAGE_SIZE) {
                        log.error(String.format("Message length %,d is too large", length));
                        closeConnection(peer);
                        break;
                    }
                    if (length > 0) {
                        byte[] msgBytes = new byte[MessageHeader.HEADER_LENGTH+(int)length];
                        System.arraycopy(hdrBytes, 0, msgBytes, 0, MessageHeader.HEADER_LENGTH);
                        buffer = ByteBuffer.wrap(msgBytes);
                        buffer.position(MessageHeader.HEADER_LENGTH);
                        peer.setInputBuffer(buffer);
                    }
                }
                //
                // Queue the message for a message handler
                //
                // We will disable read operations for this peer if it has too many
                // pending messages.  Read operations will be re-enabled once
                // all of the messages have been processed.  We do this to keep
                // one node from flooding us with requests.
                //
                if (buffer.position() == buffer.limit()) {
                    peer.setInputBuffer(null);
                    buffer.position(0);
                    Message msg = new Message(buffer, peer, null);
                    Parameters.messageQueue.put(msg);
                    synchronized(peer) {
                        count = peer.getInputCount() + 1;
                        peer.setInputCount(count);
                        if (count >= MAX_INPUT_MESSAGES || peer.getOutputList().size() >= MAX_OUTPUT_MESSAGES)
                            key.interestOps(key.interestOps()&(~SelectionKey.OP_READ));
                    }
                    break;
                }
            }
        } catch (IOException exc) {
            closeConnection(peer);
        } catch (InterruptedException exc) {
            log.warn("Interrupted while processing read request");
            networkShutdown = true;
        }
    }

    /**
     * Processes an OP_WRITE selection event
     *
     * @param       key             The channel selection key
     */
    private void processWrite(SelectionKey key) {
        Peer peer = (Peer)key.attachment();
        SocketChannel channel = peer.getChannel();
        ByteBuffer buffer = peer.getOutputBuffer();
        try {
            //
            // Write data until all pending messages have been sent or the socket buffer is full
            //
            while (true) {
                //
                // Get the next message if no write is in progress.  Disable write events
                // if there are no more messages to write.
                //
                if (buffer == null) {
                    synchronized(peer) {
                        List<Message> outputList = peer.getOutputList();
                        if (outputList.isEmpty()) {
                            key.interestOps(key.interestOps() & (~SelectionKey.OP_WRITE));
                        } else {
                            Message msg = outputList.remove(0);
                            buffer = msg.getBuffer();
                            peer.setOutputBuffer(buffer);
                        }
                    }
                }
                //
                // Stop if all messages have been sent
                //
                if (buffer == null)
                    break;
                //
                // Write the current buffer to the channel
                //
                channel.write(buffer);
                if (buffer.position() < buffer.limit())
                    break;
                buffer = null;
                peer.setOutputBuffer(null);
            }
            //
            // Restart a deferred request if we have sent all of the pending data
            //
            if (peer.getOutputBuffer() == null) {
                synchronized(peer) {
                    if (peer.getInputCount() == 0)
                        key.interestOps(key.interestOps() | SelectionKey.OP_READ);
                    Message deferredMsg = peer.getDeferredMessage();
                    if (deferredMsg != null) {
                        peer.setDeferredMessage(null);
                        deferredMsg.setPeer(peer);
                        deferredMsg.setBuffer(deferredMsg.getRestartBuffer());
                        deferredMsg.setRestartBuffer(null);
                        Parameters.messageQueue.put(deferredMsg);
                        int count = peer.getInputCount() + 1;
                        peer.setInputCount(count);
                        if (count >= MAX_INPUT_MESSAGES)
                            key.interestOps(key.interestOps()&(~SelectionKey.OP_READ));
                    }
                }
            }
        } catch (IOException exc) {
            closeConnection(peer);
        } catch (InterruptedException msg) {
            log.warn("Interrupted while queueing deferred request");
            networkShutdown = true;
        }
    }


    /**
     * Closes a peer connection and discards any pending messages
     *
     * @param       peer            The peer being closed
     */
    private void closeConnection(Peer peer) {
        PeerAddress address = peer.getAddress();
        SocketChannel channel = peer.getChannel();
        try {
            //
            // Disconnect the peer
            //
            peer.setInputBuffer(null);
            peer.setOutputBuffer(null);
            peer.setDeferredMessage(null);
            peer.getOutputList().clear();
            if (address.isOutbound())
                outboundCount--;
            address.setConnected(false);
            address.setOutbound(false);
            peer.setConnected(false);
            synchronized(connections) {
                connections.remove(peer);
                connectionMap.remove(address.getAddress());
            }
            if (!address.isStatic()) {
                synchronized(Parameters.peerAddresses) {
                    Parameters.peerAddresses.remove(address);
                    Parameters.peerMap.remove(address);
                }
            }
            //
            // Ban the peer if necessary
            //
            synchronized(peer) {
                if (peer.getBanScore() >= Parameters.MAX_BAN_SCORE &&
                                !bannedAddresses.contains(address.getAddress())) {
                    bannedAddresses.add(address.getAddress());
                    log.info(String.format("Peer address %s banned",
                                           address.getAddress().getHostAddress()));
                }
            }
            //
            // Notify listeners that a connection has ended
            //
            if (peer.getVersionCount() > 2) {
                connectionListeners.stream().forEach((listener) -> {
                    listener.connectionEnded(peer, connections.size());
                });
            }
            //
            // Close the channel
            //
            if (channel.isOpen())
                channel.close();
            log.info(String.format("Connection closed with peer %s", address));
        } catch (IOException exc) {
            log.error(String.format("Error while closing socket channel with %s", address), exc);
        }
    }

    /**
     * Processes completed messages
     */
    private void processCompletedMessages() {
        Message msg;
        while ((msg=Parameters.completedMessages.poll()) != null) {
            Peer peer = msg.getPeer();
            if (peer == null)
                continue;
            PeerAddress address = peer.getAddress();
            SelectionKey key = peer.getKey();
            //
            // Nothing to do if the connection has been closed
            //
            if (!address.isConnected())
                continue;
            //
            // Close the connection if requested
            //
            if (peer.shouldDisconnect()) {
                closeConnection(peer);
                continue;
            }
            //
            // Send the response (if any)
            //
            if (msg.getBuffer() != null) {
                synchronized(peer) {
                    peer.getOutputList().add(msg);
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
            }
            //
            // Decrement the pending input count for the peer and re-enable read
            // when the count reaches zero.  Read is disabled when the peer has
            // sent too many requests at one time.
            //
            synchronized(peer) {
                int count = peer.getInputCount() - 1;
                peer.setInputCount(count);
                if (count == 0 && peer.getOutputList().isEmpty())
                    key.interestOps(key.interestOps() | SelectionKey.OP_READ);
            }
            //
            // Sent initial setup messages if we have successfully exchanged 'version' messages
            //
            if (peer.getVersionCount() == 2) {
                peer.incVersionCount();
                Parameters.networkChainHeight = Math.max(Parameters.networkChainHeight, peer.getHeight());
                log.info(String.format("Connection handshake completed with %s", address));
                //
                // Disconnect if this is an outbound connection and the peer doesn't provide network services
                //
                if ((peer.getServices()&NetParams.NODE_NETWORK) == 0 && address.isOutbound()) {
                    log.info(String.format("Network services not provided by %s", address));
                    closeConnection(peer);
                    continue;
                }
                //
                // Send a 'getaddr' message to exchange peer address lists.
                // Do not do this if we are using static connections since we don't need
                // to know peer addresses.
                //
                if (!staticConnections) {
                    if ((peer.getServices()&NetParams.NODE_NETWORK) != 0) {
                        Message addrMsg = GetAddressMessage.buildGetAddressMessage(peer);
                        synchronized(peer) {
                            peer.getOutputList().add(addrMsg);
                            key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                        }
                    }
                }
                //
                // Send current alert messages
                //
                long currentTime = System.currentTimeMillis()/1000;
                synchronized(Parameters.alerts) {
                    Parameters.alerts.stream()
                        .filter((alert) -> (!alert.isCanceled() &&
                                            alert.getExpireTime() > currentTime))
                        .forEach((alert) -> {
                            Message alertMsg = AlertMessage.buildAlertMessage(peer, alert);
                            synchronized(peer) {
                                peer.getOutputList().add(alertMsg);
                                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                            }
                            log.info(String.format("Sent alert %d to %s", alert.getID(), address));
                        });
                }
                //
                // Send a 'getblocks' message if we are down-level and we haven't sent
                // one yet
                //
                if (getBlocksTime == 0 && (peer.getServices()&NetParams.NODE_NETWORK) != 0) {
                    if (peer.getHeight() > Parameters.blockStore.getChainHeight()) {
                        List<Sha256Hash> blockList = getBlockList();
                        Message getMsg = GetBlocksMessage.buildGetBlocksMessage(peer, blockList, Sha256Hash.ZERO_HASH);
                        synchronized(peer) {
                            peer.getOutputList().add(getMsg);
                            key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                        }
                        getBlocksTime = System.currentTimeMillis()/1000;
                        log.info(String.format("Sent 'getblocks' message to %s", address));
                    }
                }
                connectionListeners.stream().forEach((listener) -> {
                    listener.connectionStarted(peer, connections.size());
                });
            }
        }
    }

    /**
     * Process peer requests
     */
    private void processRequests() {
        long currentTime = System.currentTimeMillis()/1000;
        PeerRequest request;
        Peer peer;
        //
        // Check for request timeouts (we will wait 10 seconds for a response)
        //
        synchronized(Parameters.pendingRequests) {
            while (!Parameters.processedRequests.isEmpty()) {
                request = Parameters.processedRequests.get(0);
                if (request.getTimeStamp() >= currentTime-10 || request.isProcessing())
                    break;
                //
                // Move the request back to the pending queue
                //
                Parameters.processedRequests.remove(0);
                if (request.getType() == InventoryItem.INV_BLOCK)
                    Parameters.pendingRequests.add(request);
                else
                    Parameters.pendingRequests.add(0, request);
            }
        }
        //
        // Send pending requests.  We will suspend request processing if we come to
        // a block request and the database handler has 10 blocks waiting for processing.
        // All pending transaction requests will have been processed at this point since
        // transaction requests are placed at the front of the queue while block requests
        // are placed at the end of the queue.
        //
        while (!Parameters.pendingRequests.isEmpty()) {
            synchronized(Parameters.pendingRequests) {
                request = Parameters.pendingRequests.get(0);
                if (request.getType() == InventoryItem.INV_BLOCK &&
                            (Parameters.databaseQueue.size() >= 10 || Parameters.processedRequests.size() > 50)) {
                    request = null;
                } else {
                    Parameters.pendingRequests.remove(0);
                    Parameters.processedRequests.add(request);
                }
            }
            if (request == null)
                break;
            //
            // Send the request to the origin peer unless we already tried or the peer is
            // no longer connected
            //
            peer = request.getOrigin();
            if (peer != null && (request.wasContacted(peer) || !peer.isConnected()))
                peer = null;
            //
            // Select a peer to process the request.  The peer must provide network
            // services and must not have been contacted for this request.
            //
            if (peer == null) {
                int index = (int)(((double)connections.size())*Math.random());
                for (int i=index; i<connections.size(); i++) {
                    Peer chkPeer = connections.get(i);
                    if ((chkPeer.getServices()&NetParams.NODE_NETWORK)!=0 &&
                                            !request.wasContacted(chkPeer) && chkPeer.isConnected()) {
                        peer = chkPeer;
                        break;
                    }
                }
                if (peer == null) {
                    for (int i=0; i<index; i++) {
                        Peer chkPeer = connections.get(i);
                        if ((chkPeer.getServices()&NetParams.NODE_NETWORK)!=0 &&
                                            !request.wasContacted(chkPeer) && chkPeer.isConnected()) {
                            peer = chkPeer;
                            break;
                        }
                    }
                }
            }
            //
            // Discard the request if all of the available peers have been contacted.  We will
            // increment the banscore for the origin peer since he is broadcasting inventory
            // that he doesn't have.
            //
            if (peer == null) {
                Peer originPeer = request.getOrigin();
                synchronized(Parameters.pendingRequests) {
                    Parameters.processedRequests.remove(request);
                }
                if (originPeer != null) {
                    synchronized(originPeer) {
                        int banScore = originPeer.getBanScore() + 5;
                        originPeer.setBanScore(banScore);
                        if (banScore >= Parameters.MAX_BAN_SCORE)
                            originPeer.setDisconnect(true);
                    }
                }
                String originAddress = (originPeer!=null ? originPeer.getAddress().toString() : "local");
                log.warn(String.format("Purging unavailable %s request initiated by %s\n  %s",
                                       (request.getType()==InventoryItem.INV_BLOCK?"block":"transaction"),
                                       originAddress, request.getHash()));
                continue;
            }
            //
            // Send the request to the peer
            //
            request.addPeer(peer);
            request.setTimeStamp(currentTime);
            List<InventoryItem> invList = new ArrayList<>(1);
            invList.add(new InventoryItem(request.getType(), request.getHash()));
            Message msg = GetDataMessage.buildGetDataMessage(peer, invList);
            synchronized(peer) {
                peer.getOutputList().add(msg);
                SelectionKey key = peer.getKey();
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
            //
            // Send a 'getblocks' message if we are down-level and the request is for a block
            //
            if (request.getType() == InventoryItem.INV_BLOCK &&
                            getBlocksTime < System.currentTimeMillis()/1000-300 &&
                            Parameters.pendingRequests.size() < 10 &&
                            Parameters.blockStore.getChainHeight() < Parameters.networkChainHeight - 100) {
                List<Sha256Hash> blockList = getBlockList();
                msg = GetBlocksMessage.buildGetBlocksMessage(peer, blockList, Sha256Hash.ZERO_HASH);
                synchronized(peer) {
                    peer.getOutputList().add(msg);
                }
                getBlocksTime = System.currentTimeMillis()/1000;
                log.info(String.format("Sent 'getblocks' message to %s", peer.getAddress()));
            }
        }
    }

    /**
     * Get block list for 'getblocks' message
     */
    private List<Sha256Hash> getBlockList() {
        List<Sha256Hash> invList = new ArrayList<>(500);
        try {
            //
            // Get the chain list
            //
            int chainHeight = Parameters.blockStore.getChainHeight();
            int blockHeight = Math.max(0, chainHeight-500);
            List<InventoryItem> chainList = Parameters.blockStore.getChainList(blockHeight, Sha256Hash.ZERO_HASH);
            //
            // Build the locator list starting with the chain head and working backwards towards
            // the genesis block
            //
            int step = 1;
            int loop = 0;
            int pos = chainList.size()-1;
            while (pos >= 0) {
                invList.add(chainList.get(pos).getHash());
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
        return invList;
    }

    /**
     * Gets our external IP address from checkip.dyndns.org
     */
    private void getExternalIP() {
        int inChar;
        try {
            if (hostName != null) {
                Parameters.listenAddress = new PeerAddress(InetAddress.getByName(hostName),
                                                           Parameters.listenPort);
                log.info(String.format("External IP address is %s", Parameters.listenAddress));
            } else {
                URL url = new URL("http://checkip.dyndns.org:80/");
                log.info("Getting external IP address from checkip.dyndns.org");
                try (InputStream inStream = url.openStream()) {
                    StringBuilder outString = new StringBuilder(128);
                    while ((inChar=inStream.read()) >= 0)
                        outString.appendCodePoint(inChar);
                    String ipString = outString.toString();
                    int start = ipString.indexOf(':');
                    if (start < 0) {
                        log.error(String.format("Unrecognized response from checkip.dyndns.org\n  Response: %s",
                                                ipString));
                    } else {
                        int stop = ipString.indexOf('<', start);
                        String ipAddress = ipString.substring(start+1, stop).trim();
                        Parameters.listenAddress = new PeerAddress(InetAddress.getByName(ipAddress),
                                                                   Parameters.listenPort);
                        log.info(String.format("External IP address is %s", Parameters.listenAddress));
                    }
                }
            }
        } catch (UnknownHostException exc) {
            log.error(String.format("Unknown host name %s", hostName));
        } catch (IOException exc) {
            log.error("Unable to get external IP address from checkip.dyndns.org", exc);
        }
    }

    /**
     * Performs DNS lookups to get the initial peer list
     */
    private void dnsDiscovery() {
        //
        // Process each seed node and add the node addresses to our peer list.  We will set random
        // timestamps within the previous week so that we don't always try to connect to the same
        // nodes.
        //
        long currentTime = System.currentTimeMillis()/1000;
        for (String host : dnsSeeds) {
            PeerAddress peerAddress;
            try {
                InetAddress[] addresses = InetAddress.getAllByName(host);
                for (InetAddress address : addresses) {
                    if (Parameters.listenAddress != null &&
                                address.equals(Parameters.listenAddress.getAddress()))
                        continue;
                    long timeSeen = currentTime-(long)((double)(7*24*3600)*Math.random());
                    peerAddress = new PeerAddress(address, Parameters.DEFAULT_PORT, timeSeen);
                    peerAddress.setBroadcast(true);
                    if (Parameters.peerMap.get(peerAddress) == null) {
                        Parameters.peerAddresses.add(peerAddress);
                        Parameters.peerMap.put(peerAddress, peerAddress);
                    }
                }
            } catch (UnknownHostException exc) {
                log.warn(String.format("DNS host %s not found", host));
            }
        }
    }
}
