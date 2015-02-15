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

import org.ScripterRon.BitcoinCore.Alert;
import org.ScripterRon.BitcoinCore.Block;
import org.ScripterRon.BitcoinCore.BloomFilter;
import org.ScripterRon.BitcoinCore.Message;
import org.ScripterRon.BitcoinCore.OutPoint;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.PeerAddress;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Global parameters for JavaBitcoin
 */
public class Parameters {

    /** Minimum protocol version */
    public static final int MIN_PROTOCOL_VERSION = 60001;

    /** Genesis block bytes */
    public static byte[] GENESIS_BLOCK_BYTES;

    /** Default network port */
    public static final int DEFAULT_PORT = 8333;

    /** Coinbase transaction maturity */
    public static final int COINBASE_MATURITY = 100;

    /** Minimum transaction relay fee */
    public static final BigInteger MIN_TX_RELAY_FEE = new BigInteger("1000", 10);

    /** Maximum free transaction size */
    public static final int MAX_FREE_TX_SIZE = 10000;

    /** Maximum ban score before a peer is disconnected */
    public static final int MAX_BAN_SCORE = 100;

    /** Maximum peer address age (seconds) */
    public static final int MAX_PEER_ADDRESS_AGE = 8*60*60;

    /** Block store */
    public static BlockStore blockStore;

    /** Block chain */
    public static BlockChain blockChain;

    /** Network handler */
    public static NetworkHandler networkHandler;

    /** Network message handler */
    public static NetworkMessageListener networkMessageListener;

    /** Local listen address */
    public static PeerAddress listenAddress;

    /** Local listen port */
    public static int listenPort;

    /** Number of blocks received */
    public static final AtomicLong blocksReceived = new AtomicLong();

    /** Number of blocks sent */
    public static final AtomicLong blocksSent = new AtomicLong();

    /** Number of filtered blocks sent */
    public static final AtomicLong filteredBlocksSent = new AtomicLong();

    /** Number of transactions received */
    public static final AtomicLong txReceived = new AtomicLong();

    /** Number of transactions sent */
    public static final AtomicLong txSent = new AtomicLong();

    /** Number of transactions rejected */
    public static final AtomicLong txRejected = new AtomicLong();

    /** Network chain height */
    public static int networkChainHeight;

    /** List of peer requests that are waiting to be sent - synchronized on pendingRequests */
    public static final List<PeerRequest> pendingRequests = new LinkedList<>();

    /** List of peer requests that are waiting for a response - synchronized on pendingRequests */
    public static final List<PeerRequest> processedRequests = new LinkedList<>();

    /** Map of transactions in the memory pool (txHash, tx) - synchronized on txMap */
    public static final Map<Sha256Hash, StoredTransaction> txMap = new HashMap<>(250);

    /** Map of recent transactions (txHash, txHash) - synchronized on txMap */
    public static final Map<Sha256Hash, Sha256Hash> recentTxMap = new HashMap<>(250);

    /** Map of orphan transactions (parentTxHash, orphanTxList) - synchronized on txMap */
    public static final Map<Sha256Hash, List<StoredTransaction>> orphanTxMap = new HashMap<>(250);

    /** Map of recent spent outputs (Outpoint. spendingTxHash) - synchronized on txMap */
    public static final Map<OutPoint, Sha256Hash> spentOutputsMap = new HashMap<>(250);

    /** List of Bloom filters - synchronized on bloomFilters */
    public static final List<BloomFilter> bloomFilters = new LinkedList<>();

    /** Database handler message queue */
    public static final LinkedBlockingQueue<Block> databaseQueue = new LinkedBlockingQueue<>();

    /** Message handler message queue */
    public static final LinkedBlockingQueue<Message> messageQueue = new LinkedBlockingQueue<>(250);

    /** Peer addresses - synchronized on peerAddresses */
    public static final List<PeerAddress> peerAddresses = new LinkedList<>();

    /** Peer address map - synchronized on peerAddresses */
    public static final Map<PeerAddress, PeerAddress> peerMap = new HashMap<>(250);

    /** Completed messages */
    public static final ConcurrentLinkedQueue<Message> completedMessages = new ConcurrentLinkedQueue<>();

    /** Alert list */
    public static final List<Alert> alerts = new ArrayList<>();
}
