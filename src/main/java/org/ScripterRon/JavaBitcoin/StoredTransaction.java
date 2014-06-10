/**
 * Copyright 2013 Ronald W Hoffman
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

import org.ScripterRon.BitcoinCore.SerializedBuffer;
import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.VerificationException;

import java.io.EOFException;

/**
 * Transactions are stored in a memory pool while they are relayed to other nodes
 * in the network.  They are purged periodically to make room for newer transactions.
 */
public class StoredTransaction {

    /** Serialized transaction */
    private final byte[] txData;

    /** Transaction hash */
    private final Sha256Hash hash;

    /** Parent transaction hash */
    private Sha256Hash parentHash;

    /** Time when transaction was broadcast */
    private final long txTimeStamp;

    /**
     * Creates a new stored transaction
     *
     * @param       tx                  Transaction
     */
    public StoredTransaction(Transaction tx) {
        hash = tx.getHash();
        txData = tx.getBytes();
        txTimeStamp = System.currentTimeMillis()/1000;
    }

    /**
     * Return the transaction
     *
     * @return      Transaction
     */
    public Transaction getTransaction() {
        SerializedBuffer txBuffer = new SerializedBuffer(txData);
        Transaction tx;
        try {
            tx = new Transaction(txBuffer);
        } catch (EOFException | VerificationException exc) {
            throw new RuntimeException("Unable to get transaction: "+exc.getMessage());
        }
        return tx;
    }

    /**
     * Returns the transaction hash
     *
     * @return      Transaction hash
     */
    public Sha256Hash getHash() {
        return hash;
    }

    /**
     * Returns the parent transaction hash.  The parent is a transaction whose output is
     * being spent by this transaction.  This is used when tracking orphan transactions.
     *
     * @return      Parent transaction hash or null if there is no parent
     */
    public Sha256Hash getParent() {
        return parentHash;
    }

    /**
     * Sets the parent transaction hash
     *
     * @param       parentHash          Parent transaction hash
     */
    public void setParent(Sha256Hash parentHash) {
        this.parentHash = parentHash;
    }

    /**
     * Returns the serialized transaction data
     *
     * @return      Serialized byte stream
     */
    public byte[] getBytes() {
        return txData;
    }

    /**
     * Returns the transaction timestamp
     *
     * @return      Time when transaction was broadcast
     */
    public long getTimeStamp() {
        return txTimeStamp;
    }
}
