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

import org.ScripterRon.BitcoinCore.Sha256Hash;
import org.ScripterRon.BitcoinCore.VarInt;

import java.io.EOFException;

/**
 * TransactionID consists of the transaction hash plus the transaction output index
 * and is used as the key for the LevelDB TxOutputs table.
 */
public class TransactionID {

    /** Transaction hash */
    private final Sha256Hash txHash;

    /** Transaction output index */
    private final int txIndex;

    /**
     * Creates the transaction ID
     *
     * @param       txHash          Transaction hash
     * @param       txIndex         Transaction output index
     */
    public TransactionID(Sha256Hash txHash, int txIndex) {
        this.txHash = txHash;
        this.txIndex = txIndex;
    }

    /**
     * Creates the transaction ID from the serialized key data
     *
     * @param       bytes           Serialized key data
     * @throws      EOFException    End-of-data reached
     */
    public TransactionID(byte[] bytes) throws EOFException {
        if (bytes.length < 33)
            throw new EOFException("End-of-data while processing TransactionID");
        txHash = new Sha256Hash(bytes, 0, 32);
        txIndex = new VarInt(bytes, 32).toInt();
    }

    /**
     * Returns the serialized transaction ID
     *
     * @return      Serialized transaction ID
     */
    public byte[] getBytes() {
        byte[] indexData = VarInt.encode(txIndex);
        byte[] bytes = new byte[32+indexData.length];
        System.arraycopy(txHash.getBytes(), 0, bytes, 0, 32);
        System.arraycopy(indexData, 0, bytes, 32, indexData.length);
        return bytes;
    }

    /**
     * Returns the transaction hash
     *
     * @return                  Transaction hash
     */
    public Sha256Hash getTxHash() {
        return txHash;
    }

    /**
     * Returns the transaction output index
     *
     * @return                  Transaction output index
     */
    public int getTxIndex() {
        return txIndex;
    }

    /**
     * Compares two objects
     *
     * @param       obj         Object to compare
     * @return                  TRUE if the objects are equal
     */
    @Override
    public boolean equals(Object obj) {
        return (obj!=null && (obj instanceof TransactionID) &&
                        txHash.equals(((TransactionID)obj).txHash) && txIndex==((TransactionID)obj).txIndex);
    }

    /**
     * Returns the hash code
     *
     * @return                  Hash code
     */
    @Override
    public int hashCode() {
        return txHash.hashCode()^txIndex;
    }
}
