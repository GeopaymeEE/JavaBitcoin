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

import org.ScripterRon.BitcoinCore.SerializedBuffer;

import java.io.EOFException;

/**
 * The LevelDB Alerts table contains an entry for each alert that we have received.  The
 * key is the alert ID and the value is an instance of AlertEntry.
 *
 * <p>AlertEntry</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   1 byte     IsCanceled      TRUE if the alert has been canceled
 *   VarInt     PayloadLength   Length of the alert payload
 *   Variable   Payload         Alert payload
 *   VarInt     SigLength       Length of the payload signature
 *   Variable   Signature       Alert signature
 * </pre>
 */
public class AlertEntry {

    /** Cancel status */
    private boolean isCanceled;

    /** Alert payload */
    private final byte[] payload;

    /** Alert signature */
    private final byte[] signature;

    /**
     * Creates a new AlertEntry
     *
     * @param       payload         Alert payload
     * @param       signature       Alert signature
     * @param       isCanceled      TRUE if the alert has been canceled
     */
    public AlertEntry(byte[] payload, byte[] signature, boolean isCanceled) {
        this.isCanceled = isCanceled;
        this.payload = payload;
        this.signature = signature;
    }

    /**
     * Creates a new TransactionEntry
     *
     * @param       entryData       Serialized entry data
     * @throws      EOFException    End-of-data processing serialized data
     */
    public AlertEntry(byte[] entryData) throws EOFException {
        SerializedBuffer inBuffer = new SerializedBuffer(entryData);
        isCanceled = inBuffer.getBoolean();
        payload = inBuffer.getBytes();
        signature = inBuffer.getBytes();
    }

    /**
     * Returns the serialized data stream
     *
     * @return      Serialized data stream
     */
    public byte[] getBytes() {
        SerializedBuffer outBuffer = new SerializedBuffer();
        outBuffer.putBoolean(isCanceled)
                 .putVarInt(payload.length)
                 .putBytes(payload)
                 .putVarInt(signature.length)
                 .putBytes(signature);
        return outBuffer.toByteArray();
    }

    /**
     * Returns the payload
     *
     * @return      Alert payload
     */
    public byte[] getPayload() {
        return payload;
    }

    /**
     * Returns the signature
     *
     * @return      Alert signature
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Checks if the alert has been canceled
     *
     * @return      TRUE if the alert has been canceled
     */
    public boolean isCanceled() {
        return isCanceled;
    }

    /**
     * Set the alert cancel status
     *
     * @param       isCanceled      TRUE if the alert has been canceled
     */
    public void setCancel(boolean isCanceled) {
        this.isCanceled = isCanceled;
    }
}
