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

import org.ScripterRon.BitcoinCore.BlockHeader;
import org.ScripterRon.BitcoinCore.SerializedBuffer;
import org.ScripterRon.BitcoinCore.Sha256Hash;

import java.io.EOFException;
import java.math.BigInteger;

/**
 * The LevelDB Blocks database contains an entry for each block stored in one
 * of the block files.  The key is the block hash and the value is an
 * instance of BlockEntry.
 *
 * <p>BlockEntry</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   1 byte     OnChain         Block is on the chain
 *   1 byte     OnHold          Block is on hold
 *  32 bytes    PrevHash        Previous block hash
 *  VarBytes    ChainWork       Chain work
 *   VarInt     TimeStamp       Block timestamp
 *   VarInt     BlockHeight     Block height
 *   VarInt     FileNumber      Block file number
 *   VarInt     FileOffset      Block file offset
 *  80 bytes    Header          Block header
 * </pre>
 */
public class BlockEntry {

    /** Previous block hash */
    private final Sha256Hash prevHash;

    /** Block height */
    private int blockHeight;

    /** Chain work */
    private BigInteger chainWork;

    /** Block timestamp */
    private final long timeStamp;

    /** Block chain status */
    private boolean onChain;

    /** Block hold status */
    private boolean onHold;

    /** Block file number */
    private int fileNumber;

    /** Block file offset */
    private int fileOffset;

    /** Block header */
    private byte[] header;

    /**
     * Creates a new BlockEntry
     *
     * @param       prevHash        Previous block hash
     * @param       blockHeight     Block height
     * @param       chainWork       Chain work
     * @param       onChain         TRUE if the block is on the chain
     * @param       onHold          TRUE if the block is held
     * @param       timeStamp       Block timestamp
     * @param       fileNumber      Block file number
     * @param       fileOffset      Block file offset
     * @param       header          Block header
     */
    public BlockEntry(Sha256Hash prevHash, int blockHeight, BigInteger chainWork,
                                    boolean onChain, boolean onHold, long timeStamp,
                                    int fileNumber, int fileOffset, byte[] header) {
        this.prevHash = prevHash;
        this.blockHeight = blockHeight;
        this.chainWork = chainWork;
        this.onChain = onChain;
        this.onHold = onHold;
        this.timeStamp = timeStamp;
        this.fileNumber = fileNumber;
        this.fileOffset = fileOffset;
        this.header = header;
    }

    /**
     * Creates a new BlockEntry from the serialized entry data
     *
     * @param       entryData       Serialized entry data
     * @throws      EOFException    End-of-data processing the serialized data
     */
    public BlockEntry(byte[] entryData) throws EOFException {
        SerializedBuffer inBuffer = new SerializedBuffer(entryData);
        onChain = inBuffer.getBoolean();
        onHold = inBuffer.getBoolean();
        prevHash = new Sha256Hash(inBuffer.getBytes(32));
        chainWork = new BigInteger(inBuffer.getBytes());
        timeStamp = inBuffer.getVarLong();
        blockHeight = inBuffer.getVarInt();
        fileNumber = inBuffer.getVarInt();
        fileOffset = inBuffer.getVarInt();
        if (inBuffer.available() >= BlockHeader.HEADER_SIZE)
            header = inBuffer.getBytes(BlockHeader.HEADER_SIZE);
        else
            header = new byte[0];
    }

    /**
     * Returns the serialized entry data
     *
     * @return      Serialized data stream
     */
    public byte[] getBytes() {
        byte[] workBytes = chainWork.toByteArray();
        SerializedBuffer outBuffer = new SerializedBuffer();
        outBuffer.putBoolean(onChain)
                 .putBoolean(onHold)
                 .putBytes(prevHash.getBytes())
                 .putVarInt(workBytes.length)
                 .putBytes(workBytes)
                 .putVarLong(timeStamp)
                 .putVarInt(blockHeight)
                 .putVarInt(fileNumber)
                 .putVarInt(fileOffset)
                 .putBytes(header);
        return outBuffer.toByteArray();
    }

    /**
     * Returns the previous block hash
     *
     * @return      Block hash
     */
    public Sha256Hash getPrevHash() {
        return prevHash;
    }

    /**
     * Returns the block timestamp
     *
     * @return      Block timestamp
     */
    public long getTimeStamp() {
        return timeStamp;
    }

    /**
     * Returns the block height
     *
     * @return      Block height
     */
    public int getHeight() {
        return blockHeight;
    }

    /**
     * Sets the block height
     *
     * @param       blockHeight     Tne block height
     */
    public void setHeight(int blockHeight) {
        this.blockHeight = blockHeight;
    }

    /**
     * Returns the chain work
     *
     * @return      Chain work
     */
    public BigInteger getChainWork() {
        return chainWork;
    }

    /**
     * Sets the chain work
     *
     * @param       chainWork       Chain work
     */
    public void setChainWork(BigInteger chainWork) {
        this.chainWork = chainWork;
    }

    /**
     * Returns the block chain status
     *
     * @return      TRUE if the block is on the chain
     */
    public boolean isOnChain() {
        return onChain;
    }

    /**
     * Sets the block chain status
     *
     * @param       onChain         TRUE if the block is on the chain
     */
    public void setChain(boolean onChain) {
        this.onChain = onChain;
    }

    /**
     * Return the block hold status
     *
     * @return      TRUE if the block is held
     */
    public boolean isOnHold() {
        return onHold;
    }

    /**
     * Sets the block hold status
     *
     * @param       onHold          TRUE if the block is held
     */
    public void setHold(boolean onHold) {
        this.onHold = onHold;
    }

    /**
     * Returns the block file number
     *
     * @return      Block file number
     */
    public int getFileNumber() {
        return fileNumber;
    }

    /**
     * Sets the block file number
     *
     * @param       fileNumber      The new block file number
     */
    public void setFileNumber(int fileNumber) {
        this.fileNumber = fileNumber;
    }

    /**
     * Returns the block file offset
     *
     * @return      Block file offset
     */
    public int getFileOffset() {
        return fileOffset;
    }

    /**
     * Sets the block file offset
     *
     * @param       fileOffset      The new block file offset
     */
    public void setFileOffset(int fileOffset) {
        this.fileOffset = fileOffset;
    }

    /**
     * Return the block header bytes
     *
     * @return                      Header bytes
     */
    public byte[] getHeaderBytes() {
        return header;
    }

    /**
     * Set the block header bytes
     *
     * @param       headerBytes     Header bytes
     */
    public void setHeaderBytes(byte[] headerBytes) {
        header = headerBytes;
    }
}
