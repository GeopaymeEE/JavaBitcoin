/*
 * Copyright 2013-2014 Ronald Hoffman.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.List;

/**
 * Create the block database by loading the blocks from existing block chain files (such as
 * the blknnnnn.dat files created by the reference client)
 */
public class LoadBlockChain {
    
    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(LoadBlockChain.class);

    /**
     * Load the block chain from the reference client data directory
     * 
     * @param       blockChainPath      Reference client application directory path
     * @param       startBlock          Starting block file number
     * @param       stopBlock           Stop block file number
     */
    public static void load(String blockChainPath, int startBlock, int stopBlock) {
        int blockCount = 0;
        int heldCount = 0;
        String fileName = null;
        boolean stopLoad = false;
        log.info(String.format("Loading block chain from '%s'", blockChainPath));
        try {
            //
            // Get the block chain file list from the 'blocks' subdirectory sorted by ordinal value
            // (blk00000.dat, blk00001.dat, blk00002.dat, etc).  We will stop when we reach a
            // non-existent file.
            //
            List<File> fileList = new ArrayList<>(150);
            for (int i=startBlock; i<=stopBlock; i++) {
                File file = new File(String.format("%s%sblocks%sblk%05d.dat",
                                                   blockChainPath, Main.fileSeparator, Main.fileSeparator, i));
                if (!file.exists())
                    break;
                fileList.add(file);
            }
            //
            // Read the blocks in each file
            //
            // The blocks in the file are separated by 4 bytes containing the network-specific packet magic
            // value.  The next 4 bytes contain the block length in little-endian format.
            //
            byte[] numBuffer = new byte[8];
            byte[] blockBuffer = new byte[Parameters.MAX_BLOCK_SIZE];
            for (File inFile : fileList) {
                fileName = inFile.getName();
                log.info(String.format("Processing block data file %s", fileName));
                try (FileInputStream in = new FileInputStream(inFile)) {
                    while (!stopLoad) {
                        //
                        // Get the magic number and the block length from the input stream.
                        // Stop when we reach the end of the file or the magic number is zero.
                        //
                        int count = in.read(numBuffer);
                        if (count < 8)
                            break;
                        long magic = Utils.readUint32LE(numBuffer, 0);
                        long length = Utils.readUint32LE(numBuffer, 4);
                        if (magic == 0)
                            break;
                        if (magic != Parameters.MAGIC_NUMBER) {
                            log.error(String.format("Block magic number %X is incorrect", magic));
                            throw new IOException("Incorrect file format");
                        }
                        if (length > blockBuffer.length) {
                            log.error(String.format("Block length %d exceeds maximum block size", length));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Read the block from the input stream
                        //
                        count = in.read(blockBuffer, 0, (int)length);
                        if (count != (int)length) {
                            log.error(String.format("Block truncated: Needed %d bytes, Read %d bytes",
                                      (int)length, count));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Create a new block from the serialized byte stream.  Since we are
                        // reading from a trusted input source, we won't waste time verifying blocks
                        // (this also avoids a lot of problems with bad blocks that made it into
                        // the block chain before the rules were tightened)
                        //
                        Block block = new Block(blockBuffer, 0, count, false);
                        //
                        // Add the block to the block store and update the block chain.  Stop
                        // loading blocks if we get 25 consecutive blocks being held (something
                        // is wrong and needs to be investigated)
                        //
                        if (Parameters.blockStore.isNewBlock(block.getHash())) {
                            if (Parameters.blockChain.storeBlock(block) == null) {
                              log.info(String.format("Current block was not added to the block chain\n  %s",
                                                     block.getHashAsString()));
                              if (++heldCount >= 25)
                                stopLoad = true;
                            } else {
                                heldCount = 0;
                            }
                        }
                        blockCount++;
                    }
                }
                //
                // Stop loading blocks if we encountered a problem
                //
                if (stopLoad)
                    break;
            }
            //
            // All done
            //
            log.info(String.format("Processed %d blocks", blockCount));
        } catch (IOException exc) {
            log.error(String.format("I/O error reading block chain file %s", fileName), exc);
        } catch (BlockStoreException exc) {
            log.error("Unable to store block in database", exc);
        } catch (VerificationException exc) {
            log.error("Block verification error", exc);
        } catch (Exception exc) {
            log.error("Exception during block chain load", exc);
        }
    }
}
