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
import static org.ScripterRon.JavaBitcoin.Main.log;

import org.ScripterRon.BitcoinCore.Block;
import org.ScripterRon.BitcoinCore.NetParams;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;
import org.ScripterRon.BitcoinCore.Utils;

/**
 * CreateBootstrap will create the block chain bootstrap files in the specified
 * directory.  The file names will be blknnnnn.dat.gz and will be compressed
 * using GZIP.  These files can be used with the LOAD option to create a new
 * database.
 */
public class CreateBootstrap {

    /**
     * Create the bootstrap files
     *
     * @param       dirPath             Bootstrap directory
     * @param       startHeight         Start chain height
     * @param       stopHeight          Stop chain height
     */
    public static void process(String dirPath, int startHeight, int stopHeight) {
        //
        // Make sure the bootstrap directory exists
        //
        File dirFile = new File(dirPath);
        if (!dirFile.exists() || !dirFile.isDirectory()) {
            log.error(String.format("'%s' is not a directory", dirPath));
            return;
        }
        log.info(String.format("Creating bootstrap files in %s", dirPath));
        //
        // Create the 'blocks' subdirectory if it does not exist
        //
        dirFile = new File(String.format("%s%sblocks", dirPath, Main.fileSeparator));
        if (!dirFile.exists())
            dirFile.mkdir();
        //
        // Erase existing bootstrap files
        //
        File fileList[] = dirFile.listFiles();
        if (fileList != null && fileList.length > 0) {
            for (File file : fileList) {
                String fileName = file.getName();
                if (fileName.startsWith("blk") && fileName.endsWith(".gz"))
                    file.delete();
            }
        }
        //
        // Process the block chain
        //
        String fileName = "";
        int fileNumber = -1;
        int byteCount = 0;
        int start = Math.max(startHeight, 0);
        int stop = Math.min(stopHeight, Parameters.blockStore.getChainHeight());
        File file = null;
        GZIPOutputStream zipOut = null;
        byte[] prefix = new byte[8];
        try {
            for (int height=start; height<=stop; height++) {
                //
                // Close the current bootstrap file after processing 1GB
                //
                if (byteCount > 1024*1024*1024) {
                    zipOut.close();
                    zipOut = null;
                }
                //
                // Open the next bootstrap file
                //
                if (zipOut == null) {
                    fileName = String.format("blk%05d.dat.gz", ++fileNumber);
                    byteCount = 0;
                    file = new File(String.format("%s%sblocks%s%s",
                                dirPath, Main.fileSeparator, Main.fileSeparator, fileName));
                    zipOut = new GZIPOutputStream(new FileOutputStream(file), 1024*1024);
                    log.info(String.format("Creating bootstrap file %s", fileName));
                }
                //
                // Write the block to the bootstrap file
                //
                Block block = Parameters.blockStore.getBlock(Parameters.blockStore.getBlockId(height));
                byte[] blockBytes = block.getBytes();
                Utils.uint32ToByteArrayLE(NetParams.MAGIC_NUMBER, prefix, 0);
                Utils.uint32ToByteArrayLE(blockBytes.length, prefix, 4);
                zipOut.write(prefix);
                zipOut.write(blockBytes);
                byteCount += blockBytes.length;
            }
        } catch (IOException exc) {
            log.error(String.format("I/O error creating bootstrap file %s", fileName), exc);
        } catch (BlockStoreException exc) {
            log.error("Unable to get block from database", exc);
        } catch (Exception exc) {
            log.error("Exception while creating bootstrap files", exc);
        } finally {
            if (file != null && zipOut != null) {
                try {
                    zipOut.close();
                    if (file.length() == 0)
                        file.delete();
                } catch (IOException exc) {
                    log.error(String.format("Unable to close bootstrap file %s", fileName), exc);
                }
            }
        }
    }
}
