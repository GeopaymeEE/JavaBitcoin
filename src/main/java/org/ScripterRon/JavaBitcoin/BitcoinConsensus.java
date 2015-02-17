/*
 * Copyright 2015 Ronald W Hoffman.
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

import org.ScripterRon.BitcoinCore.ScriptException;
import org.ScripterRon.BitcoinCore.ScriptParser;
import org.ScripterRon.BitcoinCore.Transaction;
import org.ScripterRon.BitcoinCore.TransactionInput;
import org.ScripterRon.BitcoinCore.TransactionOutput;

/**
 * Bitcoin-Core provides a library to help alternate implementations
 * avoid consensus failures.  This class provides the inteface between
 * JavaBitcoin and the consensus library.
 */
public class BitcoinConsensus {

    /** JNI library available */
    private static boolean jniAvailable = false;

    /** Get the consensus library version */
    private static native int JniGetVersion();

    /** Verify a transaction script */
    private static native int JniVerifyScript(byte[] txBytes, int txIndex, byte[] scriptBytes);

    /**
     * Initialize the JNI library
     */
    public static void init() {
        String libraryName = null;
        String osName = System.getProperty("os.name");
        if (osName != null) {
            osName = osName.toLowerCase();
            String dataModel = System.getProperty("sun.arch.data.model");
            if (dataModel == null)
                dataModel = "32";
            if (osName.contains("windows") || osName.contains("linux")) {
                if (dataModel.equals("64"))
                    libraryName = "JavaBitcoin_x86_64";
                else
                    libraryName = "JavaBitcoin_x86";
            }
        }
        if (libraryName != null) {
            try {
                System.loadLibrary(libraryName);
                jniAvailable = true;
                log.info(String.format("Bitcoin consensus library %s Version %d loaded",
                                       libraryName, JniGetVersion()));
            } catch (UnsatisfiedLinkError exc) {
                log.warn(String.format("Bitcoin consensus library %s is not available - using Java consensus routines",
                                       libraryName));
            } catch (Exception exc) {
                log.error(String.format("Unable to load Bitcoin consensus library %s - using Java consensus routines",
                                        libraryName), exc);
            }
        } else {
            log.warn("Bitcoin consensus library support is not available - using Java consensus routines");
        }
    }

    /**
     * Return the Bitcoin consensus library version
     *
     * @return                      Library version or -1 if the library is not available
     */
    public static int getVersion() {
        return (jniAvailable ? JniGetVersion() : -1);
    }

    /**
     * Verify a transaction script correctly spends a transaction output
     *
     * @param       txInput             Transaction input
     * @param       txOutput            Transaction output
     * @return                          TRUE if the transaction verification was successful
     * @throws      ScriptException     Transaction script is not valid
     */
    public static boolean verifyScript(TransactionInput txInput, TransactionOutput txOutput)
                                        throws ScriptException {
        boolean txValid;
        if (jniAvailable) {
            Transaction tx = txInput.getTransaction();
            int result = JniVerifyScript(tx.getBytes(), txInput.getIndex(), txOutput.getScriptBytes());
            if (result == 0) {
                txValid = true;
            } else if (result == -1) {
                txValid = false;
            } else {
                String msg;
                switch (result) {
                    case -2:            // JNI error
                        msg = "JNI error occurred";
                        break;
                    case 1:             // Invalid transaction index
                        msg = "Invalid transaction index";
                        break;
                    case 2:             // Transaction size mismatch
                        msg = "Transaction size mismatch";
                        break;
                    case 3:             // Transaction deserialization failed
                        msg = "Transaction deserialization failed";
                        break;
                    default:            // Unrecognized error code
                        msg = "Unrecognized consensus library error code "+result;
                }
                throw new ScriptException(msg);
            }
        } else {
            txValid = ScriptParser.process(txInput, txOutput, Parameters.blockStore.getChainHeight());
        }
        return txValid;
    }
}
