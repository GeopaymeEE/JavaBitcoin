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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

/**
 * A script is a small program contained in the transaction which determines whether or not
 * an output can be spent.  The first half of the script is provided by the transaction input
 * and the second half of the script is provided by the transaction output.
 */
public class Script {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Script.class);

    /**
     * Checks that the script consists of only push-data operations.
     *
     * For canonical scripts, each push-data operation must use the shortest opcode possible.
     * Numeric values between 0 and 16 must use OP_n opcodes.
     *
     * @param       scriptBytes     Script bytes
     * @param       canonical       TRUE for canonical checking
     * @return                      TRUE if only canonical push-data operations were found
     * @throws      EOFException    Script is too short
     */
    public static boolean checkInputScript(byte[] scriptBytes, boolean canonical) throws EOFException {
        boolean scriptValid = true;
        int offset = 0;
        int length = scriptBytes.length;
        while (scriptValid && offset < length) {
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                int dataLength = result[0];
                offset = result[1];
                if (canonical) {
                    if (dataLength == 1) {
                        if (opcode != 1 || ((int)scriptBytes[offset]&0xff) <= 16) {
                            log.warn("Pushing numeric value between 0 and 16");
                            scriptValid = false;
                        }
                    } else if (dataLength < 76) {
                        if (opcode >= ScriptOpCodes.OP_PUSHDATA1) {
                            log.warn("Pushing data length less than 76 with multi-byte opcode");
                            scriptValid = false;
                        }
                    } else if (dataLength < 256) {
                        if (opcode != ScriptOpCodes.OP_PUSHDATA1) {
                            log.warn("Pushing data length less than 256 with multi-byte opcode");
                            scriptValid = false;
                        }
                    } else if (dataLength < 65536) {
                        if (opcode != ScriptOpCodes.OP_PUSHDATA2) {
                            log.warn("Pushing data length less than 65536 with multi-byte opcode");
                            scriptValid = false;
                        }
                    }
                }
                offset += dataLength;
                if (offset > length)
                    throw new EOFException("End-of-data while processing script");
            } else if (opcode > ScriptOpCodes.OP_16) {
                log.warn("Non-pushdata opcode");
                scriptValid = false;
            }
        }
        if (!scriptValid)
            Main.dumpData("Failing Input Script", scriptBytes);
        return scriptValid;
    }

    /**
     * Get the input data elements
     *
     * @param       scriptBytes     Script bytes
     * @return                      Data element list
     * @throws      EOFException    Script is too short
     */
    public static List<byte[]> getData(byte[] scriptBytes) throws EOFException {
        List<byte[]> dataList = new ArrayList<>();
        int offset = 0;
        int length = scriptBytes.length;
        while (offset<length) {
            int dataLength;
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                dataLength = result[0];
                offset = result[1];
                if (dataLength > 0) {
                    if (offset+dataLength > length)
                        throw new EOFException("End-of-data while processing script");
                    dataList.add(Arrays.copyOfRange(scriptBytes, offset, offset+dataLength));
                    offset += dataLength;
                }
            }
        }
        return dataList;
    }

    /**
     * Count the number of signature operations in a script
     *
     * OP_CHECKSIG and OP_CHECKSIGVERIFY count as 1 signature operation
     *
     * OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY count as n signature operations where
     * n is the number of public keys preceding the opcode.
     *
     * @param       scriptBytes         Script bytes
     * @return                          TRUE if the number of signature operations is acceptable
     * @throws      EOFException        Script is too short
     */
    public static boolean countSigOps(byte[] scriptBytes) throws EOFException {
        int sigCount = 0;
        int offset = 0;
        int length = scriptBytes.length;
        while (offset < length) {
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                int dataLength = result[0];
                offset = result[1];
                offset += dataLength;
                if (offset > length)
                    throw new EOFException("End-of-data while processing script");
            } else if (opcode == ScriptOpCodes.OP_CHECKSIG || opcode == ScriptOpCodes.OP_CHECKSIGVERIFY) {
                // OP_CHECKSIG counts as 1 signature operation
                sigCount++;
            } else if (opcode == ScriptOpCodes.OP_CHECKMULTISIG ||   opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY) {
                // OP_CHECKMULTISIG counts as 1 signature operation for each pubkey
                if (offset > 1) {
                    int keyCount = ((int)scriptBytes[offset-2])&0xff;
                    if (keyCount>=81 && keyCount<=96)
                        sigCount += keyCount-80;
                }
            }
        }
        return (sigCount<=ScriptOpCodes.MAX_SIG_OPS);
    }

    /**
     * Checks script data elements against a Bloom filter
     *
     * @param       filter              Bloom filter
     * @param       scriptBytes         Script to check
     * @return                          TRUE if a data element in the script matched the filter
     */
    public static boolean checkFilter(BloomFilter filter, byte[] scriptBytes) {
        boolean foundMatch = false;
        int offset = 0;
        int length = scriptBytes.length;
        //
        // Check each data element in the script
        //
        try {
            while (offset<length && !foundMatch) {
                int dataLength;
                int opcode = ((int)scriptBytes[offset++])&0xff;
                if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                    //
                    // Get the data element
                    //
                    int[] result = getDataLength(opcode, scriptBytes, offset);
                    dataLength = result[0];
                    offset = result[1];
                    if (dataLength > 0) {
                        if (offset+dataLength > length)
                            throw new EOFException("End-of-data while processing script");
                        foundMatch = filter.contains(scriptBytes, offset, dataLength);
                        offset += dataLength;
                    }
                }
            }
        } catch (EOFException exc) {
            log.warn("Unable to check script against Bloom filter", exc);
            Main.dumpData("Failing Script Program", scriptBytes);
        }
        return foundMatch;
    }

    /**
     * Returns the payment type for an output script
     *
     * @param       scriptBytes         Script to check
     * @return      Payment type or 0 if not a standard payment type
     */
    public static int getPaymentType(byte[] scriptBytes) {
        int paymentType = 0;
        if (scriptBytes.length > 0) {
            if (scriptBytes[0] == (byte)ScriptOpCodes.OP_RETURN) {
                //
                // Scripts starting with OP_RETURN are unspendable
                //
                paymentType = ScriptOpCodes.PAY_TO_NOBODY;
            } else if (scriptBytes[0] == (byte)ScriptOpCodes.OP_DUP) {
                //
                // Check PAY_TO_PUBKEY_HASH
                //   OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
                //
                if (scriptBytes.length == 25 && scriptBytes[1] == (byte)ScriptOpCodes.OP_HASH160 &&
                                                scriptBytes[2] == 20 &&
                                                scriptBytes[23] == (byte)ScriptOpCodes.OP_EQUALVERIFY &&
                                                scriptBytes[24] == (byte)ScriptOpCodes.OP_CHECKSIG)
                    paymentType = ScriptOpCodes.PAY_TO_PUBKEY_HASH;
            } else if (((int)scriptBytes[0]&0xff) <= 65) {
                //
                // Check PAY_TO_PUBKEY
                //   <pubkey> OP_CHECKSIG
                //
                int length = (int)scriptBytes[0];
                if (scriptBytes.length == length+2 && scriptBytes[length+1] == (byte)ScriptOpCodes.OP_CHECKSIG)
                    paymentType = ScriptOpCodes.PAY_TO_PUBKEY;
            } else if (scriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160) {
                //
                // Check PAY_TO_SCRIPT_HASH
                //   OP_HASH160 <20-byte hash> OP_EQUAL
                //
                if (scriptBytes.length == 23 && scriptBytes[1] == 20 &&
                                                scriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL)
                    paymentType = ScriptOpCodes.PAY_TO_SCRIPT_HASH;
            } else if (((int)scriptBytes[0]&0xff) >= 81 && ((int)scriptBytes[0]&0xff) <= 96) {
                //
                // Check PAY_TO_MULTISIG
                //   <m> <pubkey> <pubkey> ... <n> OP_CHECKMULTISIG
                //
                int offset = 1;
                while (offset < scriptBytes.length) {
                    int opcode = (int)scriptBytes[offset]&0xff;
                    if (opcode <= 65) {
                        //
                        // We have another pubkey - step over it
                        //
                        offset += opcode+1;
                        continue;
                    }
                    if (opcode >= 81 && opcode <= 96) {
                        //
                        // We have found <n>
                        //
                        if (scriptBytes.length == offset+2 &&
                                        scriptBytes[offset+1] == (byte)ScriptOpCodes.OP_CHECKMULTISIG)
                            paymentType = ScriptOpCodes.PAY_TO_MULTISIG;
                    }
                    break;
                }
            }
        }
        return paymentType;
    }

    /**
     * Get the length of the next data element
     *
     * @param       opcode              Current opcode
     * @param       scriptBytes         Script program
     * @param       startOffset         Offset to byte following the opcode
     * @return      Array containing the data length and the offset to the data
     * @throws      EOFException        Script is too short
     */
    public static int[] getDataLength(int opcode, byte[] scriptBytes, int startOffset) throws EOFException {
        int[] result = new int[2];
        int offset = startOffset;
        int dataToRead;
        if (opcode < ScriptOpCodes.OP_PUSHDATA1) {
            // These opcodes push data with a length equal to the opcode
            dataToRead = opcode;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA1) {
            // The data length is in the next byte
            if (offset > scriptBytes.length-1)
                throw new EOFException("End-of-data while processing script");
            dataToRead = (int)scriptBytes[offset]&0xff;
            offset++;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA2) {
            // The data length is in the next two bytes
            if (offset > scriptBytes.length-2)
                throw new EOFException("End-of-data while processing script");
            dataToRead = ((int)scriptBytes[offset]&0xff) | (((int)scriptBytes[offset+1]&0xff)<<8);
            offset += 2;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA4) {
            // The data length is in the next four bytes
            if (offset > scriptBytes.length-4)
                throw new EOFException("End-of-data while processing script");
            dataToRead = ((int)scriptBytes[offset]&0xff) |
                                    (((int)scriptBytes[offset+1]&0xff)<<8) |
                                    (((int)scriptBytes[offset+2]&0xff)<<16) |
                                    (((int)scriptBytes[offset+3]&0xff)<<24);
            offset += 4;
        } else {
            dataToRead = 0;
        }
        result[0] = dataToRead;
        result[1] = offset;
        return result;
    }
}
