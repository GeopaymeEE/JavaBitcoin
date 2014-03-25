/*
 * Copyright 2014 Ronald W Hoffman.
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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Transaction script parser
 * 
 * A script is a small program contained in the transaction which determines whether or not
 * an output can be spent.  The first half of the script is provided by the transaction input
 * and the second half of the script is provided by the transaction output.
 */
public class ScriptParser {
    
    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(ScriptParser.class);
    
    /**
     * Processes a transaction script to determine if the spending transaction 
     * is authorized to spend the output coins
     * 
     * @param       txInput             Transaction input spending the coins
     * @param       txOutput            Transaction output providing the coins
     * @return                          The script result
     * @throws      ScriptException     Unable to process the transaction script
     */
    public static boolean process(TransactionInput txInput, StoredOutput txOutput)
                                        throws ScriptException {
        Transaction tx = txInput.getTransaction();
        boolean txValid = true;
        boolean pay2ScriptHash = false;
        List<byte[]> scriptStack = new ArrayList<>(5);
        List<StackElement> elemStack = new ArrayList<>(25);
        byte[] inputScriptBytes = txInput.getScriptBytes();
        if (inputScriptBytes.length != 0)
            scriptStack.add(inputScriptBytes);
        byte[] outputScriptBytes = txOutput.getScriptBytes();
        if (outputScriptBytes.length != 0)
            scriptStack.add(outputScriptBytes);
        //
        // The result is FALSE if there are no scripts to process since an empty stack
        // is the same as FALSE
        //
        if (scriptStack.isEmpty())
            return false;
        //
        // Check for a pay-to-script-hash output (BIP0016)
        //
        // The output script: OP_HASH160 <20-byte hash> OP_EQUAL
        // The inputs script: can contain only data elements and must have at least two elements
        // The block height must be greater than 175,000
        //
        if (Parameters.blockStore.getChainHeight() > 175000 && scriptStack.size() == 2 &&
                                            outputScriptBytes.length == 23 &&
                                            outputScriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160 &&
                                            outputScriptBytes[1] == 20 &&
                                            outputScriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL) {
            int offset = 0;
            int count = 0;
            pay2ScriptHash = true;
            try {
                while (offset < inputScriptBytes.length) {
                    int opcode = (int)inputScriptBytes[offset++]&0xff;
                    if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                        int[] result = Script.getDataLength(opcode, inputScriptBytes, offset);
                        offset = result[0] + result[1];
                        count++;
                    } else {
                        pay2ScriptHash = false;
                        break;
                    }
                }
                if (count < 2)
                    pay2ScriptHash = false;
            } catch (EOFException exc) {
                log.error(String.format("End-of-datat while scanning input script\n  Tx %s", 
                                         tx.getHash().toString()));
                Main.dumpData("Failing Input Script", inputScriptBytes);
                throw new ScriptException("End-of-data while scanning input script");
            }
        }
        //
        // Process the script segments
        //
        try {
            boolean p2sh = pay2ScriptHash;
            while (txValid && !scriptStack.isEmpty()) {
                txValid = processScript(txInput, scriptStack, elemStack, p2sh);
                scriptStack.remove(0);
                if (pay2ScriptHash && !scriptStack.isEmpty()) {
                    byte[] scriptBytes = scriptStack.get(0);
                    p2sh = (scriptBytes.length == 23 && 
                            scriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160 &&
                            scriptBytes[1] == 20 &&
                            scriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL);
                }
            }
        } catch (Throwable exc) {
            log.error(String.format("%s\n  Tx %s", exc.getMessage(), tx.getHash().toString()));
            Main.dumpData("Failing Script", scriptStack.get(0));
            throw new ScriptException(exc.getMessage());
        }
        //
        // The script is successful if a non-zero value is on the top of the stack.  An
        // empty stack is the same as a FALSE value.
        //
        if (txValid) {
            if (elemStack.isEmpty()) {
                txValid = false;
            } else {
                txValid = popStack(elemStack).isTrue();
            }
        }
        
        return txValid;
    }
    
    /**
     * Processes the current script
     * 
     * @param       txInput             The current transaction input
     * @param       scriptStack         Script stack
     * @param       elemStack           Element stack
     * @param       p2sh                TRUE if this is a pay-to-script-hash
     * @return                          Script result
     * @throws      EOFException        End-of-data processing script
     * @throws      IOException         Unable to process signature
     * @throws      ScriptException     Unable to process script
     */
    private static boolean processScript(TransactionInput txInput, List<byte[]> scriptStack, 
                                        List<StackElement> elemStack, boolean p2sh) 
                                        throws EOFException, IOException, ScriptException {
        boolean txValid = true;
        byte[] scriptBytes = scriptStack.get(0);
        int offset = 0;
        int lastSeparator = 0;
        //
        // Process the script opcodes
        //
        while (txValid && offset<scriptBytes.length) {
            StackElement elem, elem1, elem2;
            byte[] bytes;
            int dataToRead = -1;
            int opcode = (int)scriptBytes[offset++]&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                // Data push opcodes
                int[] result = Script.getDataLength(opcode, scriptBytes, offset);
                dataToRead = result[0];
                offset = result[1];
            } else if (opcode >= ScriptOpCodes.OP_1 && opcode <= ScriptOpCodes.OP_16) {
                // Push 1 to 16 onto the stack based on the opcode (0x51-0x60)
                bytes = new byte[1];
                bytes[0] = (byte)(opcode&0x0f);
                if (bytes[0] == 0)
                    bytes[0] = (byte)16;
                elemStack.add(new StackElement(bytes));
            } else if (opcode >= ScriptOpCodes.OP_NOP1 && opcode <= ScriptOpCodes.OP_NOP10) {
                // Reserved for future expansion
            } else {
                switch (opcode) {
                    case ScriptOpCodes.OP_NOP:
                        // Do nothing
                        break;
                    case ScriptOpCodes.OP_RETURN:
                        // Mark transaction invalid
                        txValid = false;
                        break;
                    case ScriptOpCodes.OP_CODESEPARATOR:
                        // Signature operations ignore data before the separator
                        lastSeparator = offset;
                        break;
                    case ScriptOpCodes.OP_1NEGATE:
                        // Push -1 onto the stack
                        elemStack.add(new StackElement(new byte[]{(byte)255}));
                        break;
                    case ScriptOpCodes.OP_NOT:
                        // Reverse the top stack element (TRUE->FALSE, FALSE->TRUE)
                        elemStack.add(new StackElement(!popStack(elemStack).isTrue()));
                        break;
                    case ScriptOpCodes.OP_MIN:
                        // Compare top 2 stack elements and replace with the smaller
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(elem1.compareTo(elem2)<=0 ? elem1 : elem2);
                        break;
                    case ScriptOpCodes.OP_MAX:
                        // Compare top 2 stack elements and replace with the larger
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        elemStack.add(elem1.compareTo(elem2)>=0 ? elem1 : elem2);
                        break;
                    case ScriptOpCodes.OP_DROP:
                        // Pop the stack
                        popStack(elemStack);
                        break;
                    case ScriptOpCodes.OP_DUP:
                        // Duplicate the top stack element
                        elemStack.add(new StackElement(peekStack(elemStack)));
                        break;
                    case ScriptOpCodes.OP_IFDUP:
                        // Duplicate top stack element if it is not zero
                        elem = peekStack(elemStack);
                        if (elem.isTrue())
                            elemStack.add(new StackElement(elem));
                        break;
                    case ScriptOpCodes.OP_DEPTH:
                        // Push the stack depth
                        elemStack.add(new StackElement(BigInteger.valueOf(elemStack.size())));
                        break;
                    case ScriptOpCodes.OP_VERIFY:
                        // Verify the top stack element
                        txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_EQUAL:
                    case ScriptOpCodes.OP_EQUALVERIFY:
                        // Push 1 (TRUE) if top two stack elements are equal, else push 0 (FALSE)
                        bytes = new byte[1];
                        elem1 = popStack(elemStack);
                        elem2 = popStack(elemStack);
                        if (elem1.equals(elem2))
                            bytes[0] = (byte)1;
                        elemStack.add(new StackElement(bytes));
                        if (opcode == ScriptOpCodes.OP_EQUAL) {
                            if (p2sh && bytes[0] == 1) {
                                // Remove TRUE from the stack so that we are left with just the remaining
                                // data elements from the input script (OP_EQUAL is the last opcode
                                // in the output script)
                                popStack(elemStack);
                            }
                        } else {
                            txValid = processVerify(elemStack);
                        }
                        break;
                    case ScriptOpCodes.OP_RIPEMD160:
                        // RIPEMD160 hash of the top stack element
                        elemStack.add(new StackElement(Utils.hash160(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_SHA1:
                        // SHA-1 hash of top stack element
                        elemStack.add(new StackElement(Utils.sha1Hash(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_SHA256:
                        // SHA-256 hash of top stack element
                        elemStack.add(new StackElement(Utils.singleDigest(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_HASH160:
                        // SHA-256 hash followed by RIPEMD160 hash of top stack element
                        elem = popStack(elemStack);
                        elemStack.add(new StackElement(Utils.sha256Hash160(elem.getBytes())));
                        // Save the deserialized script for pay-to-hash-script processing
                        if (p2sh)
                            scriptStack.add(elem.getBytes());
                        break;
                    case ScriptOpCodes.OP_HASH256:
                        // Double SHA-256 hash of top stack element
                        elemStack.add(new StackElement(Utils.doubleDigest(popStack(elemStack).getBytes())));
                        break;
                    case ScriptOpCodes.OP_CHECKSIG:
                    case ScriptOpCodes.OP_CHECKSIGVERIFY:
                        // Check single signature
                        processCheckSig(txInput, elemStack, scriptBytes, lastSeparator);
                        if (opcode == ScriptOpCodes.OP_CHECKSIGVERIFY)
                            txValid = processVerify(elemStack);
                        break;
                    case ScriptOpCodes.OP_CHECKMULTISIG:
                    case ScriptOpCodes.OP_CHECKMULTISIGVERIFY:
                        // Check multiple signatures
                        processMultiSig(txInput, elemStack, scriptBytes, lastSeparator);
                        if (opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY)
                            txValid = processVerify(elemStack);
                        break;
                    default:
                        log.error(String.format("Unsupported script opcode %s(%d)",
                                        ScriptOpCodes.getOpCodeName((byte)opcode), opcode));
                        throw new ScriptException("Unsupported script opcode");
                }
            }
            //
            // Create a stack element for a data push operation and add it to the stack
            //
            if (dataToRead >= 0) {
                if (offset+dataToRead > scriptBytes.length)
                    throw new EOFException("End-of-data while processing script");
                bytes = new byte[dataToRead];
                if (dataToRead > 0)
                    System.arraycopy(scriptBytes, offset, bytes, 0, dataToRead);
                offset += dataToRead;
                elemStack.add(new StackElement(bytes));
            }
        }
        return txValid;
    }
    
    /**
     * Returns the top element from the stack but does not remove it from the stack
     * 
     * @param       elemStack           The element stack
     * @return                          The top stack element
     * @throws      ScriptException     The stack is empty
     */
    private static StackElement peekStack(List<StackElement> elemStack) throws ScriptException {
        if (elemStack.isEmpty())
            throw new ScriptException("Stack underrun");
        return elemStack.get(elemStack.size()-1);
    }

    /**
     * Pop the top element from the stack and return it
     *
     * @param       elemStack           The element stack
     * @return                          The top stack element
     * @throws      ScriptException     The stack is empty
     */
    private static StackElement popStack(List<StackElement> elemStack) throws ScriptException {
        if (elemStack.isEmpty())
            throw new ScriptException("Stack underrun");
        return elemStack.remove(elemStack.size()-1);
    }

    /**
     * Process OP_VERIFY
     *
     * Checks the top element on the stack and removes it if it is non-zero.  The return value
     * is TRUE if the top element is non-zero and FALSE otherwise.
     * 
     * @param       elemStack           The element stack
     * @return                          TRUE if the top stack element is non-zero
     */
    private static boolean processVerify(List<StackElement> elemStack) {
        boolean txValid;
        int index = elemStack.size()-1;
        if (index < 0) {
            txValid = false;
        } else if (elemStack.get(index).isTrue()) {
            txValid = true;
            elemStack.remove(index);
        } else {
            txValid = false;
        }
        return txValid;
    }

    /**
     * Process OP_CHECKSIG
     *
     * The stack must contain the signature and the public key.  The public key is
     * used to verify the signature.  TRUE is pushed on the stack if the signature
     * is valid, otherwise FALSE is pushed on the stack.
     *
     * @param       txInput             The current transaction input
     * @param       elemStack           The element stack
     * @param       scriptBytes         The current script program
     * @param       lastSeparator       The last code separator offset or zero
     * @throws      IOException         Unable to process encoded element
     * @throws      ScriptException     Unable to verify signature
     */
    private static void processCheckSig(TransactionInput txInput, List<StackElement> elemStack, 
                                        byte[] scriptBytes, int lastSeparator) 
                                        throws IOException, ScriptException {
        byte[] bytes;
        boolean result;
        //
        // Check the signature
        //
        // Make sure the public key starts with x'02', x'03' or x'04'.  Otherwise,
        // Bouncycastle throws an illegal argument exception.  We will return FALSE
        // if we find an invalid public key.
        //
        StackElement pubKey = popStack(elemStack);
        StackElement sig = popStack(elemStack);
        bytes = pubKey.getBytes();
        if (bytes.length == 0) {
            log.warn("Null public key provided");
            result = false;
        } else if (!ECKey.isPubKeyCanonical(bytes)) {
            log.warn(String.format("Non-canonical public key\n  Key %s", Utils.bytesToHexString(bytes)));
            result = false;
        } else {
            List<StackElement> pubKeys = new ArrayList<>();
            pubKeys.add(pubKey);
            result = checkSig(txInput, sig, pubKeys, scriptBytes, lastSeparator);
        }
        //
        // Push the result on the stack
        //
        elemStack.add(new StackElement(result));
    }

    /**
     * Process OP_MULTISIG
     *
     * The stack must contain at least one signature and at least one public key.
     * Each public key is tested against each signature until a valid signature is
     * found.  All signatures must be verified but all public keys do not need to
     * be used.  A public key is removed from the list once it has been used to
     * verify a signature.
     *
     * TRUE is pushed on the stack if all signatures have been verified,
     * otherwise FALSE is pushed on the stack.
     * 
     * @param       txInput             The current transaction input
     * @param       elemStack           The element stack
     * @param       scriptBytes         The current script program
     * @param       lastSeparator       The last code separator offset or zero
     * @throws      IOException         Unable to process signature
     * @throws      ScriptException     Unable to verify signature
     */
    private static void processMultiSig(TransactionInput txInput, List<StackElement> elemStack, 
                                        byte[] scriptBytes, int lastSeparator) 
                                        throws IOException, ScriptException {
        List<StackElement> keys = new ArrayList<>(ScriptOpCodes.MAX_SIG_OPS);
        List<StackElement> sigs = new ArrayList<>(ScriptOpCodes.MAX_SIG_OPS);
        boolean isValid = true;
        StackElement elem;
        byte[] bytes;
        //
        // Get the public keys
        //
        // Some transactions are storing application data as one of the public
        // keys.  So we need to check for a valid initial byte (02, 03, 04).  
        // The garbage key will be ignored and the transaction will be valid as long 
        // as the signature is verified using one of the valid keys.
        //
        int pubKeyCount = popStack(elemStack).getBigInteger().intValue();
        if (pubKeyCount > ScriptOpCodes.MAX_SIG_OPS)
            throw new ScriptException("Too many public keys for OP_CHECKMULTISIG");
        for (int i=0; i<pubKeyCount; i++) {
            elem = popStack(elemStack);
            bytes = elem.getBytes();
            if (bytes.length == 0)
                log.warn("Null public key provided");
            else if (!ECKey.isPubKeyCanonical(bytes))
                log.warn(String.format("Non-canonical public key\n  Key %s", Utils.bytesToHexString(bytes)));
            else
                keys.add(elem);
        }
        //
        // Get the signatures
        //
        int sigCount = popStack(elemStack).getBigInteger().intValue();
        if (sigCount > ScriptOpCodes.MAX_SIG_OPS)
            throw new ScriptException("Too many signatures for OP_CHECKMULTISIG");
        for (int i=0; i<sigCount; i++)
            sigs.add(popStack(elemStack));
        //
        // Due to a bug in the reference client, an extra element is removed from the stack
        //
        popStack(elemStack);
        //
        // Verify each signature and stop if we have a verification failure
        //
        // We will stop when all signatures have been verified or there are no more
        // public keys available
        //
        for (StackElement sig : sigs) {
            if (keys.isEmpty()) {
                log.warn("Not enough keys provided for OP_CHECKMULTISIG");
                isValid = false;
                break;
            }
            isValid = checkSig(txInput, sig, keys, scriptBytes, lastSeparator);
            if (!isValid)
                break;
        }
        //
        // Push the result on the stack
        //
        elemStack.add(new StackElement(isValid));
    }

    /**
     * Checks the transaction signature
     *
     * The signature is valid if it is signed by one of the supplied public keys.
     *
     * @param       txInput             The current transaction input
     * @param       sig                 The signature to be verified
     * @param       pubKeys             The public keys to be checked
     * @param       scriptBytes         The current script program
     * @param       lastSeparator       The last code separator offset or zero
     * @return                          TRUE if the signature is valid, FALSE otherwise
     * @throw       IOException         Unable to process signature
     * @throw       ScriptException     Unable to verify signature
     */
    private static boolean checkSig(TransactionInput txInput, StackElement sig, List<StackElement> pubKeys, 
                                        byte[] scriptBytes, int lastSeparator) 
                                        throws IOException, ScriptException {
        byte[] sigBytes = sig.getBytes();
        boolean isValid = false;
        byte[] subProgram;
        //
        // Remove all occurrences of the signature from the output script and create a new program.
        //
        try (ByteArrayOutputStream outStream = new ByteArrayOutputStream(scriptBytes.length)) {
            int index = lastSeparator;
            int count = scriptBytes.length;
            while (index < count) {
                int startPos = index;
                int dataLength = 0;
                int opcode = ((int)scriptBytes[index++])&0x00ff;
                if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                    int result[] = Script.getDataLength(opcode, scriptBytes, index);
                    dataLength = result[0];
                    index = result[1];
                }
                boolean copyElement = true;
                if (dataLength == sigBytes.length) {
                    copyElement = false;
                    for (int i=0; i<dataLength; i++) {
                        if (sigBytes[i] != scriptBytes[index+i]) {
                            copyElement = true;
                            break;
                        }
                    }
                }
                if (copyElement)
                    outStream.write(scriptBytes, startPos, index-startPos+dataLength);
                index += dataLength;
            }
            subProgram = outStream.toByteArray();
        }
        //
        // The hash type is the last byte of the signature.  Remove it and create a new
        // byte array containing the DER-encoded signature.
        //
        int hashType = (int)sigBytes[sigBytes.length-1]&0x00ff;
        byte[] encodedSig = new byte[sigBytes.length-1];
        System.arraycopy(sigBytes, 0, encodedSig, 0, encodedSig.length);
        //
        // Serialize the transaction and then add the hash type to the end of the data
        //
        // The reference client has a bug for SIGHASH_SINGLE when the input index is
        // greater than or equal to the number of outputs.  In this case, it doesn't
        // detect an error and instead uses the error code as the transaction hash.
        // To handle this, we will set the serialized transaction data to null.  ECKey.verify()
        // will detect this and use the error hash when verifying the signature.
        //
        Transaction tx = txInput.getTransaction();
        byte[] txData = null;
        if ((hashType&0x7f) != ScriptOpCodes.SIGHASH_SINGLE || txInput.getIndex() < tx.getOutputs().size()) {
            try (ByteArrayOutputStream outStream = new ByteArrayOutputStream(1024)) {
                tx.serializeForSignature(txInput.getIndex(), hashType, subProgram, outStream);
                Utils.uint32ToByteStreamLE(hashType, outStream);
                txData = outStream.toByteArray();
            }
        }
        //
        // Use the public keys to verify the signature for the hashed data.  Stop as
        // soon as we have a verified signature.  The public key will be removed from
        // the list if it verifies a signature to prevent one person from signing the
        // transaction multiple times.
        //
        Iterator<StackElement> it = pubKeys.iterator();
        while (it.hasNext()) {
            StackElement pubKey = it.next();
            ECKey ecKey = new ECKey(pubKey.getBytes());
            try {
                isValid = ecKey.verifySignature(txData, encodedSig);
            } catch (ECException exc) {
                log.warn("Public key exception - discarding failing public key", exc);
                it.remove();
            }
            //
            // Remove the public key from the list if the verification is successful
            //
            if (isValid) {
                it.remove();
                break;
            }
        }
        return isValid;
    }
}
