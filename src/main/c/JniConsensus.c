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

/**
 * Bitcoin-Core consensus library interface
 */
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include "bitcoinconsensus.h"
#include "org_ScripterRon_JavaBitcoin_BitcoinConsensus.h"

/**
 * Return the consensus library version
 *
 * @return                      Library version
 */
JNIEXPORT jint JNICALL Java_org_ScripterRon_JavaBitcoin_BitcoinConsensus_JniGetVersion(
                JNIEnv *envp, jclass this) {
    return bitcoinconsensus_version();
}

/**
 * Verify a transaction script
 *
 * @param       txBytes         Transaction bytes
 * @param       txIndex         Transaction input index
 * @param       scriptBytes     Output script bytes
 * @return                      Result
 *                                   0=Verification successful
 *                                  -1=Verification failed
 *                                  -2=JNI error occurred
 *                                  >0=Bitcoin consensus error code
*/
JNIEXPORT jint JNICALL Java_org_ScripterRon_JavaBitcoin_BitcoinConsensus_JniVerifyScript(
                JNIEnv *envp, jclass this,
                jobjectArray jniTxBytes, jint txIndex,
                jobjectArray jniScriptBytes) {
    //
    // Get the transaction bytes
    //
    jsize txLength = (*envp)->GetArrayLength(envp, jniTxBytes);
    jbyte *txBytes = (*envp)->GetByteArrayElements(envp, jniTxBytes, NULL);
    if (txBytes == NULL) {
        printf("Unable to get transaction bytes\n");
        return -2;
    }
    //
    // Get the script bytes
    //
    jsize scriptLength = (*envp)->GetArrayLength(envp, jniScriptBytes);
    jbyte *scriptBytes = (*envp)->GetByteArrayElements(envp, jniScriptBytes, NULL);
    if (scriptBytes == NULL) {
        printf("Unable to get script bytes\n");
        return -2;
    }
    //
    // Verify the script
    //
    bitcoinconsensus_error errcode = bitcoinconsensus_ERR_OK;
    int result = bitcoinconsensus_verify_script(
                (unsigned char *)scriptBytes, (unsigned int)scriptLength,
                (unsigned char *)txBytes,     (unsigned int)txLength,
                (unsigned int)txIndex,
                bitcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH | bitcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG,
                &errcode);
    if (errcode != bitcoinconsensus_ERR_OK)
        result = errcode;           // Error occurred
    else if (result == 1)
        result = 0;                 // Verification successful
    else
        result = -1;                // Verification failed
    //
    // Release the input parameters
    //
    (*envp)->ReleaseByteArrayElements(envp, jniTxBytes, txBytes, 0);
    (*envp)->ReleaseByteArrayElements(envp, jniScriptBytes, scriptBytes, 0);
    return result;
}
