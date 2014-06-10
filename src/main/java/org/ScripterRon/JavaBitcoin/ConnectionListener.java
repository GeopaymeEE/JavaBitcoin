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

import org.ScripterRon.BitcoinCore.Peer;

/**
 * A connection listener receives notification when a connection starts or ends
 */
public interface ConnectionListener {

    /**
     * Notifies when a connection is started
     *
     * @param       peer            Remote peer
     * @param       count           Connection count
     */
    public void connectionStarted(Peer peer, int count);

    /**
     * Notifies when a connection is terminated
     *
     * @param       peer            Remote peer
     * @param       count           Connection count
     */
    public void connectionEnded(Peer peer, int count);
}
