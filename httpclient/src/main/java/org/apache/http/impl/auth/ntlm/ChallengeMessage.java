/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package org.apache.http.impl.auth.ntlm;

import org.apache.http.impl.auth.DebugUtil;

/** Challenge (Type 2) message class */
public class ChallengeMessage extends NTLMInputMessage
{
    protected byte[] challenge;
    protected String target;
    protected byte[] targetInfo;
    protected int flags;


    ChallengeMessage( final String message ) throws NTLMEngineException
    {
        super( message, 2 );
        init();
    }


    ChallengeMessage( final byte[] message ) throws NTLMEngineException
    {
        super( message, 2 );
        init();
    }


    private void init() throws NTLMEngineException
    {

        // Type 2 message is laid out as follows:
        // First 8 bytes: NTLMSSP[0]
        // Next 4 bytes: Ulong, value 2
        // Next 8 bytes, starting at offset 12: target field (2 ushort lengths, 1 ulong offset)
        // Next 4 bytes, starting at offset 20: Flags, e.g. 0x22890235
        // Next 8 bytes, starting at offset 24: Challenge
        // Next 8 bytes, starting at offset 32: ??? (8 bytes of zeros)
        // Next 8 bytes, starting at offset 40: targetinfo field (2 ushort lengths, 1 ulong offset)
        // Next 2 bytes, major/minor version number (e.g. 0x05 0x02)
        // Next 8 bytes, build number
        // Next 2 bytes, protocol version number (e.g. 0x00 0x0f)
        // Next, various text fields, and a ushort of value 0 at the end

        // Parse out the rest of the info we need from the message
        // The nonce is the 8 bytes starting from the byte in position 24.
        challenge = new byte[8];
        readBytes( challenge, 24 );

        flags = readULong( 20 );

        // Do the target!
        target = null;
        // The TARGET_DESIRED flag is said to not have understood semantics
        // in Type2 messages, so use the length of the packet to decide
        // how to proceed instead
        if ( getMessageLength() >= 12 + 8 )
        {
            final byte[] bytes = readSecurityBuffer( 12 );
            if ( bytes.length != 0 )
            {
                target = new String( bytes, NTLMEngineImpl.getCharset( flags ) );
            }
        }

        // Do the target info!
        targetInfo = null;
        // TARGET_DESIRED flag cannot be relied on, so use packet length
        if ( getMessageLength() >= 40 + 8 )
        {
            final byte[] bytes = readSecurityBuffer( 40 );
            if ( bytes.length != 0 )
            {
                targetInfo = bytes;
            }
        }
    }


    /** Retrieve the challenge */
    byte[] getChallenge()
    {
        return challenge;
    }


    /** Retrieve the target */
    String getTarget()
    {
        return target;
    }


    /** Retrieve the target info */
    byte[] getTargetInfo()
    {
        return targetInfo;
    }


    /** Retrieve the response flags */
    int getFlags()
    {
        return flags;
    }


    public String debugDump()
    {
        final StringBuilder sb = new StringBuilder( "Type2Message\n" );
        sb.append( "  flags:\n    " ).append( NTLMEngineImpl.dumpFlags( flags ) ).append( "\n" );
        sb.append( "  challenge:\n    " ).append( DebugUtil.dump( challenge ) ).append( "\n" );
        sb.append( "  target:\n    " ).append( target ).append( "\n" );
        sb.append( "  targetInfo:\n    " ).append( DebugUtil.dump( targetInfo ) );
        return sb.toString();
    }

}