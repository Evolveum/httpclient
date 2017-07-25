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

import org.apache.commons.codec.binary.Base64;

/** NTLM input message base class. For messages that the client is receiving. */
abstract class NTLMInputMessage extends NTLMMessage
{

    /** Constructor to use when message base64-encoded contents are known.*/
    NTLMInputMessage( final String messageBody, final int expectedType ) throws NTLMEngineException
    {
        this( Base64.decodeBase64( messageBody.getBytes( NTLMEngineImpl.DEFAULT_CHARSET ) ), expectedType );
    }


    /** Constructor to use when message binary contents are known */
    NTLMInputMessage( final byte[] messageBytes, final int expectedType ) throws NTLMEngineException
    {
        messageContents = messageBytes;
        // Look for NTLM message
        if ( messageContents.length < NTLMEngineImpl.SIGNATURE.length )
        {
            throw new NTLMEngineException( "NTLM message decoding error - packet too short" );
        }
        int i = 0;
        while ( i < NTLMEngineImpl.SIGNATURE.length )
        {
            if ( messageContents[i] != NTLMEngineImpl.SIGNATURE[i] )
            {
                throw new NTLMEngineException(
                    "NTLM message expected - instead got unrecognized bytes" );
            }
            i++;
        }

        // Check to be sure there's a type 2 message indicator next
        final int type = readULong( NTLMEngineImpl.SIGNATURE.length );
        if ( type != expectedType )
        {
            throw new NTLMEngineException( "NTLM type " + Integer.toString( expectedType )
                + " message expected - instead got type " + Integer.toString( type ) );
        }
    }


    /** Get the message length */
    protected int getMessageLength()
    {
        return messageContents.length;
    }


    public byte[] getBytes()
    {
        return messageContents;
    }

}