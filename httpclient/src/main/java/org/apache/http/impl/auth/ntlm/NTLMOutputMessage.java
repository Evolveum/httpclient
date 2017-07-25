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
import org.apache.http.util.EncodingUtils;

/** NTLM output message base class. For messages that the client is sending. */
abstract class NTLMOutputMessage extends NTLMMessage
{

    /** The current output position */
    private int currentOutputPosition = 0;
    protected boolean messageEncoded = false;


    /** Get the message length */
    protected int getMessageLength()
    {
        return currentOutputPosition;
    }


    /**
     * Prepares the object to create a response of the given length.
     *
     * @param maxlength
     *            the maximum length of the response to prepare, not
     *            including the type and the signature (which this method
     *            adds).
     */
    protected void prepareResponse( final int maxlength, final int messageType )
    {
        messageContents = new byte[maxlength];
        currentOutputPosition = 0;
        addBytes( NTLMEngineImpl.SIGNATURE );
        addULong( messageType );
    }


    /**
     * Adds the given byte to the response.
     *
     * @param b
     *            the byte to add.
     */
    protected void addByte( final byte b )
    {
        messageContents[currentOutputPosition] = b;
        currentOutputPosition++;
    }


    protected int getCurrentOutputPosition()
    {
        return currentOutputPosition;
    }


    protected void skipBytes( final int size )
    {
        currentOutputPosition += size;
    }


    /**
     * Adds the given bytes to the response.
     *
     * @param bytes
     *            the bytes to add.
     */
    protected void addBytes( final byte[] bytes )
    {
        if ( bytes == null )
        {
            return;
        }
        for ( final byte b : bytes )
        {
            messageContents[currentOutputPosition] = b;
            currentOutputPosition++;
        }
    }


    /** Adds a USHORT to the response */
    protected void addUShort( final int value )
    {
        addByte( ( byte ) ( value & 0xff ) );
        addByte( ( byte ) ( value >> 8 & 0xff ) );
    }


    /** Adds a ULong to the response */
    protected void addULong( final int value )
    {
        addByte( ( byte ) ( value & 0xff ) );
        addByte( ( byte ) ( value >> 8 & 0xff ) );
        addByte( ( byte ) ( value >> 16 & 0xff ) );
        addByte( ( byte ) ( value >> 24 & 0xff ) );
    }


    /**
     * Returns the response that has been generated after shrinking the
     * array if required and base64 encodes the response.
     *
     * @return The response as above.
     */
    public String getResponse() {
        return EncodingUtils.getAsciiString( Base64.encodeBase64( getBytes() ) );
    }


    public byte[] getBytes() {
        if ( !messageEncoded )
        {
            encodeMessage();
            final byte[] resp;
            if ( messageContents.length > currentOutputPosition )
            {
                final byte[] tmp = new byte[currentOutputPosition];
                System.arraycopy( messageContents, 0, tmp, 0, currentOutputPosition );
                messageContents = tmp;
            }
        }
        return messageContents;
    }


    protected abstract void encodeMessage();
}