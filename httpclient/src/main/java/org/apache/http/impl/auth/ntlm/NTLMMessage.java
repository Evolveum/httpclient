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

/** NTLM message generation, base class */
abstract class NTLMMessage
{
    /** The current response */
    protected byte[] messageContents = null;


    /**
     * Get the length of the signature and flags, so calculations can adjust
     * offsets accordingly.
     */
    protected int getPreambleLength()
    {
        return NTLMEngineImpl.SIGNATURE.length + 4;
    }


    /** Get the message length */
    protected abstract int getMessageLength();


    /** Read a byte from a position within the message buffer */
    protected byte readByte( final int position ) throws NTLMEngineException
    {
        if ( messageContents.length < position + 1 )
        {
            throw new NTLMEngineException( "NTLM: Message too short" );
        }
        return messageContents[position];
    }


    /** Read a bunch of bytes from a position in the message buffer */
    protected void readBytes( final byte[] buffer, final int position ) throws NTLMEngineException
    {
        if ( messageContents.length < position + buffer.length )
        {
            throw new NTLMEngineException( "NTLM: Message too short" );
        }
        System.arraycopy( messageContents, position, buffer, 0, buffer.length );
    }


    /** Read a ushort from a position within the message buffer */
    protected int readUShort( final int position ) throws NTLMEngineException
    {
        return NTLMEngineImpl.readUShort( messageContents, position );
    }


    /** Read a ulong from a position within the message buffer */
    protected int readULong( final int position ) throws NTLMEngineException
    {
        return NTLMEngineImpl.readULong( messageContents, position );
    }


    /** Read a security buffer from a position within the message buffer */
    protected byte[] readSecurityBuffer( final int position ) throws NTLMEngineException
    {
        return NTLMEngineImpl.readSecurityBuffer( messageContents, position );
    }


    public abstract byte[] getBytes();
}