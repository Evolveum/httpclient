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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.impl.auth.DebugUtil;
import org.apache.http.impl.auth.ntlm.NTLMEngineImpl.HMACMD5;
import org.apache.http.impl.auth.ntlm.NTLMEngineImpl.Mode;

public class NTLMHandle
{
    final private byte[] exportedSessionKey;
    private byte[] signingKey;
    private byte[] sealingKey;
    private Cipher rc4;
    final Mode mode;
    final private boolean isConnection;
    int sequenceNumber = 0;


    NTLMHandle( final byte[] exportedSessionKey, final Mode mode, final boolean isSonnection )
    {
        this.exportedSessionKey = exportedSessionKey;
        this.isConnection = isSonnection;
        this.mode = mode;
    }


    public byte[] getSigningKey()
    {
        return signingKey;
    }


    public byte[] getSealingKey()
    {
        return sealingKey;
    }


    void init() throws NTLMEngineException
    {
        try
        {
            final MessageDigest signMd5 = MessageDigest.getInstance( "MD5" );
            final MessageDigest sealMd5 = MessageDigest.getInstance( "MD5" );
            signMd5.update( exportedSessionKey );
            sealMd5.update( exportedSessionKey );
            if ( mode == Mode.CLIENT )
            {
                signMd5.update( NTLMEngineImpl.SIGN_MAGIC_CLIENT );
                sealMd5.update( NTLMEngineImpl.SEAL_MAGIC_CLIENT );
            }
            else
            {
                signMd5.update( NTLMEngineImpl.SIGN_MAGIC_SERVER );
                sealMd5.update( NTLMEngineImpl.SEAL_MAGIC_SERVER );
            }
            signingKey = signMd5.digest();
            sealingKey = sealMd5.digest();
            if (NTLMEngineImpl.develTrace)
            {
                NTLMEngineImpl.log.trace( "signingKey("+mode+"): " + DebugUtil.dump( signingKey ) );
                NTLMEngineImpl.log.trace( "sealingKey("+mode+"): " + DebugUtil.dump( sealingKey ) );
            }
        }
        catch ( final Exception e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
        rc4 = initCipher();
    }


    private Cipher initCipher() throws NTLMEngineException
    {
        Cipher cipher;
        try
        {
            cipher = Cipher.getInstance( "RC4" );
            if ( mode == Mode.CLIENT )
            {
                cipher.init( Cipher.ENCRYPT_MODE, new SecretKeySpec( sealingKey, "RC4" ) );
            }
            else
            {
                cipher.init( Cipher.DECRYPT_MODE, new SecretKeySpec( sealingKey, "RC4" ) );
            }
        }
        catch ( Exception e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
        return cipher;
    }


    private void advanceMessageSequence() throws NTLMEngineException
    {
        if ( !isConnection )
        {
            MessageDigest sealMd5;
            try
            {
                sealMd5 = MessageDigest.getInstance( "MD5" );
            }
            catch ( NoSuchAlgorithmException e )
            {
                throw new NTLMEngineException( e.getMessage(), e );
            }
            sealMd5.update( sealingKey );
            final byte[] seqNumBytes = new byte[4];
            NTLMEngineImpl.writeULong( seqNumBytes, sequenceNumber, 0 );
            sealMd5.update( seqNumBytes );
            sealingKey = sealMd5.digest();
            initCipher();
        }
        sequenceNumber++;
    }


    private byte[] encrypt( final byte[] data ) throws NTLMEngineException
    {
        return rc4.update( data );
    }


    private byte[] decrypt( final byte[] data ) throws NTLMEngineException
    {
        return rc4.update( data );
    }


    private byte[] computeSignature( final byte[] message ) throws NTLMEngineException
    {
        final byte[] sig = new byte[16];

        // version
        sig[0] = 0x01;
        sig[1] = 0x00;
        sig[2] = 0x00;
        sig[3] = 0x00;

        // HMAC (first 8 bytes)
        final HMACMD5 hmacMD5 = new HMACMD5( signingKey );
        hmacMD5.update( encodeLong( sequenceNumber ) );
        hmacMD5.update( message );
        final byte[] hmac = hmacMD5.getOutput();
        final byte[] trimmedHmac = new byte[8];
        System.arraycopy( hmac, 0, trimmedHmac, 0, 8 );
        final byte[] encryptedHmac = encrypt( trimmedHmac );
        System.arraycopy( encryptedHmac, 0, sig, 4, 8 );

        // sequence number
        encodeLong( sig, 12, sequenceNumber );

        return sig;
    }


    private boolean validateSignature( final byte[] signature, final byte message[] ) throws NTLMEngineException
    {
        final byte[] computedSignature = computeSignature( message );
        //            log.info( "SSSSS validateSignature("+seqNumber+")\n"
        //                + "  received: " + DebugUtil.dump( signature ) + "\n"
        //                + "  computed: " + DebugUtil.dump( computedSignature ) );
        return Arrays.equals( signature, computedSignature );
    }


    public byte[] signAndEcryptMessage( final byte[] cleartextMessage ) throws NTLMEngineException
    {
        final byte[] encryptedMessage = encrypt( cleartextMessage );
        final byte[] signature = computeSignature( cleartextMessage );
        final byte[] outMessage = new byte[signature.length + encryptedMessage.length];
        System.arraycopy( signature, 0, outMessage, 0, signature.length );
        System.arraycopy( encryptedMessage, 0, outMessage, signature.length, encryptedMessage.length );
        advanceMessageSequence();
        return outMessage;
    }


    public byte[] decryptAndVerifySignedMessage( final byte[] inMessage ) throws NTLMEngineException
    {
        final byte[] signature = new byte[16];
        System.arraycopy( inMessage, 0, signature, 0, signature.length );
        final byte[] encryptedMessage = new byte[inMessage.length - 16];
        System.arraycopy( inMessage, 16, encryptedMessage, 0, encryptedMessage.length );
        final byte[] cleartextMessage = decrypt( encryptedMessage );
        if ( !validateSignature( signature, cleartextMessage ) )
        {
            throw new NTLMEngineException( "Wrong signature" );
        }
        advanceMessageSequence();
        return cleartextMessage;
    }


    private byte[] encodeLong( final int value )
    {
        final byte[] enc = new byte[4];
        encodeLong( enc, 0, value );
        return enc;
    }


    private void encodeLong( final byte[] buf, final int offset, final int value )
    {
        buf[offset + 0] = ( byte ) ( value & 0xff );
        buf[offset + 1] = ( byte ) ( value >> 8 & 0xff );
        buf[offset + 2] = ( byte ) ( value >> 16 & 0xff );
        buf[offset + 3] = ( byte ) ( value >> 24 & 0xff );
    }
}