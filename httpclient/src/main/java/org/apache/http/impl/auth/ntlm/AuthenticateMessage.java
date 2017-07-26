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

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import org.apache.http.impl.auth.DebugUtil;
import org.apache.http.impl.auth.ntlm.NTLMEngineImpl.CipherGen;
import org.apache.http.impl.auth.ntlm.NTLMEngineImpl.HMACMD5;

/** Authenticate (Type 3) message class */
public class AuthenticateMessage extends NTLMOutputMessage
{
    // Response flags from the type2 message
    protected int type2Flags;

    protected byte[] domainBytes;
    protected byte[] hostBytes;
    protected byte[] userBytes;

    // LmChallengeResponse field (section 2.2.1.3)
    protected byte[] lmChallengeResponse;

    // NtChallengeResponse field (section 2.2.1.3)
    protected byte[] ntChallengeResponse;

    protected byte[] encryptedRandomSessionKey;
    protected byte[] exportedSessionKey;

    int micPosition = -1;
    protected boolean computeMic = false;

    // TODO: refactor. No good parsing the messge in constructor.
    AuthenticateMessage( final String domain, final String host, final String user, final String password,
        final byte[] nonce,
        final int type2Flags, final String target, final byte[] targetInformation,
        final X509Certificate peerServerCertificate )
        throws NTLMEngineException {
        // Save the flags
        this.type2Flags = type2Flags;

        // Strip off domain name from the host!
        final String unqualifiedHost = NTLMEngineImpl.convertHost( host );
        // Use only the base domain name!
        final String unqualifiedDomain = NTLMEngineImpl.convertDomain( domain );

        byte[] responseTargetInformation = targetInformation;
        if ( peerServerCertificate != null )
        {
            responseTargetInformation = addGssMicAvsToTargetInfo( targetInformation, peerServerCertificate );
        }

        // Create a cipher generator class.  Use domain BEFORE it gets modified!
        final CipherGen gen = new CipherGen( unqualifiedDomain, user, password, nonce, target,
            responseTargetInformation );

        // Use the new code to calculate the responses, including v2 if that
        // seems warranted.
        byte[] sessionBaseKey;
        try
        {
            if ( ( ( type2Flags & NTLMEngineImpl.FLAG_TARGETINFO_PRESENT ) != 0 ) &&
                targetInformation != null && target != null ) {

                // NTLMv2
                if (NTLMEngineImpl.develTrace) {
                    NTLMEngineImpl.log.trace( "Generating NTLMv2 responses" );
                }
                ntChallengeResponse = gen.getNTLMv2Response();

                final byte[] targetInfoTimestamp = getTargetInfoTimestamp(targetInformation);
                if (NTLMEngineImpl.develTrace) {
                    NTLMEngineImpl.log.trace("targetInfoTimestamp: " + DebugUtil.dump( targetInfoTimestamp ));
                }
                if (targetInfoTimestamp == null) {
                    lmChallengeResponse = gen.getLMv2Response();
                } else {
                    // [MS-NLMP] section 3.1.5.12
                    // Client Received a CHALLENGE_MESSAGE from the Server
                    // If NTLMv2 authentication is used and the CHALLENGE_MESSAGE TargetInfo field has an MsvAvTimestamp present,
                    // the client SHOULD NOT send the LmChallengeResponse and SHOULD send Z(24) instead.
                    lmChallengeResponse = new byte[24];
                }

                if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_LAN_MANAGER_KEY ) != 0 )
                {
                    sessionBaseKey = gen.getLanManagerSessionKey();
                }
                else
                {
                    sessionBaseKey = gen.getNTLMv2SessionBaseKey();
                }

            } else {

                // NTLMv1
                if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_NTLM2_SESSION ) != 0 ) {
                    if (NTLMEngineImpl.develTrace) {
                        NTLMEngineImpl.log.trace( "Generating NTLMv1 responses with NTLMv2 session" );
                    }
                    // NTLM2 session stuff is requested
                    ntChallengeResponse = gen.getNTLM2SessionResponse();
                    lmChallengeResponse = gen.getLM2SessionResponse();
                    if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_LAN_MANAGER_KEY ) != 0 ) {
                        sessionBaseKey = gen.getLanManagerSessionKey();
                    } else {
                        sessionBaseKey = gen.getNTLM2SessionResponseUserSessionKey();
                    }

                } else {

                    if (NTLMEngineImpl.develTrace) {
                        NTLMEngineImpl.log.trace( "Generating NTLMv1 responses" );
                    }
                    ntChallengeResponse = gen.getNTLMResponse();
                    lmChallengeResponse = gen.getLMResponse();
                    if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_LAN_MANAGER_KEY ) != 0 ) {
                        sessionBaseKey = gen.getLanManagerSessionKey();
                    } else {
                        sessionBaseKey = gen.getNTLMUserSessionKey();
                    }
                }
            }
        } catch ( final NTLMEngineException e ) {
            // This likely means we couldn't find the MD4 hash algorithm -
            // fail back to just using LM
            if (NTLMEngineImpl.develTrace) {
                NTLMEngineImpl.log.trace( "Got exceptions, failback to LM algorithms", e );
            }
            ntChallengeResponse = new byte[0];
            lmChallengeResponse = gen.getLMResponse();
            if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_LAN_MANAGER_KEY ) != 0 ) {
                sessionBaseKey = gen.getLanManagerSessionKey();
            } else {
                sessionBaseKey = gen.getLMUserSessionKey();
            }
        }
        if (NTLMEngineImpl.develTrace) {
            NTLMEngineImpl.log.trace( "LmChallengeResponse:\n" + DebugUtil.dump( lmChallengeResponse ) );
            NTLMEngineImpl.log.trace( "NtChallengeResponse:\n" + DebugUtil.dump( ntChallengeResponse ) );
            NTLMEngineImpl.log.trace( "sessionBaseKey:" + DebugUtil.dump( sessionBaseKey ) );
        }

        // Strictly speaking we should transform sessionBaseKey to keyExchenageKey here.
        // But in the two specific usecases implemented by this code that is not necessary.
        // As the time is limited we simply don't implement that particular transformation code.

        if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_SIGN ) != 0 ) {
            if ( ( type2Flags & NTLMEngineImpl.FLAG_REQUEST_EXPLICIT_KEY_EXCH ) != 0 ) {
                exportedSessionKey = gen.getExportedSessionKey();
                encryptedRandomSessionKey = NTLMEngineImpl.RC4( exportedSessionKey, sessionBaseKey );
            } else {
                encryptedRandomSessionKey = sessionBaseKey;
                exportedSessionKey = encryptedRandomSessionKey;
            }

            if (NTLMEngineImpl.develTrace) {
                NTLMEngineImpl.log.trace( "exportedSessionKey:\n" + DebugUtil.dump( exportedSessionKey ) );
                NTLMEngineImpl.log.trace( "encryptedRandomSessionKey:\n" + DebugUtil.dump( encryptedRandomSessionKey ) );
            }
        } else {
            encryptedRandomSessionKey = null;
        }
        final Charset charset = NTLMEngineImpl.getCharset( type2Flags );
        hostBytes = unqualifiedHost != null ? unqualifiedHost.getBytes( charset ) : null;
        domainBytes = unqualifiedDomain != null ? unqualifiedDomain
            .toUpperCase( Locale.ROOT ).getBytes( charset ) : null;
        userBytes = user.getBytes( charset );
    }


    private byte[] getTargetInfoTimestamp( final byte[] targetInformation ) throws NTLMEngineException {
        if (targetInformation == null) {
            return null;
        }
        return getValueOfAVPair(targetInformation, NTLMEngineImpl.MSV_AV_TIMESTAMP);
    }


    private byte[] getValueOfAVPair( final byte[] buffer, final int attributeId ) throws NTLMEngineException {
        int i = 0;
        while (i < buffer.length) {
            final int avId = NTLMEngineImpl.readUShort( buffer, i );
            final int avLen = NTLMEngineImpl.readUShort( buffer, i + 2 );
            if (avId == attributeId) {
                final byte[] val = new byte[avLen];
                System.arraycopy( buffer, i + 4, val, 0, avLen );
                return val;
            }
            i = i + 4 + avLen;
        }
        return null;
    }


    public byte[] getEncryptedRandomSessionKey() {
        return encryptedRandomSessionKey;
    }


    public byte[] getExportedSessionKey() {
        return exportedSessionKey;
    }


    /** Assemble the response */
    @Override
    protected void encodeMessage() {
        final int ntRespLen = ntChallengeResponse.length;
        final int lmRespLen = lmChallengeResponse.length;

        final int domainLen = domainBytes != null ? domainBytes.length : 0;
        final int hostLen = hostBytes != null ? hostBytes.length : 0;
        final int userLen = userBytes.length;
        final int sessionKeyLen;
        if ( encryptedRandomSessionKey != null ) {
            sessionKeyLen = encryptedRandomSessionKey.length;
        } else {
            sessionKeyLen = 0;
        }

     // Calculate the layout within the packet
        final int domainOffset = 72 + // allocate space for the version
            ( computeMic ? 16 : 0 ); // and MIC
        final int userOffset = domainOffset + domainLen;
        final int hostOffset = userOffset + userLen;
        final int lmRespOffset = hostOffset + hostLen;
        final int ntRespOffset = lmRespOffset + lmRespLen;
        final int sessionKeyOffset = ntRespOffset + ntRespLen;
        final int finalLength = sessionKeyOffset + sessionKeyLen;

        // Start the response. Length includes signature and type
        prepareResponse( finalLength, 3 );

        // LM Resp Length (twice)
        addUShort( lmRespLen );
        addUShort( lmRespLen );

        // LM Resp Offset
        addULong( lmRespOffset );

        // NT Resp Length (twice)
        addUShort( ntRespLen );
        addUShort( ntRespLen );

        // NT Resp Offset
        addULong( ntRespOffset );

        // Domain length (twice)
        addUShort( domainLen );
        addUShort( domainLen );

        // Domain offset.
        addULong( domainOffset );

        // User Length (twice)
        addUShort( userLen );
        addUShort( userLen );

        // User offset
        addULong( userOffset );

        // Host length (twice)
        addUShort( hostLen );
        addUShort( hostLen );

        // Host offset
        addULong( hostOffset );

        // Session key length (twice)
        addUShort( sessionKeyLen );
        addUShort( sessionKeyLen );

        // Session key offset
        addULong( sessionKeyOffset );

        // Flags.
        addULong(
            type2Flags
        );

        // Product Version
        addUShort( 0x0106 );
        // Build
        addUShort( 0x1db1 );
        // reserved
        addUShort( 0x0000 );
        // reserved + NTLM revision
        addUShort( 0x0f00 );

        if ( computeMic ) {
            micPosition = getCurrentOutputPosition();
            skipBytes( 16 );
        }

        // Add the actual data
        addBytes( domainBytes );
        addBytes( userBytes );
        addBytes( hostBytes );
        addBytes( lmChallengeResponse );
        addBytes( ntChallengeResponse );
        if ( encryptedRandomSessionKey != null ) {
            addBytes( encryptedRandomSessionKey );
        }
    }


    /**
     * Computation of message integrity code (MIC) as specified in [MS-NLMP] section 3.2.5.1.2.
     * The MIC is computed from all the messages in the exchange. Therefore it can be added to the
     * last message only after it is encoded.
     */
    void addMic( final byte[] negotiateMessageBytes, final byte[] challengeMessageBytes ) throws NTLMEngineException
    {
        if ( computeMic )
        {
            if ( micPosition == -1 )
            {
                encodeMessage();
                messageEncoded = true;
            }
            if ( exportedSessionKey == null )
            {
                throw new NTLMEngineException( "Cannot add MIC: no exported session key" );
            }
            final HMACMD5 hmacMD5 = new HMACMD5( exportedSessionKey );
            hmacMD5.update( negotiateMessageBytes );
            // TODO
//            hmacMD5.update( DebugUtil.fromHex( "4e 54 4c 4d 53 53 50 00 01 00 00 00 32 90 88 e2 03 00 03 00 28 00 00 00 00 00 00 00 2b 00 00 00 06 01 b1 1d 00 00 00 0f 57 49 4e"));
            hmacMD5.update( challengeMessageBytes );
            hmacMD5.update( messageContents );
            final byte[] mic = hmacMD5.getOutput();
            System.arraycopy( mic, 0, messageContents, micPosition, mic.length );
            if (NTLMEngineImpl.develTrace) {
                NTLMEngineImpl.log.trace( "mic:\n" + DebugUtil.dump( mic ) );
            }
        }
    }


    /**
     * Add GSS channel binding hash and MIC flag to the targetInfo.
     * Looks like this is needed if we want to use exported session key for GSS wrapping.
     */
    private byte[] addGssMicAvsToTargetInfo( final byte[] originalTargetInfo,
        final X509Certificate peerServerCertificate ) throws NTLMEngineException
    {
        final byte[] newTargetInfo = new byte[originalTargetInfo.length + 8 + 20];
        final int appendLength = originalTargetInfo.length - 4; // last tag is MSV_AV_EOL, do not copy that
        System.arraycopy( originalTargetInfo, 0, newTargetInfo, 0, appendLength );
        NTLMEngineImpl.writeUShort( newTargetInfo, NTLMEngineImpl.MSV_AV_FLAGS, appendLength );
        NTLMEngineImpl.writeUShort( newTargetInfo, 4, appendLength + 2 );
        NTLMEngineImpl.writeULong( newTargetInfo, NTLMEngineImpl.MSV_AV_FLAGS_MIC, appendLength + 4 );
        computeMic = true;
        NTLMEngineImpl.writeUShort( newTargetInfo, NTLMEngineImpl.MSV_AV_CHANNEL_BINDINGS, appendLength + 8 );
        NTLMEngineImpl.writeUShort( newTargetInfo, 16, appendLength + 10 );

        byte[] channelBindingsHash;
        try
        {
            final byte[] certBytes = peerServerCertificate.getEncoded();
            final MessageDigest sha256 = MessageDigest.getInstance( "SHA-256" );
            final byte[] certHashBytes = sha256.digest( certBytes );
            final byte[] channelBindingStruct = new byte[16 + 4 + NTLMEngineImpl.MAGIC_TLS_SERVER_ENDPOINT.length
                + certHashBytes.length];
            NTLMEngineImpl.writeULong( channelBindingStruct, 0x00000035, 16 );
            System.arraycopy( NTLMEngineImpl.MAGIC_TLS_SERVER_ENDPOINT, 0, channelBindingStruct, 20,
                NTLMEngineImpl.MAGIC_TLS_SERVER_ENDPOINT.length );
            System.arraycopy( certHashBytes, 0, channelBindingStruct, 20 + NTLMEngineImpl.MAGIC_TLS_SERVER_ENDPOINT.length,
                certHashBytes.length );
            final MessageDigest md5 = MessageDigest.getInstance( "MD5" );
            channelBindingsHash = md5.digest( channelBindingStruct );
        }
        catch ( CertificateEncodingException e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }

        System.arraycopy( channelBindingsHash, 0, newTargetInfo, appendLength + 12, 16 );
        return newTargetInfo;
    }


    public String debugDump()
    {
        final StringBuilder sb = new StringBuilder( "AuthenticationMessage\n" );
        sb.append( "  flags:\n    " ).append( NTLMEngineImpl.dumpFlags( type2Flags ) ).append( "\n" );
        sb.append( "  domainBytes:\n    " ).append( DebugUtil.dump( domainBytes ) ).append( "\n" );
        sb.append( "  hostBytes:\n    " ).append( DebugUtil.dump( hostBytes ) ).append( "\n" );
        sb.append( "  userBytes:\n    " ).append( DebugUtil.dump( userBytes ) ).append( "\n" );
        sb.append( "  lmResp:\n    " ).append( DebugUtil.dump( lmChallengeResponse ) ).append( "\n" );
        sb.append( "  ntResp:\n    " ).append( DebugUtil.dump( ntChallengeResponse ) ).append( "\n" );
        sb.append( "  encryptedRandomSessionKey:\n    " ).append( DebugUtil.dump( encryptedRandomSessionKey ) )
            .append( "\n" );
        sb.append( "  exportedSessionKey:\n    " ).append( DebugUtil.dump( exportedSessionKey ) );
        return sb.toString();
    }

}