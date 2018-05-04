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
import java.security.Key;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Consts;
import org.apache.http.auth.NTCredentials;
import org.apache.http.impl.auth.DebugUtil;
import org.apache.http.impl.auth.DerUtil;
import org.apache.http.util.CharsetUtils;


/**
 * <p>
 * Provides an implementation for NTLMv1, NTLMv2, and NTLM2 Session forms of the NTLM
 * authentication protocol. The implementation is based on the [MS-NLMP] specification.
 * The implementation provides partial support for message integrity (signing) and
 * confidentiality (sealing). However this is not full GSS API implementation yet.
 * </p>
 * <p>
 * The NTLM Engine is stateful. It remembers the messages that were sent and received
 * during the protocol exchange. This is needed for computation of message integrity
 * code (MIC) that is computed from all protocol messages.
 * </p>
 * <p>
 * Implementation notes: this is an implementation which is loosely based on older
 * and very limited NTLM implementation. The old implementation was obviously NOT
 * based on Microsoft specifications - or at least it have not used the terminology
 * used in the specification. This new implementation is based on the [MS-NLMP]
 * specification and an attempt was made to align the terminology with the specification.
 * This was done with some success. But old names remain at places. I have decided to
 * favor compatibility with previous implementation over reworking everything.
 * That is also the reason that the NTLMEngine interface is unchanged.
 * The extension of this implementation was mostly motivated by the needs of
 * CredSSP protocol. CredSSP needs NTLM key exchange and message integrity/confidentiality.
 * This class is using a lot of inner classes. That is how the original implementation
 * looked like. Maybe it should be separated to ordinary classes in the future.
 * The connection-less mode of operation is only partially implemented and not really tested.
 * </p>
 * <p>
 * Based on [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol (Revision 28.0, 7/4/2016)
 * https://msdn.microsoft.com/en-us/library/cc236621.aspx
 * </p>
 *
 * @since 4.1
 */
public class NTLMEngineImpl implements NTLMEngine
{

    /** Unicode encoding */
    private static final Charset UNICODE_LITTLE_UNMARKED = CharsetUtils.lookup( "UnicodeLittleUnmarked" );
    /** Character encoding */
    static final Charset DEFAULT_CHARSET = Consts.ASCII;

    // Flags we use; descriptions according to:
    // http://davenport.sourceforge.net/ntlm.html
    // and
    // http://msdn.microsoft.com/en-us/library/cc236650%28v=prot.20%29.aspx
    // [MS-NLMP] section 2.2.2.5
    public static final int FLAG_REQUEST_UNICODE_ENCODING = 0x00000001; // Unicode string encoding requested
    public static final int FLAG_REQUEST_OEM_ENCODING = 0x00000002; // OEM codepage sstring encoding requested
    public static final int FLAG_REQUEST_TARGET = 0x00000004; // Requests target field
    public static final int FLAG_REQUEST_SIGN = 0x00000010; // Requests all messages have a signature attached, in NEGOTIATE message.
    public static final int FLAG_REQUEST_SEAL = 0x00000020; // Request key exchange for message confidentiality in NEGOTIATE message.  MUST be used in conjunction with 56BIT.
    public static final int FLAG_REQUEST_LAN_MANAGER_KEY = 0x00000080; // Request Lan Manager key instead of user session key
    public static final int FLAG_REQUEST_NTLMv1 = 0x00000200; // Request NTLMv1 security.  MUST be set in NEGOTIATE and CHALLENGE both
    public static final int FLAG_DOMAIN_PRESENT = 0x00001000; // Domain is present in message
    public static final int FLAG_WORKSTATION_PRESENT = 0x00002000; // Workstation is present in message
    public static final int FLAG_REQUEST_ALWAYS_SIGN = 0x00008000; // Requests a signature block on all messages.  Overridden by REQUEST_SIGN and REQUEST_SEAL.
    public static final int FLAG_REQUEST_NTLM2_SESSION = 0x00080000; // From server in challenge, requesting NTLM2 session security
    public static final int FLAG_REQUEST_VERSION = 0x02000000; // Request protocol version
    public static final int FLAG_TARGETINFO_PRESENT = 0x00800000; // From server in challenge message, indicating targetinfo is present
    public static final int FLAG_REQUEST_128BIT_KEY_EXCH = 0x20000000; // Request explicit 128-bit key exchange
    public static final int FLAG_REQUEST_EXPLICIT_KEY_EXCH = 0x40000000; // Request explicit key exchange
    public static final int FLAG_REQUEST_56BIT_ENCRYPTION = 0x80000000; // Must be used in conjunction with SEAL

    // Attribute-value identifiers (AvId)
    // according to [MS-NLMP] section 2.2.2.1
    public static final int MSV_AV_EOL = 0x0000; // Indicates that this is the last AV_PAIR in the list.
    public static final int MSV_AV_NB_COMPUTER_NAME = 0x0001; // The server's NetBIOS computer name.
    public static final int MSV_AV_NB_DOMAIN_NAME = 0x0002; // The server's NetBIOS domain name.
    public static final int MSV_AV_DNS_COMPUTER_NAME = 0x0003; // The fully qualified domain name (FQDN) of the computer.
    public static final int MSV_AV_DNS_DOMAIN_NAME = 0x0004; // The FQDN of the domain.
    public static final int MSV_AV_DNS_TREE_NAME = 0x0005; // The FQDN of the forest.
    public static final int MSV_AV_FLAGS = 0x0006; // A 32-bit value indicating server or client configuration.
    public static final int MSV_AV_TIMESTAMP = 0x0007; // server local time
    public static final int MSV_AV_SINGLE_HOST = 0x0008; // A Single_Host_Data structure.
    public static final int MSV_AV_TARGET_NAME = 0x0009; // The SPN of the target server.
    public static final int MSV_AV_CHANNEL_BINDINGS = 0x000A; // A channel bindings hash.

    public static final int MSV_AV_FLAGS_ACCOUNT_AUTH_CONSTAINED = 0x00000001; // Indicates to the client that the account authentication is constrained.
    public static final int MSV_AV_FLAGS_MIC = 0x00000002; // Indicates that the client is providing message integrity in the MIC field in the AUTHENTICATE_MESSAGE.
    public static final int MSV_AV_FLAGS_UNTRUSTED_TARGET_SPN = 0x00000004; // Indicates that the client is providing a target SPN generated from an untrusted source.

    /** Secure random generator */
    private static final java.security.SecureRandom RND_GEN;
    static {
        java.security.SecureRandom rnd = null;
        try {
            rnd = java.security.SecureRandom.getInstance( "SHA1PRNG" );
        } catch ( final Exception ignore ) {
        }
        RND_GEN = rnd;
    }

    /** The signature string as bytes in the default encoding */
    static final byte[] SIGNATURE = DerUtil.nullTerminatedAsciiString( "NTLMSSP" );

    // Key derivation magic strings for the SIGNKEY algorithm defined in
    // [MS-NLMP] section 3.4.5.2
    static final byte[] SIGN_MAGIC_SERVER = DerUtil.nullTerminatedAsciiString(
        "session key to server-to-client signing key magic constant" );
    static final byte[] SIGN_MAGIC_CLIENT = DerUtil.nullTerminatedAsciiString(
        "session key to client-to-server signing key magic constant" );
    static final byte[] SEAL_MAGIC_SERVER = DerUtil.nullTerminatedAsciiString(
        "session key to server-to-client sealing key magic constant" );
    static final byte[] SEAL_MAGIC_CLIENT = DerUtil.nullTerminatedAsciiString(
        "session key to client-to-server sealing key magic constant" );

    // prefix for GSS API channel binding
    static final byte[] MAGIC_TLS_SERVER_ENDPOINT = "tls-server-end-point:".getBytes( Consts.ASCII );

    static final Log log = LogFactory.getLog( NTLMEngineImpl.class );

    /**
     * Enabling or disabling the development trace (extra logging).
     * We do NOT want this to be enabled by default.
     * We do not want to enable it even if full logging is turned on.
     * This may leak sensitive key material to the log files. It is supposed to be used only
     * for development purposes. We really need this to diagnose protocol issues, especially
     * if NTLM is used inside CredSSP.
     */
    static boolean develTrace = false;

    final NTCredentials credentials;
    final private boolean isConnection;

    /**
     * Type 1 (NEGOTIATE) message sent by the client.
     */
    private NegotiateMessage negotiateMessage;

    /**
     * Type 2 (CHALLENGE) message received by the client.
     */
    private ChallengeMessage challengeMessage;

    /**
     * Type 3 (AUTHENTICATE) message sent by the client.
     */
    private AuthenticateMessage authenticateMessage;

    /**
     * The key that is result of the NTLM key exchange.
     */
    private byte[] exportedSessionKey;

    /**
     * Creates a new instance of NTLM engine.
     *
     * @param credentials NT credentials that will be used in the message exchange.
     * @param isConnection true for connection mode, false for connection-less mode.
     */
    public NTLMEngineImpl( final NTCredentials credentials, final boolean isConnection )
    {
        super();
        this.credentials = credentials;
        this.isConnection = isConnection;
    }


    /**
     * Generate (create) new NTLM AUTHENTICATE (type 1) message in a form of Java object.
     * The generated message is remembered by the engine, e.g. for the purpose of MIC computation.
     *
     * @param ntlmFlags initial flags for the message. These flags influence the behavior of
     *                  entire protocol exchange.
     * @return NTLM AUTHENTICATE (type 1) message in a form of Java object
     * @throws NTLMEngineException in case of any (foreseeable) error
     */
    @Override
    public NegotiateMessage generateNegotiateMessage( final Integer ntlmFlags ) throws NTLMEngineException {
        if ( negotiateMessage != null )
        {
            throw new NTLMEngineException( "Type 1 message already generated" );
        }
        if ( credentials == null )
        {
            throw new NTLMEngineException( "No credentials" );
        }
        negotiateMessage = new NegotiateMessage(
            credentials.getDomain(),
            credentials.getWorkstation(),
            ntlmFlags );
        return negotiateMessage;
    }


    /**
     * Parse NTLM CHALLENGE (type 2) message in a base64-encoded format. The message is remembered by the engine.
     *
     * @param type2MessageBase64 base64 encoded NTLM challenge message
     * @return NTLM challenge message in a form of Java object.
     * @throws NTLMEngineException in case of any (foreseeable) error
     */
    public ChallengeMessage parseChallengeMessage( final String type2MessageBase64 ) throws NTLMEngineException {
        return parseChallengeMessage( Base64.decodeBase64( type2MessageBase64.getBytes( DEFAULT_CHARSET ) ) );
    }


    /**
     * Parse NTLM CHALLENGE (type 2) message in a binary format. The message is remembered by the engine.
     *
     * @param messageBytes binary (byte array) NTLM challenge message
     * @return NTLM challenge message in a form of Java object.
     * @throws NTLMEngineException in case of any (foreseeable) error
     */
    @Override
    public ChallengeMessage parseChallengeMessage( final byte[] messageBytes ) throws NTLMEngineException {
        if ( challengeMessage != null )
        {
            throw new NTLMEngineException( "Challenge message already parsed" );
        }
        challengeMessage = new ChallengeMessage( messageBytes );
        return challengeMessage;
    }


    /**
     * Generate NTLM AUTHENTICATE (type 3) message based on previous messages that were seen by the engine.
     *
     * @param peerServerCertificate optional peer certificate. If present then it will be used to set up
     *                              GSS API channel binding.
     * @return NTLM authenticate message in a form of Java object.
     * @throws NTLMEngineException in case of any (foreseeable) error
     */
    @Override
    public AuthenticateMessage generateAuthenticateMessage( final X509Certificate peerServerCertificate ) throws NTLMEngineException {
        if ( authenticateMessage != null ) {
            throw new NTLMEngineException( "Authenticate message already generated" );
        }
        if ( challengeMessage == null ) {
            throw new NTLMEngineException( "Challenge message was not yet parsed" );
        }
        if ( credentials == null ) {
            throw new NTLMEngineException( "No credentials" );
        }
        authenticateMessage = new AuthenticateMessage(
            credentials.getDomain(),
            credentials.getWorkstation(),
            credentials.getUserName(),
            credentials.getPassword(),
            challengeMessage.getChallenge(),
            challengeMessage.getFlags(),
            challengeMessage.getTarget(),
            challengeMessage.getTargetInfo(),
            peerServerCertificate );
        this.exportedSessionKey = authenticateMessage.getExportedSessionKey();
        authenticateMessage.addMic( negotiateMessage.getBytes(), challengeMessage.getBytes() );
        return authenticateMessage;
    }


    /** Strip dot suffix from a name */
    private static String stripDotSuffix( final String value )
    {
        if ( value == null )
        {
            return null;
        }
        final int index = value.indexOf( "." );
        if ( index != -1 )
        {
            return value.substring( 0, index );
        }
        return value;
    }


    /** Convert host to standard form */
    static String convertHost( final String host )
    {
        return stripDotSuffix( host );
    }


    /** Convert domain to standard form */
    static String convertDomain( final String domain )
    {
        return stripDotSuffix( domain );
    }


    static int readULong( final byte[] src, final int index ) throws NTLMEngineException {
        if ( src.length < index + 4 )
        {
            throw new NTLMEngineException( "NTLM authentication - buffer too small for DWORD" );
        }
        return ( src[index] & 0xff ) | ( ( src[index + 1] & 0xff ) << 8 )
            | ( ( src[index + 2] & 0xff ) << 16 ) | ( ( src[index + 3] & 0xff ) << 24 );
    }


    static int readUShort( final byte[] src, final int index ) throws NTLMEngineException {
        if ( src.length < index + 2 )
        {
            throw new NTLMEngineException( "NTLM authentication - buffer too small for WORD" );
        }
        return ( src[index] & 0xff ) | ( ( src[index + 1] & 0xff ) << 8 );
    }

    static byte[] readSecurityBuffer( final byte[] src, final int index ) throws NTLMEngineException {
        final int length = readUShort( src, index );
        final int offset = readULong( src, index + 4 );
        if ( src.length < offset + length )
        {
            throw new NTLMEngineException(
                "NTLM authentication - buffer too small for data item" );
        }
        final byte[] buffer = new byte[length];
        System.arraycopy( src, offset, buffer, 0, length );
        return buffer;
    }


    /** Calculate a challenge block */
    private static byte[] generateChallenge() throws NTLMEngineException {
        if ( RND_GEN == null ) {
            throw new NTLMEngineException( "Random generator not available" );
        }
        final byte[] rval = new byte[8];
        synchronized ( RND_GEN ) {
            RND_GEN.nextBytes( rval );
        }
        return rval;
    }


    /** Calculate a 16-byte secondary key */
    private static byte[] generateExportedSessionKey() throws NTLMEngineException
    {
        if ( RND_GEN == null ) {
            throw new NTLMEngineException( "Random generator not available" );
        }
        final byte[] rval = new byte[16];
        synchronized ( RND_GEN ) {
            RND_GEN.nextBytes( rval );
        }

        return rval;
    }

    protected static class CipherGen
    {

        protected final String domain;
        protected final String user;
        protected final String password;
        protected final byte[] challenge;
        protected final String target;
        protected final byte[] targetInformation;

        // Information we can generate but may be passed in (for testing)
        protected byte[] clientChallenge;
        protected byte[] clientChallenge2;
        protected byte[] exportedSessionKey;
        protected byte[] timestamp;

        // Stuff we always generate
        protected byte[] lmHash = null;
        protected byte[] lmResponse = null;
        protected byte[] ntlmPasswordHash = null;
        protected byte[] ntlmResponse = null;
        protected byte[] responseKeyNt = null;
        protected byte[] responseKeyLm = null;
        protected byte[] lmv2Response = null;
        protected byte[] ntlmv2Blob = null;
        protected byte[] ntlmv2Response = null;
        protected byte[] ntlm2SessionResponse = null;
        protected byte[] lm2SessionResponse = null;
        protected byte[] lmUserSessionKey = null;
        protected byte[] ntlmUserSessionKey = null;
        protected byte[] ntlmv2SessionBaseKey = null;
        protected byte[] ntlm2SessionResponseUserSessionKey = null;
        protected byte[] lanManagerSessionKey = null;


        public CipherGen( final String domain, final String user, final String password,
            final byte[] challenge, final String target, final byte[] targetInformation,
            final byte[] clientChallenge, final byte[] clientChallenge2,
            final byte[] exportedSessionKey, final byte[] timestamp )
        {
            this.domain = domain;
            this.target = target;
            this.user = user;
            this.password = password;
            this.challenge = challenge;
            this.targetInformation = targetInformation;
            this.clientChallenge = clientChallenge;
            this.clientChallenge2 = clientChallenge2;
            this.exportedSessionKey = exportedSessionKey;
            this.timestamp = timestamp;
        }


        public CipherGen( final String domain, final String user, final String password,
            final byte[] challenge, final String target, final byte[] targetInformation )
        {
            this( domain, user, password, challenge, target, targetInformation, null, null, null, null );
        }


        /** Calculate and return client challenge */
        public byte[] getClientChallenge()
            throws NTLMEngineException
        {
            if ( clientChallenge == null )
            {
                clientChallenge = generateChallenge();
            }
            return clientChallenge;
        }


        /** Calculate and return second client challenge */
        public byte[] getClientChallenge2()
            throws NTLMEngineException
        {
            if ( clientChallenge2 == null ) {
                clientChallenge2 = generateChallenge();
            }
            return clientChallenge2;
        }


        public byte[] getExportedSessionKey() throws NTLMEngineException {
            if ( exportedSessionKey == null ) {
                exportedSessionKey = generateExportedSessionKey();
            }
            return exportedSessionKey;
        }


        /** Calculate and return the LMHash */
        public byte[] getLMHash() throws NTLMEngineException {
            if ( lmHash == null ) {
                lmHash = lmHash( password );
            }
            return lmHash;
        }


        /** Calculate and return the LMResponse */
        public byte[] getLMResponse() throws NTLMEngineException {
            if ( lmResponse == null ) {
                lmResponse = lmResponse( getLMHash(), challenge );
            }
            return lmResponse;
        }


        /** Calculate and return the NTLMHash */
        public byte[] getNTLMPasswordHash() throws NTLMEngineException {
            if ( ntlmPasswordHash == null ) {
                ntlmPasswordHash = ntowfv1( password );
            }
            return ntlmPasswordHash;
        }


        /** Calculate and return the NTLMResponse */
        public byte[] getNTLMResponse() throws NTLMEngineException {
            if ( ntlmResponse == null ) {
                ntlmResponse = lmResponse( getNTLMPasswordHash(), challenge );
            }
            return ntlmResponse;
        }


        /** Calculate the LMv2 hash. ResponseKeyLM in the specifications. */
        public byte[] getResponseKeyLm() throws NTLMEngineException {
            if ( responseKeyLm == null ) {
                responseKeyLm = ntowfv2lm( domain, user, password );
            }
            return responseKeyLm;
        }


        /** Calculate the NTLMv2 hash. ResponseKeyNT in the specifications. */
        public byte[] getResponseKeyNt() throws NTLMEngineException {
            if ( responseKeyNt == null ) {
                responseKeyNt = ntowfv2( domain, user, getNTLMPasswordHash() );
            }
            return responseKeyNt;
        }


        /** Calculate a timestamp */
        public byte[] getTimestamp() {
            if ( timestamp == null ) {
                long time = System.currentTimeMillis();
                time += 11644473600000L; // milliseconds from January 1, 1601 -> epoch.
                time *= 10000; // tenths of a microsecond.
                // convert to little-endian byte array.
                timestamp = new byte[8];
                for ( int i = 0; i < 8; i++ ) {
                    timestamp[i] = ( byte ) time;
                    time >>>= 8;
                }
            }
            if (develTrace) {
                log.trace( "timestamp: " + DebugUtil.dump( timestamp ) );
            }
            return timestamp;
        }


        /**
         * Calculate the NTLMv2Blob.
         * Denoteted as "temp" in MS-NLMP section 3.3.2
         */
        public byte[] getNTLMv2Blob()
            throws NTLMEngineException {
            if ( ntlmv2Blob == null ) {
                ntlmv2Blob = createBlob( getClientChallenge2(), targetInformation, getTimestamp() );
            }
            return ntlmv2Blob;
        }


        /** Calculate the NTLMv2Response. NtChallengeResponse in the specifications. */
        public byte[] getNTLMv2Response()
            throws NTLMEngineException {
            if ( ntlmv2Response == null ) {
                ntlmv2Response = computeResponse( "NT", getResponseKeyNt(), challenge, getNTLMv2Blob() );
            }
            return ntlmv2Response;
        }


        /** Calculate the LMv2Response */
        public byte[] getLMv2Response()
            throws NTLMEngineException {
            if ( lmv2Response == null ) {
                lmv2Response = computeResponse( "LM", getResponseKeyLm(), challenge, getClientChallenge() );
            }
            return lmv2Response;
        }


        /** Get NTLM2SessionResponse */
        public byte[] getNTLM2SessionResponse()
            throws NTLMEngineException {
            if ( ntlm2SessionResponse == null ) {
                ntlm2SessionResponse = ntlm2SessionResponse( getNTLMPasswordHash(), challenge, getClientChallenge() );
            }
            return ntlm2SessionResponse;
        }


        /** Calculate and return LM2 session response */
        public byte[] getLM2SessionResponse()
            throws NTLMEngineException
        {
            if ( lm2SessionResponse == null ) {
                final byte[] clntChallenge = getClientChallenge();
                lm2SessionResponse = new byte[24];
                System.arraycopy( clntChallenge, 0, lm2SessionResponse, 0, clntChallenge.length );
                Arrays.fill( lm2SessionResponse, clntChallenge.length, lm2SessionResponse.length, ( byte ) 0x00 );
            }
            return lm2SessionResponse;
        }


        /** Get LMUserSessionKey */
        public byte[] getLMUserSessionKey()
            throws NTLMEngineException
        {
            if ( lmUserSessionKey == null ) {
                lmUserSessionKey = new byte[16];
                System.arraycopy( getLMHash(), 0, lmUserSessionKey, 0, 8 );
                Arrays.fill( lmUserSessionKey, 8, 16, ( byte ) 0x00 );
            }
            return lmUserSessionKey;
        }


        /** Get NTLMUserSessionKey */
        public byte[] getNTLMUserSessionKey()
            throws NTLMEngineException
        {
            if ( ntlmUserSessionKey == null )
            {
                final MD4 md4 = new MD4();
                md4.update( getNTLMPasswordHash() );
                ntlmUserSessionKey = md4.getOutput();
            }
            return ntlmUserSessionKey;
        }


        /** GetNTLMv2UserSessionKey */
        public byte[] getNTLMv2SessionBaseKey()
            throws NTLMEngineException
        {
            if ( ntlmv2SessionBaseKey == null )
            {
                final byte[] responseKeyNt = getResponseKeyNt();
                final byte[] ntChallengeResponse = getNTLMv2Response();
                // Strictly speaking, the NtChallengeResponse should be composed from the ntProofStr and temp
                // and we would like to reuse the ntProofStr here. But the construction of challenge response
                // happens inside the lmv2Response() method called from getNTLMv2Response() method.
                // Therefore we will rip out ntProofStr of the ntChallengeResponse.
                final byte[] ntProofStr = new byte[16];
                System.arraycopy( ntChallengeResponse, 0, ntProofStr, 0, 16 );
                ntlmv2SessionBaseKey = hmacMD5( ntProofStr, responseKeyNt );
            }
            return ntlmv2SessionBaseKey;
        }


        /** Get NTLM2SessionResponseUserSessionKey */
        public byte[] getNTLM2SessionResponseUserSessionKey()
            throws NTLMEngineException
        {
            if ( ntlm2SessionResponseUserSessionKey == null )
            {
                final byte[] ntlm2SessionResponseNonce = getLM2SessionResponse();
                final byte[] sessionNonce = new byte[challenge.length + ntlm2SessionResponseNonce.length];
                System.arraycopy( challenge, 0, sessionNonce, 0, challenge.length );
                System.arraycopy( ntlm2SessionResponseNonce, 0, sessionNonce, challenge.length,
                    ntlm2SessionResponseNonce.length );
                ntlm2SessionResponseUserSessionKey = hmacMD5( sessionNonce, getNTLMUserSessionKey() );
            }
            return ntlm2SessionResponseUserSessionKey;
        }


        /** Get LAN Manager session key */
        public byte[] getLanManagerSessionKey()
            throws NTLMEngineException
        {
            if ( lanManagerSessionKey == null )
            {
                try
                {
                    final byte[] keyBytes = new byte[14];
                    System.arraycopy( getLMHash(), 0, keyBytes, 0, 8 );
                    Arrays.fill( keyBytes, 8, keyBytes.length, ( byte ) 0xbd );
                    final Key lowKey = createDESKey( keyBytes, 0 );
                    final Key highKey = createDESKey( keyBytes, 7 );
                    final byte[] truncatedResponse = new byte[8];
                    System.arraycopy( getLMResponse(), 0, truncatedResponse, 0, truncatedResponse.length );
                    Cipher des = Cipher.getInstance( "DES/ECB/NoPadding" );
                    des.init( Cipher.ENCRYPT_MODE, lowKey );
                    final byte[] lowPart = des.doFinal( truncatedResponse );
                    des = Cipher.getInstance( "DES/ECB/NoPadding" );
                    des.init( Cipher.ENCRYPT_MODE, highKey );
                    final byte[] highPart = des.doFinal( truncatedResponse );
                    lanManagerSessionKey = new byte[16];
                    System.arraycopy( lowPart, 0, lanManagerSessionKey, 0, lowPart.length );
                    System.arraycopy( highPart, 0, lanManagerSessionKey, lowPart.length, highPart.length );
                }
                catch ( final Exception e )
                {
                    throw new NTLMEngineException( e.getMessage(), e );
                }
            }
            return lanManagerSessionKey;
        }
    }


    /** Calculates HMAC-MD5 */
    static byte[] hmacMD5( final byte[] value, final byte[] key )
        throws NTLMEngineException
    {
        final HMACMD5 hmacMD5 = new HMACMD5( key );
        hmacMD5.update( value );
        return hmacMD5.getOutput();
    }


    /** Calculates RC4 */
    static byte[] RC4( final byte[] value, final byte[] key )
        throws NTLMEngineException
    {
        try
        {
            final Cipher rc4 = Cipher.getInstance( "RC4" );
            rc4.init( Cipher.ENCRYPT_MODE, new SecretKeySpec( key, "RC4" ) );
            return rc4.doFinal( value );
        }
        catch ( final Exception e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
    }


    /**
     * Calculates the NTLM2 Session Response for the given challenge, using the
     * specified password and client challenge.
     *
     * @return The NTLM2 Session Response. This is placed in the NTLM response
     *         field of the Type 3 message; the LM response field contains the
     *         client challenge, null-padded to 24 bytes.
     */
    static byte[] ntlm2SessionResponse( final byte[] ntlmHash, final byte[] challenge,
        final byte[] clientChallenge ) throws NTLMEngineException
    {
        try
        {
            final MessageDigest md5 = MessageDigest.getInstance( "MD5" );
            md5.update( challenge );
            md5.update( clientChallenge );
            final byte[] digest = md5.digest();

            final byte[] sessionHash = new byte[8];
            System.arraycopy( digest, 0, sessionHash, 0, 8 );
            return lmResponse( ntlmHash, sessionHash );
        }
        catch ( final Exception e )
        {
            if ( e instanceof NTLMEngineException )
            {
                throw ( NTLMEngineException ) e;
            }
            throw new NTLMEngineException( e.getMessage(), e );
        }
    }


    /**
     * Creates the LM Hash of the user's password.
     *
     * @param password
     *            The password.
     *
     * @return The LM Hash of the given password, used in the calculation of the
     *         LM Response.
     */
    private static byte[] lmHash( final String password ) throws NTLMEngineException
    {
        try
        {
            final byte[] oemPassword = password.toUpperCase( Locale.ROOT ).getBytes( Consts.ASCII );
            final int length = Math.min( oemPassword.length, 14 );
            final byte[] keyBytes = new byte[14];
            System.arraycopy( oemPassword, 0, keyBytes, 0, length );
            final Key lowKey = createDESKey( keyBytes, 0 );
            final Key highKey = createDESKey( keyBytes, 7 );
            final byte[] magicConstant = "KGS!@#$%".getBytes( Consts.ASCII );
            final Cipher des = Cipher.getInstance( "DES/ECB/NoPadding" );
            des.init( Cipher.ENCRYPT_MODE, lowKey );
            final byte[] lowHash = des.doFinal( magicConstant );
            des.init( Cipher.ENCRYPT_MODE, highKey );
            final byte[] highHash = des.doFinal( magicConstant );
            final byte[] lmHash = new byte[16];
            System.arraycopy( lowHash, 0, lmHash, 0, 8 );
            System.arraycopy( highHash, 0, lmHash, 8, 8 );
            return lmHash;
        }
        catch ( final Exception e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
    }


    /**
     * Creates the NTLM Hash of the user's password.
     * [MS-NLMP] section 3.3.1
     *
     * @param password
     *            The password.
     *
     * @return The NTLM Hash of the given password, used in the calculation of
     *         the NTLM Response and the NTLMv2 and LMv2 Hashes.
     */
    private static byte[] ntowfv1( final String password ) throws NTLMEngineException
    {
        // Password is always uncoded in unicode regardless of the encoding specified by flags
        final byte[] unicodePassword = password.getBytes( UNICODE_LITTLE_UNMARKED );
        final MD4 md4 = new MD4();
        md4.update( unicodePassword );
        return md4.getOutput();
    }


    /**
     * Creates the LMv2 Hash of the user's password.
     * Corresponds to the LMOWFv2(Passwd, User, UserDom) function from the specification.
     * [MS-NLMP] section 3.3.1
     *
     * However, this has slight twist of uppercasing the domain name. Which I could not find
     * in the specifications. The function is kept as it is because I'm not sure why it was
     * implemented like this.
     *
     * @return The LMv2 Hash, used in the calculation of the NTLMv2 and LMv2
     *         Responses.
     */
    private static byte[] ntowfv2lm( final String domain, final String user, final String password )
        throws NTLMEngineException
    {
        // Password is always uncoded in unicode regardless of the encoding specified by flags
        final HMACMD5 hmacMD5 = new HMACMD5( ntowfv1( password ) );
        // Upper case username, upper case domain!
        hmacMD5.update( user.toUpperCase( Locale.ROOT ).getBytes( UNICODE_LITTLE_UNMARKED ) );
        if ( domain != null )
        {
            hmacMD5.update( domain.toUpperCase( Locale.ROOT ).getBytes( UNICODE_LITTLE_UNMARKED ) );
        }
        return hmacMD5.getOutput();
    }


    /**
     * Creates the NTLMv2 Hash of the user's password.
     * Corresponds to the LMOWFv2(Passwd, User, UserDom) function from the specification.
     *
     * @return The NTLMv2 Hash, used in the calculation of the NTLMv2 and LMv2
     *         Responses.
     */
    private static byte[] ntowfv2( final String domain, final String user, final byte[] ntlmHash )
        throws NTLMEngineException
    {
        final HMACMD5 hmacMD5 = new HMACMD5( ntlmHash );
        // Upper case username, mixed case target!!
        hmacMD5.update( user.toUpperCase( Locale.ROOT ).getBytes( UNICODE_LITTLE_UNMARKED ) );
        if ( domain != null )
        {
            hmacMD5.update( domain.getBytes( UNICODE_LITTLE_UNMARKED ) );
        }
        return hmacMD5.getOutput();
    }


    /**
     * Creates the LM Response from the given hash and Type 2 challenge.
     *
     * @param hash
     *            The LM or NTLM Hash.
     * @param challenge
     *            The server challenge from the Type 2 message.
     *
     * @return The response (either LM or NTLM, depending on the provided hash).
     */
    private static byte[] lmResponse( final byte[] hash, final byte[] challenge ) throws NTLMEngineException
    {
        try
        {
            final byte[] keyBytes = new byte[21];
            System.arraycopy( hash, 0, keyBytes, 0, 16 );
            final Key lowKey = createDESKey( keyBytes, 0 );
            final Key middleKey = createDESKey( keyBytes, 7 );
            final Key highKey = createDESKey( keyBytes, 14 );
            final Cipher des = Cipher.getInstance( "DES/ECB/NoPadding" );
            des.init( Cipher.ENCRYPT_MODE, lowKey );
            final byte[] lowResponse = des.doFinal( challenge );
            des.init( Cipher.ENCRYPT_MODE, middleKey );
            final byte[] middleResponse = des.doFinal( challenge );
            des.init( Cipher.ENCRYPT_MODE, highKey );
            final byte[] highResponse = des.doFinal( challenge );
            final byte[] lmResponse = new byte[24];
            System.arraycopy( lowResponse, 0, lmResponse, 0, 8 );
            System.arraycopy( middleResponse, 0, lmResponse, 8, 8 );
            System.arraycopy( highResponse, 0, lmResponse, 16, 8 );
            return lmResponse;
        }
        catch ( final Exception e )
        {
            throw new NTLMEngineException( e.getMessage(), e );
        }
    }


    /**
     * Computes authentication response from the given hash, client data,
     * and server challenge.
     * Used for both LmChallengeResponse and NtChallengeResponse.
     *
     * [MS-NLMP] section 3.3.2
     *
     * @param responseKey
     *            The NTLMv2 Hash. ResponseKeyNT or ResponseKeyLM
     * @param clientData
     *            The client data (blob or client challenge).
     *            Denoted as "temp" in the MS-NLMP spec.
     * @param serverChallenge
     *            The server challenge from the challenge message.
     *
     * @return The response (either NTLMv2 or LMv2, depending on the client
     *         data).
     */
    private static byte[] computeResponse( final String type, final byte[] responseKey, final byte[] serverChallenge, final byte[] clientData )
        throws NTLMEngineException {
        final HMACMD5 hmacMD5 = new HMACMD5( responseKey );
        hmacMD5.update( serverChallenge );
        hmacMD5.update( clientData );
        final byte[] proofStr = hmacMD5.getOutput(); // NtProofStr or its LM equivalent
        final byte[] response = new byte[proofStr.length + clientData.length];
        System.arraycopy( proofStr, 0, response, 0, proofStr.length );
        System.arraycopy( clientData, 0, response, proofStr.length, clientData.length );
        if (develTrace) {
            log.trace( type+"response" +
                "\n   responseKey:\n        " + DebugUtil.dump( responseKey ) +
                "\n   serverChallenge:\n        " + DebugUtil.dump( serverChallenge ) +
                "\n   clientData(temp):\n        " + DebugUtil.dump( clientData ) +
                "\n   proofStr:\n        " + DebugUtil.dump( proofStr ) +
                "\n   response:\n        " + DebugUtil.dump( response ) );
        }
        return response;
    }

    public static enum Mode
    {
        CLIENT, SERVER;
    }

    @Override
    public NTLMHandle createClientHandle() throws NTLMEngineException
    {
        final NTLMHandle handle = new NTLMHandle( exportedSessionKey, Mode.CLIENT, isConnection );
        handle.init();
        return handle;
    }

    @Override
    public NTLMHandle createServerHandle() throws NTLMEngineException
    {
        final NTLMHandle handle = new NTLMHandle( exportedSessionKey, Mode.SERVER, isConnection );
        handle.init();
        return handle;
    }

    /**
     * Creates the NTLMv2 blob from the given target information block and
     * client challenge.
     *
     * This is "temp" in the specifications (ComputeResponse method, 3.3.2)
     *
     * @param serverName
     *            The target information block from the challenge message.
     * @param clientChallenge
     *            The random 8-byte client challenge.
     *
     * @return The blob, used in the calculation of the NTLMv2 Response.
     */
    private static byte[] createBlob( final byte[] clientChallenge, final byte[] serverName, final byte[] timestamp ) {
        final byte[] responseVersion = new byte[]
            { ( byte ) 0x01, ( byte ) 0x01 };
        final byte[] reserved1 = new byte[]
            { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };
        final byte[] reserved2 = new byte[]
            { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };
        final byte[] reserved3 = new byte[]
            { ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 };
        final byte[] blob = new byte[responseVersion.length + reserved1.length + timestamp.length + 8
            + reserved2.length + serverName.length + reserved3.length];
        int offset = 0;
        System.arraycopy( responseVersion, 0, blob, offset, responseVersion.length );
        offset += responseVersion.length;
        System.arraycopy( reserved1, 0, blob, offset, reserved1.length );
        offset += reserved1.length;
        System.arraycopy( timestamp, 0, blob, offset, timestamp.length );
        offset += timestamp.length;
        System.arraycopy( clientChallenge, 0, blob, offset, 8 );
        offset += 8;
        System.arraycopy( reserved2, 0, blob, offset, reserved2.length );
        offset += reserved2.length;
        System.arraycopy( serverName, 0, blob, offset, serverName.length );
        offset += serverName.length;
        System.arraycopy( reserved3, 0, blob, offset, reserved3.length );
        offset += reserved3.length;
        return blob;
    }


    /**
     * Creates a DES encryption key from the given key material.
     *
     * @param bytes
     *            A byte array containing the DES key material.
     * @param offset
     *            The offset in the given byte array at which the 7-byte key
     *            material starts.
     *
     * @return A DES encryption key created from the key material starting at
     *         the specified offset in the given byte array.
     */
    private static Key createDESKey( final byte[] bytes, final int offset )
    {
        final byte[] keyBytes = new byte[7];
        System.arraycopy( bytes, offset, keyBytes, 0, 7 );
        final byte[] material = new byte[8];
        material[0] = keyBytes[0];
        material[1] = ( byte ) ( keyBytes[0] << 7 | ( keyBytes[1] & 0xff ) >>> 1 );
        material[2] = ( byte ) ( keyBytes[1] << 6 | ( keyBytes[2] & 0xff ) >>> 2 );
        material[3] = ( byte ) ( keyBytes[2] << 5 | ( keyBytes[3] & 0xff ) >>> 3 );
        material[4] = ( byte ) ( keyBytes[3] << 4 | ( keyBytes[4] & 0xff ) >>> 4 );
        material[5] = ( byte ) ( keyBytes[4] << 3 | ( keyBytes[5] & 0xff ) >>> 5 );
        material[6] = ( byte ) ( keyBytes[5] << 2 | ( keyBytes[6] & 0xff ) >>> 6 );
        material[7] = ( byte ) ( keyBytes[6] << 1 );
        oddParity( material );
        return new SecretKeySpec( material, "DES" );
    }


    /**
     * Applies odd parity to the given byte array.
     *
     * @param bytes
     *            The data whose parity bits are to be adjusted for odd parity.
     */
    private static void oddParity( final byte[] bytes )
    {
        for ( int i = 0; i < bytes.length; i++ )
        {
            final byte b = bytes[i];
            final boolean needsParity = ( ( ( b >>> 7 ) ^ ( b >>> 6 ) ^ ( b >>> 5 ) ^ ( b >>> 4 ) ^ ( b >>> 3 )
                ^ ( b >>> 2 ) ^ ( b >>> 1 ) ) & 0x01 ) == 0;
            if ( needsParity )
            {
                bytes[i] |= ( byte ) 0x01;
            }
            else
            {
                bytes[i] &= ( byte ) 0xfe;
            }
        }
    }


    static Charset getCharset( final Integer flags ) throws NTLMEngineException
    {
        if ( flags != null && ( flags & FLAG_REQUEST_UNICODE_ENCODING ) == 0 )
        {
            return DEFAULT_CHARSET;
        }
        else
        {
            if ( UNICODE_LITTLE_UNMARKED == null )
            {
                throw new NTLMEngineException( "Unicode not supported" );
            }
            return UNICODE_LITTLE_UNMARKED;
        }
    }

    static void writeUShort( final byte[] buffer, final int value, final int offset )
    {
        buffer[offset] = ( byte ) ( value & 0xff );
        buffer[offset + 1] = ( byte ) ( value >> 8 & 0xff );
    }


    static void writeULong( final byte[] buffer, final int value, final int offset )
    {
        buffer[offset] = ( byte ) ( value & 0xff );
        buffer[offset + 1] = ( byte ) ( value >> 8 & 0xff );
        buffer[offset + 2] = ( byte ) ( value >> 16 & 0xff );
        buffer[offset + 3] = ( byte ) ( value >> 24 & 0xff );
    }


    static String toHexString( final byte[] bytes )
    {
        final StringBuilder sb = new StringBuilder();
        for ( int i = 0; i < bytes.length; i++ )
        {
            sb.append( String.format( "%02X", bytes[i] ) );
        }
        return sb.toString();
    }


    static int F( final int x, final int y, final int z )
    {
        return ( ( x & y ) | ( ~x & z ) );
    }


    static int G( final int x, final int y, final int z )
    {
        return ( ( x & y ) | ( x & z ) | ( y & z ) );
    }


    static int H( final int x, final int y, final int z )
    {
        return ( x ^ y ^ z );
    }


    static int rotintlft( final int val, final int numbits )
    {
        return ( ( val << numbits ) | ( val >>> ( 32 - numbits ) ) );
    }

    /**
     * Cryptography support - MD4. The following class was based loosely on the
     * RFC and on code found at http://www.cs.umd.edu/~harry/jotp/src/md.java.
     * Code correctness was verified by looking at MD4.java from the jcifs
     * library (http://jcifs.samba.org). It was massaged extensively to the
     * final form found here by Karl Wright (kwright@metacarta.com).
     */
    static class MD4
    {
        protected int A = 0x67452301;
        protected int B = 0xefcdab89;
        protected int C = 0x98badcfe;
        protected int D = 0x10325476;
        protected long count = 0L;
        protected byte[] dataBuffer = new byte[64];


        MD4()
        {
        }


        void update( final byte[] input )
        {
            // We always deal with 512 bits at a time. Correspondingly, there is
            // a buffer 64 bytes long that we write data into until it gets
            // full.
            int curBufferPos = ( int ) ( count & 63L );
            int inputIndex = 0;
            while ( input.length - inputIndex + curBufferPos >= dataBuffer.length )
            {
                // We have enough data to do the next step. Do a partial copy
                // and a transform, updating inputIndex and curBufferPos
                // accordingly
                final int transferAmt = dataBuffer.length - curBufferPos;
                System.arraycopy( input, inputIndex, dataBuffer, curBufferPos, transferAmt );
                count += transferAmt;
                curBufferPos = 0;
                inputIndex += transferAmt;
                processBuffer();
            }

            // If there's anything left, copy it into the buffer and leave it.
            // We know there's not enough left to process.
            if ( inputIndex < input.length )
            {
                final int transferAmt = input.length - inputIndex;
                System.arraycopy( input, inputIndex, dataBuffer, curBufferPos, transferAmt );
                count += transferAmt;
                curBufferPos += transferAmt;
            }
        }


        byte[] getOutput()
        {
            // Feed pad/length data into engine. This must round out the input
            // to a multiple of 512 bits.
            final int bufferIndex = ( int ) ( count & 63L );
            final int padLen = ( bufferIndex < 56 ) ? ( 56 - bufferIndex ) : ( 120 - bufferIndex );
            final byte[] postBytes = new byte[padLen + 8];
            // Leading 0x80, specified amount of zero padding, then length in
            // bits.
            postBytes[0] = ( byte ) 0x80;
            // Fill out the last 8 bytes with the length
            for ( int i = 0; i < 8; i++ )
            {
                postBytes[padLen + i] = ( byte ) ( ( count * 8 ) >>> ( 8 * i ) );
            }

            // Update the engine
            update( postBytes );

            // Calculate final result
            final byte[] result = new byte[16];
            writeULong( result, A, 0 );
            writeULong( result, B, 4 );
            writeULong( result, C, 8 );
            writeULong( result, D, 12 );
            return result;
        }


        protected void processBuffer()
        {
            // Convert current buffer to 16 ulongs
            final int[] d = new int[16];

            for ( int i = 0; i < 16; i++ )
            {
                d[i] = ( dataBuffer[i * 4] & 0xff ) + ( ( dataBuffer[i * 4 + 1] & 0xff ) << 8 )
                    + ( ( dataBuffer[i * 4 + 2] & 0xff ) << 16 )
                    + ( ( dataBuffer[i * 4 + 3] & 0xff ) << 24 );
            }

            // Do a round of processing
            final int AA = A;
            final int BB = B;
            final int CC = C;
            final int DD = D;
            round1( d );
            round2( d );
            round3( d );
            A += AA;
            B += BB;
            C += CC;
            D += DD;

        }


        protected void round1( final int[] d )
        {
            A = rotintlft( ( A + F( B, C, D ) + d[0] ), 3 );
            D = rotintlft( ( D + F( A, B, C ) + d[1] ), 7 );
            C = rotintlft( ( C + F( D, A, B ) + d[2] ), 11 );
            B = rotintlft( ( B + F( C, D, A ) + d[3] ), 19 );

            A = rotintlft( ( A + F( B, C, D ) + d[4] ), 3 );
            D = rotintlft( ( D + F( A, B, C ) + d[5] ), 7 );
            C = rotintlft( ( C + F( D, A, B ) + d[6] ), 11 );
            B = rotintlft( ( B + F( C, D, A ) + d[7] ), 19 );

            A = rotintlft( ( A + F( B, C, D ) + d[8] ), 3 );
            D = rotintlft( ( D + F( A, B, C ) + d[9] ), 7 );
            C = rotintlft( ( C + F( D, A, B ) + d[10] ), 11 );
            B = rotintlft( ( B + F( C, D, A ) + d[11] ), 19 );

            A = rotintlft( ( A + F( B, C, D ) + d[12] ), 3 );
            D = rotintlft( ( D + F( A, B, C ) + d[13] ), 7 );
            C = rotintlft( ( C + F( D, A, B ) + d[14] ), 11 );
            B = rotintlft( ( B + F( C, D, A ) + d[15] ), 19 );
        }


        protected void round2( final int[] d )
        {
            A = rotintlft( ( A + G( B, C, D ) + d[0] + 0x5a827999 ), 3 );
            D = rotintlft( ( D + G( A, B, C ) + d[4] + 0x5a827999 ), 5 );
            C = rotintlft( ( C + G( D, A, B ) + d[8] + 0x5a827999 ), 9 );
            B = rotintlft( ( B + G( C, D, A ) + d[12] + 0x5a827999 ), 13 );

            A = rotintlft( ( A + G( B, C, D ) + d[1] + 0x5a827999 ), 3 );
            D = rotintlft( ( D + G( A, B, C ) + d[5] + 0x5a827999 ), 5 );
            C = rotintlft( ( C + G( D, A, B ) + d[9] + 0x5a827999 ), 9 );
            B = rotintlft( ( B + G( C, D, A ) + d[13] + 0x5a827999 ), 13 );

            A = rotintlft( ( A + G( B, C, D ) + d[2] + 0x5a827999 ), 3 );
            D = rotintlft( ( D + G( A, B, C ) + d[6] + 0x5a827999 ), 5 );
            C = rotintlft( ( C + G( D, A, B ) + d[10] + 0x5a827999 ), 9 );
            B = rotintlft( ( B + G( C, D, A ) + d[14] + 0x5a827999 ), 13 );

            A = rotintlft( ( A + G( B, C, D ) + d[3] + 0x5a827999 ), 3 );
            D = rotintlft( ( D + G( A, B, C ) + d[7] + 0x5a827999 ), 5 );
            C = rotintlft( ( C + G( D, A, B ) + d[11] + 0x5a827999 ), 9 );
            B = rotintlft( ( B + G( C, D, A ) + d[15] + 0x5a827999 ), 13 );

        }


        protected void round3( final int[] d )
        {
            A = rotintlft( ( A + H( B, C, D ) + d[0] + 0x6ed9eba1 ), 3 );
            D = rotintlft( ( D + H( A, B, C ) + d[8] + 0x6ed9eba1 ), 9 );
            C = rotintlft( ( C + H( D, A, B ) + d[4] + 0x6ed9eba1 ), 11 );
            B = rotintlft( ( B + H( C, D, A ) + d[12] + 0x6ed9eba1 ), 15 );

            A = rotintlft( ( A + H( B, C, D ) + d[2] + 0x6ed9eba1 ), 3 );
            D = rotintlft( ( D + H( A, B, C ) + d[10] + 0x6ed9eba1 ), 9 );
            C = rotintlft( ( C + H( D, A, B ) + d[6] + 0x6ed9eba1 ), 11 );
            B = rotintlft( ( B + H( C, D, A ) + d[14] + 0x6ed9eba1 ), 15 );

            A = rotintlft( ( A + H( B, C, D ) + d[1] + 0x6ed9eba1 ), 3 );
            D = rotintlft( ( D + H( A, B, C ) + d[9] + 0x6ed9eba1 ), 9 );
            C = rotintlft( ( C + H( D, A, B ) + d[5] + 0x6ed9eba1 ), 11 );
            B = rotintlft( ( B + H( C, D, A ) + d[13] + 0x6ed9eba1 ), 15 );

            A = rotintlft( ( A + H( B, C, D ) + d[3] + 0x6ed9eba1 ), 3 );
            D = rotintlft( ( D + H( A, B, C ) + d[11] + 0x6ed9eba1 ), 9 );
            C = rotintlft( ( C + H( D, A, B ) + d[7] + 0x6ed9eba1 ), 11 );
            B = rotintlft( ( B + H( C, D, A ) + d[15] + 0x6ed9eba1 ), 15 );

        }

    }

    /**
     * Cryptography support - HMACMD5 - algorithmically based on various web
     * resources by Karl Wright
     */
    static class HMACMD5
    {
        protected byte[] ipad;
        protected byte[] opad;
        protected MessageDigest md5;


        HMACMD5( final byte[] input ) throws NTLMEngineException
        {
            byte[] key = input;
            try {
                md5 = MessageDigest.getInstance( "MD5" );
            } catch ( final Exception ex ) {
                // Umm, the algorithm doesn't exist - throw an
                // NTLMEngineException!
                throw new NTLMEngineException(
                    "Error getting md5 message digest implementation: " + ex.getMessage(), ex );
            }

            // Initialize the pad buffers with the key
            ipad = new byte[64];
            opad = new byte[64];

            int keyLength = key.length;
            if ( keyLength > 64 ) {
                // Use MD5 of the key instead, as described in RFC 2104
                md5.update( key );
                key = md5.digest();
                keyLength = key.length;
            }
            int i = 0;
            while ( i < keyLength ) {
                ipad[i] = ( byte ) ( key[i] ^ ( byte ) 0x36 );
                opad[i] = ( byte ) ( key[i] ^ ( byte ) 0x5c );
                i++;
            } while ( i < 64 ) {
                ipad[i] = ( byte ) 0x36;
                opad[i] = ( byte ) 0x5c;
                i++;
            }

            // Very important: update the digest with the ipad buffer
            md5.reset();
            md5.update( ipad );

        }


        /** Grab the current digest. This is the "answer". */
        byte[] getOutput()
        {
            final byte[] digest = md5.digest();
            md5.update( opad );
            return md5.digest( digest );
        }


        /** Update by adding a complete array */
        void update( final byte[] input )
        {
            md5.update( input );
        }


        /** Update the algorithm */
        void update( final byte[] input, final int offset, final int length )
        {
            md5.update( input, offset, length );
        }

    }

    static String dumpFlags( final int flags ) {
        final StringBuilder sb = new StringBuilder();
        sb.append( String.format( "[%04X:", flags ) );
        dumpFlag( sb, flags, FLAG_REQUEST_UNICODE_ENCODING, "REQUEST_UNICODE_ENCODING" );
        dumpFlag( sb, flags, FLAG_REQUEST_OEM_ENCODING, "REQUEST_OEM_ENCODING" );
        dumpFlag( sb, flags, FLAG_REQUEST_TARGET, "REQUEST_TARGET" );
        dumpFlag( sb, flags, FLAG_REQUEST_SIGN, "REQUEST_SIGN" );
        dumpFlag( sb, flags, FLAG_REQUEST_SEAL, "REQUEST_SEAL" );
        dumpFlag( sb, flags, FLAG_REQUEST_LAN_MANAGER_KEY, "REQUEST_LAN_MANAGER_KEY" );
        dumpFlag( sb, flags, FLAG_REQUEST_NTLMv1, "REQUEST_NTLMv1" );
        dumpFlag( sb, flags, FLAG_DOMAIN_PRESENT, "DOMAIN_PRESENT" );
        dumpFlag( sb, flags, FLAG_WORKSTATION_PRESENT, "WORKSTATION_PRESENT" );
        dumpFlag( sb, flags, FLAG_REQUEST_ALWAYS_SIGN, "REQUEST_ALWAYS_SIGN" );
        dumpFlag( sb, flags, FLAG_REQUEST_NTLM2_SESSION, "REQUEST_NTLM2_SESSION" );
        dumpFlag( sb, flags, FLAG_REQUEST_VERSION, "REQUEST_VERSION" );
        dumpFlag( sb, flags, FLAG_TARGETINFO_PRESENT, "TARGETINFO_PRESENT" );
        dumpFlag( sb, flags, FLAG_REQUEST_128BIT_KEY_EXCH, "REQUEST_128BIT_KEY_EXCH" );
        dumpFlag( sb, flags, FLAG_REQUEST_EXPLICIT_KEY_EXCH, "REQUEST_EXPLICIT_KEY_EXCH" );
        dumpFlag( sb, flags, FLAG_REQUEST_56BIT_ENCRYPTION, "REQUEST_56BIT_ENCRYPTION" );
        sb.append( "]" );
        return sb.toString();
    }


    private static void dumpFlag( final StringBuilder sb, final int flags, final int flagMask, final String name ) {
        if ( ( flags & flagMask ) == flagMask ) {
            sb.append( name ).append( "," );
        }
    }
}
