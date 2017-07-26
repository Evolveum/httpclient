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
import java.util.Locale;

import org.apache.http.impl.auth.DebugUtil;

/**
 * NEGOTIATE message: Section 2.2.1.1 of [MS-NLMP]
 */
public class NegotiateMessage extends NTLMOutputMessage
{

    private final byte[] hostBytes;
    private final byte[] domainBytes;
    private final Integer flags;


    NegotiateMessage( final String domain, final String host, final Integer flags ) throws NTLMEngineException
    {
        super();
        // Strip off domain name from the host!
        final String unqualifiedHost = NTLMEngineImpl.convertHost( host );
        // Use only the base domain name!
        final String unqualifiedDomain = NTLMEngineImpl.convertDomain( domain );

        final Charset charset = NTLMEngineImpl.getCharset( flags );

        hostBytes = unqualifiedHost != null ? unqualifiedHost.getBytes( charset ) : null;
        domainBytes = unqualifiedDomain != null ? unqualifiedDomain.toUpperCase( Locale.ROOT ).getBytes( charset )
            : null;
        if ( flags == null )
        {
            this.flags = getDefaultFlags();
        }
        else
        {
            this.flags = flags;
        }
    }


    NegotiateMessage( final String domain, final String host ) throws NTLMEngineException
    {
        this( domain, host, null );
    }


    NegotiateMessage()
    {
        super();
        hostBytes = null;
        domainBytes = null;
        flags = getDefaultFlags();
    }


    private static Integer getDefaultFlags()
    {
        return
        //FLAG_WORKSTATION_PRESENT |
        //FLAG_DOMAIN_PRESENT |

        // Required flags
        //FLAG_REQUEST_LAN_MANAGER_KEY |
        NTLMEngineImpl.FLAG_REQUEST_NTLMv1 |
            NTLMEngineImpl.FLAG_REQUEST_NTLM2_SESSION |

            NTLMEngineImpl.FLAG_REQUEST_VERSION |

            NTLMEngineImpl.FLAG_REQUEST_ALWAYS_SIGN |
            //FLAG_REQUEST_SEAL |
            //FLAG_REQUEST_SIGN |

            NTLMEngineImpl.FLAG_REQUEST_128BIT_KEY_EXCH |
            NTLMEngineImpl.FLAG_REQUEST_56BIT_ENCRYPTION |
            //FLAG_REQUEST_EXPLICIT_KEY_EXCH |

            NTLMEngineImpl.FLAG_REQUEST_UNICODE_ENCODING;
    }


    /**
     * Getting the response involves building the message before returning
     * it
     */
    @Override
    protected void encodeMessage()
    {
        int domainBytesLength = 0;
        if ( domainBytes != null )
        {
            domainBytesLength = domainBytes.length;
        }
        int hostBytesLength = 0;
        if ( hostBytes != null )
        {
            hostBytesLength = hostBytes.length;
        }
        // Now, build the message. Calculate its length first, including
        // signature or type.
        final int finalLength = 32 + 8 + hostBytesLength + domainBytesLength;

        // Set up the response. This will initialize the signature, message
        // type, and flags.
        prepareResponse( finalLength, 1 );

        // Flags. These are the complete set of flags we support.
        addULong( flags );

        // Domain length (two times).
        addUShort( domainBytesLength );
        addUShort( domainBytesLength );

        // Domain offset.
        addULong( hostBytesLength + 32 + 8 );

        // Host length (two times).
        addUShort( hostBytesLength );
        addUShort( hostBytesLength );

        // Host offset (always 32 + 11).
        addULong( 32 + 11 );

        // Version
        addUShort( 0x0106 );
        // Build
        addULong( 0x1db1 );
        // NTLM revision
        addUShort( 0x0f00 );

        // Host (workstation) String.
        if ( hostBytes != null )
        {
            addBytes( hostBytes );
        }
        // Domain String.
        if ( domainBytes != null )
        {
            addBytes( domainBytes );
        }
    }


    public String debugDump()
    {
        final StringBuilder sb = new StringBuilder( "NegotiateMessage\n" );
        sb.append( "  flags:\n    " ).append( NTLMEngineImpl.dumpFlags( flags ) ).append( "\n" );
        sb.append( "  hostBytes:\n    " ).append( DebugUtil.dump( hostBytes ) ).append( "\n" );
        sb.append( "  domainBytes:\n    " ).append( DebugUtil.dump( domainBytes ) );
        return sb.toString();
    }

}