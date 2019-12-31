import sspi;
//--------------------------------------------------------------------
//  Client-side program to establish an SSPI socket connection
//  with a server and exchange messages.

//--------------------------------------------------------------------
//  Define macros and constants.

enum BIG_BUFF = 2048;

bool SEC_SUCCESS(T)(T status)
{
	return status >= 0;
}

enum g_usPort = 2000;

enum cbMaxMessage = 12000;
enum MessageAttribute = ISC_REQ_CONFIDENTIALITY ;

// #include <windows.h>
// #include <winsock.h>
// #include <stdio.h>
// #include <stdlib.h>

CredHandle hCred;
_SecHandle  hcText;

//  The following #define statement must be changed. ServerName must
//  be defined as the name of the computer running the server sample.
//  TargetName must be defined as the logon name of the user running 
//  the server program.
enum ServerName  = "Server_Computer_Name";
enum TargetName  = "Server_User_Logon_Name";

int main(string[] args)
{
	import std.stdio : writefln, stderr;
	import std.exception : enforce;
	import std.format : format;

    SOCKET            Client_Socket;
    BYTE              Data[BIG_BUFF];
    PCHAR             pMessage;
    WSADATA           wsaData;
    CredHandle        hCred;
    struct _SecHandle hCtxt;
    SECURITY_STATUS   ss;
    DWORD             cbRead;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;
    SecPkgContext_NegotiationInfo  SecPkgNegInfo;
    bool DoAuthentication (SOCKET s);

    //  Initialize the socket and the SSP security package.
    enforce(!WSAStartup (0x0101, &wsaData), "Could not initialize winsock");

    //  connect to a server.
    auto socket = createAuthenticatedSocket(serverName, serverPort, &Client_Socket, &hCred, &hCtxt);

	auto user = getUser();
	auto client = ClientAuth("NTLM",getUser());
	auto result = client.authorize();
	auto data = cast(ubyte[]) (result[1]);
	auto buf = new char[Base64.encodeLength(data.length)];
	Base64.encode(data,buf);
	auto request = cast(string)buf.idup;

    //--------------------------------------------------------------------
    //   An authenticated session with a server has been established.
    //   Receive and manage a message from the server.
    //   First, find and display the name of the negotiated
    //   SSP and the size of the signature and the encryption 
    //   trailer blocks for this SSP.

    ss = QueryContextAttributes( &hCtxt, SECPKG_ATTR_NEGOTIATION_INFO, &SecPkgNegInfo );
	enforce(ss >=0, "QueryContextAttributes failed");
	writefln("Package Name: %s", SecPkgNegInfo.PackageInfo.Name);

    ss = QueryContextAttributes( &hCtxt, SECPKG_ATTR_SIZES, &SecPkgContextSizes );
	enforce(ss >=0, "QueryContextAttributes failed");

    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    writefln("InitializeSecurityContext result = 0x%08x", ss);

    //--------------------------------------------------------------------
    //   decrypt and display the message from the server.

    enforce(receiveBytes( Client_Socket, Data, BIG_BUFF, &cbRead),"No response from server");
	enforce(cbRead > 0, "zero bytes received");

	auto cbSecurityTrailer = cast(DWORD) data[0..2];
	auto trailer = data[0 .. cbSecurityTrailer - 2];
	data = data [cbSecurityTrailer +2 .. $];
	auto message = client.decrypt(data, trailer);

    writefln("The message from the server is \n %s", message);

	client.dispose();
    return 0;
}

//--------------------------------------------------------------------
//  connectAuthSocket establishes an authenticated socket connection 
//  with a server and initializes needed security package resources.

Socket createAuthenticatedSocket(string serverName, ushort serverPort, CredHandle* hCred, _SecHandle *hcText)
{
	import std.socket : getAddressInfo, AddressFamily, Socket;
	import std.algorithm : filter;
	import std.array : array;
	import std.range : front;

    hostent *pHost;
    SOCKADDR_IN sin;

    //--------------------------------------------------------------------
    //  Lookup the server's address.

    auto addressInfos = getAddressInfo(serverName)
						.filter!(info => info.family == AddressFamily.INET)
						.array;

	auto address = new InternetAddress(serverName, serverPort);
    //--------------------------------------------------------------------
    //  Create the socket.

    Socket socket = new Socket(addressInfos.front);
	socket.connect(address);	
    enforce(doAuthentication(socket), "authentication");
    return socket;
}

bool doAuthentication(Socket s)
{
    bool        fDone = false;
    DWORD       cbOut = 0;
    DWORD       cbIn = 0;

    auto pInBuf = new ubyte[cbMaxMessage];
    auto pOutBuf = new ubyte[cbMaxMessage];

    cbOut = cbMaxMessage;
    if (!genClientContext ( null, 0, pOutBuf,  &cbOut, &fDone, TargetName, &hCred, &hcText))
    {
        return(false);
    }

    enforce(sendMessage (s, pOutBuf.ptr, cbOut ),"send message failed");

    while (!fDone) 
    {
        enforce(receiveMessage ( s, pInBuf,  cbMaxMessage, &cbIn),"receive message failed");

        cbOut = cbMaxMessage;

        enforce(genClientContext ( pInBuf,  cbIn, pOutBuf, &cbOut, &fDone, TargetName, &hCred, &hcText),"genClientContext failed");
        enforce(sendMessage ( s, pOutBuf, cbOut), "send message 2 failed");
    }

    return true;
}

bool genClientContext (ubyte *pIn, DWORD cbIn, ubyte* pOut, DWORD* pcbOut, bool* pfDone, CHAR* pszTarget, CredHandle *hCred,
_SecHandle *hcText)
{
    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    SecBufferDesc     OutBuffDesc;
    SecBuffer         OutSecBuff;
    SecBufferDesc     InBuffDesc;
    SecBuffer         InSecBuff;
    ULONG             ContextAttributes;
    static TCHAR[1024]      lpPackageName;

    if( pIn is null)
    {   
        strcpy_s(lpPackageName, 1024 * sizeof(TCHAR), "Negotiate");
        ss = AcquireCredentialsHandle (
            null, 
            lpPackageName,
            SECPKG_CRED_OUTBOUND,
            null, 
            null, 
            null, 
            null, 
            hCred,
            &Lifetime);

        enforce(SEC_SUCCESS (ss), "acquireCred failed");
    }

    //--------------------------------------------------------------------
    //  Prepare the buffers.

    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers  = 1;
    OutBuffDesc.pBuffers  = &OutSecBuff;

    OutSecBuff.cbBuffer   = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer   = pOut;

    //-------------------------------------------------------------------
    //  The input buffer is created only if a message has been received 
    //  from the server.

    if (pIn)   
    {
        InBuffDesc.ulVersion = 0;
        InBuffDesc.cBuffers  = 1;
        InBuffDesc.pBuffers  = &InSecBuff;

        InSecBuff.cbBuffer   = cbIn;
        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.pvBuffer   = pIn;

        ss = InitializeSecurityContext (
            hCred,
            hcText,
            pszTarget,
            MessageAttribute, 
            0,
            SECURITY_NATIVE_DREP,
            &InBuffDesc,
            0, 
            hcText,
            &OutBuffDesc,
            &ContextAttributes,
            &Lifetime);
    }
    else
    {
        ss = InitializeSecurityContext (
            hCred,
            null,
            pszTarget,
            MessageAttribute, 
            0, 
            SECURITY_NATIVE_DREP,
            null,
            0, 
            hcText,
            &OutBuffDesc,
            &ContextAttributes,
            &Lifetime);
    }

    if (!SEC_SUCCESS (ss))  
    {
        MyHandleError ("InitializeSecurityContext failed " );
    }

    //-------------------------------------------------------------------
    //  If necessary, complete the token.

    if ((SEC_I_COMPLETE_NEEDED == ss) 
        || (SEC_I_COMPLETE_AND_CONTINUE == ss))  
    {
        ss = CompleteAuthToken (hcText, &OutBuffDesc);
        if (!SEC_SUCCESS(ss))  
        {
            fwritef (stderr, "complete failed: 0x%08x\n", ss);
            return false;
        }
    }

    *pcbOut = OutSecBuff.cbBuffer;

    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||
        (SEC_I_COMPLETE_AND_CONTINUE == ss));

    writef ("Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
    printHexDump (OutSecBuff.cbBuffer, (ubyte*)OutSecBuff.pvBuffer);
    return true;
}

ubyte* decryptThis(ubyte* pBuffer, LPDWORD pcbMessage, _SecHandle *hCtxt, ulong cbSecurityTrailer)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    ubyte*             pSigBuffer;
    ubyte*             pDataBuffer;
    DWORD             SigBufferSize;

    //-------------------------------------------------------------------
    //  By agreement, the server encrypted the message and set the size
    //  of the trailer block to be just what it needed. decryptMessage 
    //  needs the size of the trailer block. 
    //  The size of the trailer is in the first DWORD of the
    //  message received. 

    SigBufferSize = *((DWORD *) pBuffer);
    writefln("data before decryption including trailer (%lu bytes):", *pcbMessage);
    printHexDump(*pcbMessage, pBuffer);

    //--------------------------------------------------------------------
    //  By agreement, the server placed the trailer at the beginning 
    //  of the message that was sent immediately following the trailer 
    //  size DWORD.

    pSigBuffer = pBuffer + DWORD.sizeof;

    //--------------------------------------------------------------------
    //  The data comes after the trailer.

    pDataBuffer = pSigBuffer + SigBufferSize;

    //--------------------------------------------------------------------
    //  *pcbMessage is reset to the size of just the encrypted bytes.

    *pcbMessage = *pcbMessage - SigBufferSize - DWORD.sizeof;

    //--------------------------------------------------------------------
    //  Prepare the buffers to be passed to the decryptMessage function.

    BuffDesc.ulVersion    = 0;
    BuffDesc.cBuffers     = 2;
    BuffDesc.pBuffers     = SecBuff;

    SecBuff[0].cbBuffer   = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer   = pSigBuffer;

    SecBuff[1].cbBuffer   = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer   = pDataBuffer;

    ss = decryptMessage(
        hCtxt,
        &BuffDesc,
        0,
        &ulQop);

    if (!SEC_SUCCESS(ss)) 
    {
        stderr.writefln("decryptMessage failed");
    }

    //-------------------------------------------------------------------
    //  Return a pointer to the decrypted data. The trailer data
    //  is discarded.

    return pDataBuffer;

}

ubyte* verifyThis( ubyte*   pBuffer, LPDWORD pcbMessage, _SecHandle *hCtxt, ULONG   cbMaxSignature)
{

    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    ubyte*             pSigBuffer;
    ubyte*             pDataBuffer;

    //-------------------------------------------------------------------
    //  The global cbMaxSignature is the size of the signature
    //  in the message received.

    writefln("data before verifying (including signature):");
    printHexDump (*pcbMessage, pBuffer);

    //--------------------------------------------------------------------
    //  By agreement with the server, 
    //  the signature is at the beginning of the message received,
    //  and the data that was signed comes after the signature.

    pSigBuffer = pBuffer;
    pDataBuffer = pBuffer + cbMaxSignature;

    //-------------------------------------------------------------------
    //  The size of the message is reset to the size of the data only.

    *pcbMessage = *pcbMessage - (cbMaxSignature);

    //--------------------------------------------------------------------
    //  Prepare the buffers to be passed to the signature verification 
    //  function.

    BuffDesc.ulVersion    = 0;
    BuffDesc.cBuffers     = 2;
    BuffDesc.pBuffers     = SecBuff;

    SecBuff[0].cbBuffer   = cbMaxSignature;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer   = pSigBuffer;

    SecBuff[1].cbBuffer   = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer   = pDataBuffer;

    ss = verifySignature(
        hCtxt,
        &BuffDesc,
        0,
        &ulQop
        );

    if (!SEC_SUCCESS(ss)) 
    {
        stderr.writefln("verifyMessage failed");
    }
    else
    {
        writefln("Message was properly signed.");
    }

    return pDataBuffer;

}  // end verifyThis


void printHexDump( DWORD length, ubyte* buffer)
{
    DWORD i,count,index;
    CHAR rgbDigits[]="0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;

    for(index = 0; length;
        length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        swritef_s(rgbLine, 100, "%4.4x  ",index);
        cbLine = 6;

        for(i=0;i<count;i++) 
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if(i == 7) 
            {
                rgbLine[cbLine++] = ':';
            } 
            else 
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for(; i < 16; i++) 
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for(i = 0; i < count; i++) 
        {
            if(buffer[i] < 32 || buffer[i] > 126) 
            {
                rgbLine[cbLine++] = '.';
            } 
            else 
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        writef("%s\n", rgbLine);
    }
}

bool sendMessage ( SOCKET  s, ubyte*   pBuf, DWORD   cbBuf)
{
    if (0 == cbBuf)
        return(true);

    //----------------------------------------------------------
    //  Send the size of the message.

    if (!sendBytes (s, (ubyte*)&cbBuf, sizeof (cbBuf)))
        return(false);

    //----------------------------------------------------------
    //  Send the body of the message.

    if (!sendBytes (
        s, 
        pBuf, 
        cbBuf))
    {
        return(false);
    }

    return(true);
}    

bool receiveMessage (SOCKET s, ubyte* pBuf, DWORD cbBuf, DWORD* pcbRead)

{
    DWORD cbRead;
    DWORD cbData;

    //----------------------------------------------------------
    //  Receive the number of bytes in the message.

    if (!receiveBytes (
        s, 
        (ubyte*)&cbData, 
        sizeof (cbData), 
        &cbRead))
    {
        return(false);
    }

    if (sizeof (cbData) != cbRead)
        return(false);
    //----------------------------------------------------------
    //  Read the full message.

    if (!receiveBytes (
        s, 
        pBuf, 
        cbData, 
        &cbRead))
    {
        return(false);
    }

    if (cbRead != cbData)
        return(false);

    *pcbRead = cbRead;
    return(true);
}  // end ReceiveMessage    

bool sendBytes ( SOCKET  s, ubyte*   pBuf, DWORD   cbBuf)
{
    ubyte* pTemp = pBuf;
    int   cbSent;
    int   cbRemaining = cbBuf;

    if (0 == cbBuf)
        return(true);

    while (cbRemaining) 
    {
        cbSent = send (
            s, 
            (const char *)pTemp, 
            cbRemaining, 
            0);
        if (SOCKET_ERROR == cbSent) 
        {
            fwritef (stderr, "send failed: %u\n", GetLastError ());
            return false;
        }

        pTemp += cbSent;
        cbRemaining -= cbSent;
    }

    return true;
}

bool receiveBytes ( SOCKET  s, ubyte*   pBuf, DWORD   cbBuf, DWORD  *pcbRead)
{
    ubyte* pTemp = pBuf;
    int cbRead, cbRemaining = cbBuf;

    while (cbRemaining) 
    {
        cbRead = recv ( s, (char *)pTemp, cbRemaining, 0);
        if (0 == cbRead)
            break;
        if (SOCKET_ERROR == cbRead) 
        {
            fwritef (stderr, "recv failed: %u\n", GetLastError ());
            return false;
        }

        cbRemaining -= cbRead;
        pTemp += cbRead;
    }

    *pcbRead = cbBuf - cbRemaining;

    return true;
}  // end receiveBytes


