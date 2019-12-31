module client;
version(Windows):
import sspi;
import std.socket : Socket;
import core.sys.windows.ntsecpkg : SECURITY_NATIVE_DREP;

// Port of MS example of client-side program to establish an SSPI socket connection with a server and exchange messages.


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

int main(string[] args)
{
	import std.stdio : writefln, stderr;
	import std.exception : enforce;
	import std.format : format;
	import std.conv : to;

	auto user = getUser();
	auto client = ClientAuth("NTLM",user);
	string serverName = (args.length > 1) ? args[1] : "127.0.0.1";
	ushort serverPort = (args.length > 2) ? args[2].to!ushort : 9000;

    auto socket = client.createAuthenticatedSocket(serverName, serverPort);

    //--------------------------------------------------------------------
    //   An authenticated session with a server has been established.
    //   Receive and manage a message from the server.
    //   First, find and display the name of the negotiated
    //   SSP and the size of the signature and the encryption 
    //   trailer blocks for this SSP.

	auto securityPackageNegotiationInfo = queryContextAttributes!SecPkgContext_NegotiationInfoW(&client.content, SecPackageAttribute.negotiationInfo);
	writefln("Package Name: %s", securityPackageNegotiationInfo.packageInfo.Name);

    auto securityPackageAttrSizes = queryContextAttributes!SecPkgContextSizes(&client.context, SecPackageAttribute.sizes);

    cbMaxSignature = securityPackageAttrSizes.cbMaxSignature;
    cbSecurityTrailer = securityPackageAttrSizes.cbSecurityTrailer;

    //--------------------------------------------------------------------
    //   decrypt and display the message from the server.

    auto data = socket.receiveBytes();

    writefln("data before decryption including trailer (%s bytes):", data.length);
    printHexDump(data);
	auto cbSecurityTrailer = cast(ulong) data[0..4];
	auto trailer = data[0 .. cbSecurityTrailer - 4];
	data = data [cbSecurityTrailer +4 .. $];
	auto message = client.decrypt(data, trailer);

    writefln("The message from the server is \n %s", message);

	client.dispose();
    return 0;
}

//--------------------------------------------------------------------
//  connectAuthSocket establishes an authenticated socket connection 
//  with a server and initializes needed security package resources.

Socket createAuthenticatedSocket(ref AuthClient client, string serverName, ushort serverPort)
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
    auto message = client.genClientContext([]);
    socket.sendMessage(outbuf);
	message = socket.receiveMessage();
	auto result = client.genClientContext(message);
	socket.sendMessage(result);
    return socket;
}


bool genClientContext(ref ClientAuth client, ubyte[] bufIn)
{
    if (bufIn.length == 0)
    {   
		client.packageInfo = querySecurityPackageInfo("Negotiate");
		client.dataRep = SECURITY_NATIVE_DREP;
		auto result = acquireCredentialsHandle(null,"Negotiate",CredentialDirection.outbound);
		client.credentialsExpiry = result[0];
    }

	auto result = client.authorize(bufIn);
	enforce(result == SecurityStatus.okay, result.to!string);
    writefln("Token buffer generated (%s bytes):", result[1].length);
    printHexDump(result[1]);
    return result[1];
}



void printHexDump(const(ubyte)[] buffer)
{
    size_t i,count,index;
    char[] rgbDigits = "0123456789abcdef".dup;
    char[100] rgbLine;
    char cbLine;
	auto length = buffer.length;

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

void sendMessage(Socket socket, const(ubyte)[] message)
{
	socket.sendBytes(cast(ubyte[0 ..4]) message.length.to!ulong);
	socket.sendBytes(message);
}

ubyte[] receiveMessage(Socket s)

{
	ubyte[4] messageLength;
	enforce(socket.receive(messageLength) ==4);
	messageLength = (cast(ulong)(messageLength[0..4])).to!size_t;
	auto message = socket.receiveBytes(messageLength);
	return message;
}

void sendBytes(Socket socket, const(ubyte)[] buf)
{
    size_t numBytesRemaining = buf.length;
	size_t numBytesSent = 0;

    if (buf.length == 0)
        return true;

    while(numBytesRemaining > 0)
    {
        cbSent = socket.send(buf[numBytesSent .. $]);
        numBytesSent += cbSent;
        numBytesRemaining -= cbSent;
    }
}

ubyte[] receiveBytes(Socket socket, size_t messageLength = 0)
{
	import std.array : Appender;
	Appender!(ubyte[]) ret;
	ubyte[1024] buf;
    ubyte* pTemp = pBuf;
    int cbRead, cbRemaining = messageLength;

    while (cbRemaining) 
    {
        cbRead = socket.receive(buf);
		ret.put(buf[0 .. cbRead]);
        cbRemaining -= cbRead;
        pTemp += cbRead;
    }
    return ret.data;
}


