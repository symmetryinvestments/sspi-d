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
enum MessageAttribute = IscReq.confidentiality;

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

	auto user = getUserName();
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

	auto securityPackageNegotiationInfo = queryContextAttributes!SecPkgContext_NegotiationInfoW(&client.context, SecPackageAttribute.negotiationInfo);
	writefln("Package Name: %s", securityPackageNegotiationInfo.packageInfo.Name);

    auto securityPackageAttrSizes = queryContextAttributes!SecPkgContext_Sizes(&client.context, SecPackageAttribute.sizes);

    auto cbMaxSignature = securityPackageAttrSizes.cbMaxSignature;
    auto cbSecurityTrailer = securityPackageAttrSizes.cbSecurityTrailer;

    //--------------------------------------------------------------------
    //   decrypt and display the message from the server.

    auto data = socket.receiveBytes();

    writefln("data before decryption including trailer (%s bytes):", data.length);
    printHexDump(data);
	cbSecurityTrailer = (*(cast(ulong*) data.ptr)).to!uint;
	auto trailer = data[0 .. cbSecurityTrailer - 4];
	data = data [cbSecurityTrailer +4 .. $];
	auto message = client.decrypt(data.to!string, trailer.to!string);

    writefln("The message from the server is \n %s", message);

	client.dispose();
    return 0;
}

//--------------------------------------------------------------------
//  connectAuthSocket establishes an authenticated socket connection 
//  with a server and initializes needed security package resources.

Socket createAuthenticatedSocket(ref ClientAuth client, string serverName, ushort serverPort)
{
	import std.socket : getAddressInfo, AddressFamily, Socket, InternetAddress;
	import std.algorithm : filter;
	import std.array : array;
	import std.range : front;

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
    socket.sendMessage(message);
	message = socket.receiveMessage().idup;
	auto result = client.genClientContext(message);
	socket.sendMessage(result);
    return socket;
}


auto genClientContext(ref ClientAuth client, const(ubyte)[] bufIn)
{
	import std.exception : enforce;
	import std.stdio : writefln;
	import std.conv : to;

	auto result = client.authorize(bufIn);
	enforce(result[0] == SecurityStatus.okay, result.to!string);
    writefln("Token buffer generated (%s bytes):", result[1].length);
    printHexDump(result[1]);
    return result[1];
}



void printHexDump(const(ubyte)[] buf)
{
	import std.format : format;
	import std.stdio : writefln;

    size_t i,count,index;
    char[] rgbDigits = "0123456789abcdef".dup;
    char[100] rgbLine;
    char cbLine;
	auto length = buf.length;
	char* buffer = cast(char*)buf.ptr;

    for(index = 0; length;
        length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        rgbLine = format!"%4.4x  "(index);
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
        writefln("%s", rgbLine);
    }
}

void sendMessage(Socket socket, const(ubyte)[] message)
{
	import std.conv : to;
	auto messageLength = message.length.to!ulong;
	socket.sendBytes((cast(ubyte*)&messageLength)[0..4]);
	socket.sendBytes(message);
}

ubyte[] receiveMessage(Socket socket)
{
	import std.conv : to;
	import std.exception : enforce;

	ubyte[4] messageLengthBuf;
	enforce(socket.receive(messageLengthBuf) ==4);
	size_t messageLength = (*(cast(ulong*)(messageLengthBuf.ptr))).to!size_t;
	auto message = socket.receiveBytes(messageLength);
	return message;
}

void sendBytes(Socket socket, const(ubyte)[] buf)
{
    size_t numBytesRemaining = buf.length;
	size_t numBytesSent = 0;

    if (buf.length == 0)
        return;

    while(numBytesRemaining > 0)
    {
        auto cbSent = socket.send(buf[numBytesSent .. $]);
        numBytesSent += cbSent;
        numBytesRemaining -= cbSent;
    }
}

ubyte[] receiveBytes(Socket socket, size_t messageLength = 0)
{
	import std.array : Appender;
	import std.conv : to;

	Appender!(ubyte[]) ret;
	ubyte[1024] buf;
    long cbRead, cbRemaining = messageLength.to!long;

    while(cbRemaining > 0)
    {
        cbRead = socket.receive(buf);
		ret.put(buf[0 .. cbRead.to!size_t]);
        cbRemaining -= cbRead;
    }
    return ret.data;
}


