module server;
version(Windows):
import sspi;
import std.socket : Socket;
import core.sys.windows.ntsecpkg : SECURITY_NATIVE_DREP;

enum BackLog = 10;

//  Port of Microsoft example for server-side SSPI Windows Sockets program.

int main(string[] args)
{
	import std.conv : to;
	import std.stdio : writefln;

	ushort serverPort = (args.length > 1) ? args[1].to!ushort : 9000.to!ushort;
	auto serverAuth = ServerAuth(); // "Negotiate", ServerAuth.DefaultSecurityContextFlags, SECURITY_NATIVE_DREP);
	serverAuth.setup();
	auto maxMessageSize = serverAuth.packageInfo.cbMaxToken;
	ubyte[] inBuf = new ubyte[maxMessageSize];
	ubyte[] outBuf = new ubyte[maxMessageSize];


	//-----------------------------------------------------------------   
	//  Start looping for clients.

	while(true)
	{
		writefln("Waiting for client to connect...");

		//  Make an authenticated connection with client.
		auto socket = serverAuth.acceptAuthSocket(serverPort);
		auto securityPackageContextSizes = queryContextAttributes!SecPkgContext_Sizes(&serverAuth.context,SecPackageAttribute.sizes);
		//----------------------------------------------------------------
		//  The following values are used for encryption and signing.

		auto cbMaxSignature = securityPackageContextSizes.cbMaxSignature;
		auto cbSecurityTrailer = securityPackageContextSizes.cbSecurityTrailer;

		auto securityPackageNegInfo = queryContextAttributes!SecPkgContext_NegotiationInfoW(&serverAuth.context,SecPackageAttribute.negotiationInfo);
		writefln("Package Name: %s", securityPackageNegInfo.packageInfo.Name);
		
		// impersonate the client
		auto userName = serverAuth.impersonate();
		writefln("Impersonation worked.");
		writefln("Client connected as: %s",userName);

		// Revert to self.
		serverAuth.revertImpersonate();
		writefln("Reverted to self.");

		// Send the client an encrypted message.
		auto message = "This is your server speaking";
		auto encryptedMessage = serverAuth.encrypt(message);

		//-----------------------------------------------------------------   
		//  Send the encrypted data to client.

		socket.sendBytes(encryptedMessage);
		writefln(" %s encrypted bytes sent.", encryptedMessage.length);
		serverAuth.dispose();
		serverAuth = ServerAuth("Negotiate", ServerAuth.DefaultSecurityContextFlags, SECURITY_NATIVE_DREP);
		serverAuth.setup();
	}

	//writefln("Server ran to completion without error.");
}

Socket acceptAuthSocket(ref ServerAuth server, ushort serverPort)
{
	import std.socket : getAddressInfo, AddressFamily, Socket, InternetAddress;
	import std.algorithm : filter;
	import std.array : array;
	import std.range : front;
	import std.exception : enforce;
	import std.conv : to;

    //  Lookup the server's address.
    auto addressInfos = getAddressInfo("0.0.0.0")
						.filter!(info => info.family == AddressFamily.INET)
						.array;

	auto address = new InternetAddress("0.0.0.0", serverPort);

    //  Create the socket.
    Socket socket = new Socket(addressInfos.front);
	socket.bind(address);

	// Listen
	socket.listen(BackLog);
	auto client = socket.accept();
	socket.close();

    auto messageResult = server.authorize();
	enforce(messageResult[0] == SecurityStatus.okay);
	auto message = messageResult[1];
    client.sendMessage(message);
	message = socket.receiveMessage().idup;
	auto result = server.authorize(message);
	enforce(result[0] == SecurityStatus.okay, result[0].to!string);
	client.sendMessage(result[1]);
    return client;
}


void printHexDump(const(ubyte)[] buf)
{
	import std.stdio : writefln;
	import std.format : format;

    size_t i,count,index;
    char[] rgbDigits="0123456789abcdef".dup;
    char[100] rgbLine;
    char cbLine;
	auto length = buf.length;
	char* buffer = cast(char*)buf.ptr;

    for(index = 0; length; length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        rgbLine = format!"%s4.4x  "(index);
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
	import std.exception : enforce;
	import std.conv : to;

	ubyte[4] messageLengthBuf;
	enforce(socket.receive(messageLengthBuf) ==4);
	auto messageLength = (*(cast(ulong*)(messageLengthBuf.ptr))).to!size_t;
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
    long cbRead, cbRemaining = messageLength;

    while (cbRemaining) 
    {
        cbRead = socket.receive(buf);
		ret.put(buf[0 .. cbRead.to!size_t]);
        cbRemaining -= cbRead;
    }
    return ret.data;
}


