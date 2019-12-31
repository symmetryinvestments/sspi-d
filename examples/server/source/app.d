module server;
import sspi;

//  Port of Microsoft example for server-side SSPI Windows Sockets program.

enum usPort = 2000;

//#include <windows.h>
//#include <winsock.h>
//#include <stdio.h>
//#include <stdlib.h>

CredHandle hcred;
_SecHandle  hctxt;

static ubyte* g_pInBuf = null;
static ubyte* g_pOutBuf = null;
static DWORD g_cbMaxMessage;
static TCHAR[1024] g_lpPackageName;

int main(string[] args)
{
	char[200] pMessage;
	DWORD cbMessage;
	PBYTE pDataToClient = null;
	DWORD cbDataToClient = 0;
	PCHAR pUserName = null;
	DWORD cbUserName = 0;
	SOCKET Server_Socket;
	WSADATA wsaData;
	SECURITY_STATUS ss;
	PSecPkgInfo pkgInfo;
	SecPkgContext_Sizes SecPkgContextSizes;
	SecPkgContext_NegotiationInfo SecPkgNegInfo;
	ULONG cbMaxSignature;
	ULONG cbSecurityTrailer;

	//-----------------------------------------------------------------   
	//  Set the default package to negotiate.

	strcpy_s(g_lpPackageName, 1024 * sizeof(TCHAR), "Negotiate");

	//-----------------------------------------------------------------   
	//  Initialize the socket interface and the security package.

	if( WSAStartup (0x0101, &wsaData))
	{
		fwritef (stderr, "Could not initialize winsock: \n");
		cleanup();
	}

	ss = QuerySecurityPackageInfo(g_lpPackageName,&pkgInfo);

	if (!SEC_SUCCESS(ss)) 
	{
		 stderr.writefln("Could not query package info for %s, error 0x%08x", g_lpPackageName, ss);
		 cleanup();  
	}

	g_cbMaxMessage = pkgInfo.cbMaxToken;

	FreeContextBuffer(pkgInfo);

	g_pInBuf = (PBYTE) malloc (g_cbMaxMessage);
	g_pOutBuf = (PBYTE) malloc (g_cbMaxMessage);
	   
	if (null == g_pInBuf || null == g_pOutBuf)
	{
		 fwritef (stderr, "Memory allocation error.\n");
		  cleanup();
	}

	//-----------------------------------------------------------------   
	//  Start looping for clients.

	while(true)
	{
		writefln("Waiting for client to connect...");

	//-----------------------------------------------------------------   
	//  Make an authenticated connection with client.


		if (!acceptAuthSocket (&Server_Socket))
		{
			fwritef (stderr, "Could not authenticate the socket.\n");
			cleanup();
		}
		  
		ss = QueryContextAttributes(
			   &hctxt,
			   SECPKG_ATTR_SIZES,
			   &SecPkgContextSizes );

		if (!SEC_SUCCESS(ss))  
		{
			fwritef (stderr, "QueryContextAttributes failed: 0x%08x\n", ss);
			exit(1);
		}

		//----------------------------------------------------------------
		//  The following values are used for encryption and signing.

		cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
		cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

		ss = QueryContextAttributes(
			  &hctxt,
			  SECPKG_ATTR_NEGOTIATION_INFO,
			  &SecPkgNegInfo );

		if (!SEC_SUCCESS(ss))  
		{
			  fwritef (stderr, "QueryContextAttributes failed: 0x%08x\n", ss);
			  exit(1);
		}
		else
		{
			  writefln("Package Name: %s", SecPkgNegInfo.PackageInfo.Name);
		}

		//----------------------------------------------------------------
		//  Free the allocated buffer.

		FreeContextBuffer(SecPkgNegInfo.PackageInfo);

		//-----------------------------------------------------------------   
		//  Impersonate the client.

		  ss = ImpersonateSecurityContext (&hctxt);
		  if (!SEC_SUCCESS(ss)) 
		  {
			 fwritef (stderr, "Impersonate failed: 0x%08x\n", ss);
			 cleanup();
		  }
		  else
		  {
			   writefln("Impersonation worked.");
		  }

		  GetUserName (null, &cbUserName);
		  pUserName = (PCHAR) malloc (cbUserName);

		  if (!pUserName)
		  {
			fwritef (stderr, "Memory allocation error. \n");
			cleanup();
		  }

		  if (!GetUserName (
			 pUserName, 
			 &cbUserName))
		  {
			fwritef (stderr, "Could not get the client name. \n");
			cleanup();
		  }
		  else
		  {
			writefln ("Client connected as :  %s", pUserName);
		  }

		//-----------------------------------------------------------------   
		//  Revert to self.

		  ss = RevertSecurityContext (&hctxt);
		  if (!SEC_SUCCESS(ss)) 
		  {
			 fwritef (stderr, "Revert failed: 0x%08x\n", ss);
			 cleanup();
		  }
		  else
		  {
			  writefln("Reverted to self.");
		  }

		//-----------------------------------------------------------------   
		//  Send the client an encrypted message.

		  strcpy_s(pMessage, sizeof(pMessage), "This is your server speaking");
		  cbMessage = strlen(pMessage);

		  encryptThis( (PBYTE) pMessage, cbMessage, &pDataToClient, &cbDataToClient, cbSecurityTrailer);

		//-----------------------------------------------------------------   
		//  Send the encrypted data to client.


		  if (!sendBytes( Server_Socket, pDataToClient, cbDataToClient))
		  {
			 writefln("send message failed.");
			 cleanup();
		  }

		  writefln(" %d encrypted bytes sent.", cbDataToClient);

		  if (Server_Socket)
		  {
			DeleteSecurityContext (&hctxt);
			FreeCredentialHandle (&hcred);
			shutdown (Server_Socket, 2) ; 
			closesocket (Server_Socket);
			Server_Socket = 0;
		  }
		  
		  if (pUserName)
		  {
			 free (pUserName);
			 pUserName = null;
			 cbUserName = 0;
		  }
		  if(pDataToClient)
		  {
			 free (pDataToClient);
			 pDataToClient = null;
			 cbDataToClient = 0;
		  }
	}  // end while loop

	writefln("Server ran to completion without error.");
	cleanup(); 
}  // end main

bool acceptAuthSocket (SOCKET *ServerSocket)
	{
		SOCKET sockListen;
		SOCKET sockClient;
		SOCKADDR_IN sockIn;

		//-----------------------------------------------------------------   
		//  Create listening socket.

		sockListen = socket (
		   PF_INET, 
		   SOCK_STREAM, 
		   0);
		   
		if (INVALID_SOCKET == sockListen)  
		{
		   fwritef (stderr, "Failed to create socket: %u\n", GetLastError ());
		   return(false);
		}
		   
		//-----------------------------------------------------------------   
		//  Bind to local port.

		sockIn.sin_family = AF_INET;
		sockIn.sin_addr.s_addr = 0;
		sockIn.sin_port = htons(usPort);
		 
		if (SOCKET_ERROR == bind ( sockListen, (LPSOCKADDR) &sockIn, sizeof (sockIn)))  
		{
			fwritef (stderr, "bind failed: %u\n", GetLastError ());
			return(false);
		}
		   
		//-----------------------------------------------------------------   
		//  Listen for client.
		   
		if (SOCKET_ERROR == listen (sockListen, 1))  
		{
		   fwritef (stderr, "Listen failed: %u\n", GetLastError ());
		   return(false);
		}
		else
		{
		   writefln("Listening !");
		}

		//-----------------------------------------------------------------   
		//  accept client.
		   
		sockClient = accept ( sockListen, null, null); 
		if (INVALID_SOCKET == sockClient)  
		{
			fwritef (stderr, "accept failed: %u\n", GetLastError ());
			return(false);
		}
		   
		closesocket (sockListen);

		*ServerSocket = sockClient;
	   
	return(DoAuthentication (sockClient));

}  // end acceptAuthSocket  

	bool DoAuthentication (SOCKET AuthSocket)
	{
	SECURITY_STATUS   ss;
	DWORD cbIn,       cbOut;
	bool              done =   false;
	TimeStamp         Lifetime;
	bool              fNewConversation;

	fNewConversation = true;

	ss = AcquireCredentialsHandle (
		   null, 
		   g_lpPackageName,
		   SECPKG_CRED_INBOUND,
		   null, 
		   null, 
		   null, 
		   null, 
		   &hcred,
		   &Lifetime);

	if (!SEC_SUCCESS (ss))
	{
		   fwritef (stderr, "AcquireCreds failed: 0x%08x\n", ss);
		   return(false);
	}

	while(!done) 
	{
	   if (!receiveMessage (
		 AuthSocket, 
		 g_pInBuf, 
		 g_cbMaxMessage, 
		 &cbIn))
	   {
		  return(false);
	   }
	   
	   cbOut = g_cbMaxMessage;

		if (!genServerContext (
		   g_pInBuf, 
		   cbIn, 
		   g_pOutBuf, 
		   &cbOut, 
		   &done,
		   fNewConversation))
	   {
			fwritef(stderr,"genServerContext failed.\n");
			return(false);
		}
		fNewConversation = false;
		if (!sendMessage (
			AuthSocket, 
			g_pOutBuf, 
			cbOut))
		{
			fwritef(stderr,"Sending message failed.\n");
			return(false);
		}
	} 

	return(true);
}  // end DoAuthentication

bool genServerContext ( BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, bool *pfDone, bool fNewConversation)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             Attribs = 0;
	 
	//----------------------------------------------------------------
	//  Prepare output buffers.

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	//----------------------------------------------------------------
	//  Prepare input buffers.

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn;
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn;

	writefln ("Token buffer received (%lu bytes):", InSecBuff.cbBuffer);
	printHexDump (InSecBuff.cbBuffer, (PBYTE)InSecBuff.pvBuffer);

	ss = acceptSecurityContext (
		   &hcred,
		   fNewConversation ? null : &hctxt,
		   &InBuffDesc,
		   Attribs, 
		   SECURITY_NATIVE_DREP,
		   &hctxt,
		   &OutBuffDesc,
		   &Attribs,
		   &Lifetime);

	if (!SEC_SUCCESS (ss))  
	{
		fwritef (stderr, "acceptSecurityContext failed: 0x%08x\n", ss);
		return false;
	}

	//----------------------------------------------------------------
	//  Complete token if applicable.
	   
	if ((SEC_I_COMPLETE_NEEDED == ss) 
	   || (SEC_I_COMPLETE_AND_CONTINUE == ss))  
	{
		ss = CompleteAuthToken (&hctxt, &OutBuffDesc);
		if (!SEC_SUCCESS(ss))  
	   {
		   fwritef (stderr, "complete failed: 0x%08x\n", ss);
		   return false;
		}
	}

	*pcbOut = OutSecBuff.cbBuffer;

	//  fNewConversation equals false.

	writefln ("Token buffer generated (%lu bytes):", OutSecBuff.cbBuffer);
	printHexDump (
	   OutSecBuff.cbBuffer, 
	   (PBYTE)OutSecBuff.pvBuffer);

	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) 
	   || (SEC_I_COMPLETE_AND_CONTINUE == ss));

	writefln("acceptSecurityContext result = 0x%08x", ss);

	return true;

	}  // end genServerContext


bool encryptThis ( PBYTE pMessage, ULONG cbMessage, BYTE ** ppOutput, ULONG * pcbOutput, ULONG cbSecurityTrailer)
{
	SECURITY_STATUS   ss;
	SecBufferDesc     BuffDesc;
	SecBuffer         SecBuff[2];
	ULONG             ulQop = 0;
	ULONG             SigBufferSize;

	//-----------------------------------------------------------------
	//  The size of the trailer (signature + padding) block is 
	//  determined from the global cbSecurityTrailer.

	SigBufferSize = cbSecurityTrailer;

	writefln("Data before encryption: %s", pMessage);
	writefln("Length of data before encryption: %d",cbMessage);

	//-----------------------------------------------------------------
	//  Allocate a buffer to hold the signature,
	//  encrypted data, and a DWORD  
	//  that specifies the size of the trailer block.

	* ppOutput = (PBYTE) malloc (
	 SigBufferSize + cbMessage + sizeof(DWORD));

	//------------------------------------------------------------------
	//  Prepare buffers.

	BuffDesc.ulVersion = 0;
	BuffDesc.cBuffers = 2;
	BuffDesc.pBuffers = SecBuff;

	SecBuff[0].cbBuffer = SigBufferSize;
	SecBuff[0].BufferType = SECBUFFER_TOKEN;
	SecBuff[0].pvBuffer = *ppOutput + sizeof(DWORD);

	SecBuff[1].cbBuffer = cbMessage;
	SecBuff[1].BufferType = SECBUFFER_DATA;
	SecBuff[1].pvBuffer = pMessage;

	ss = encryptMessage(
		&hctxt,
		ulQop,
		&BuffDesc,
		0);

	if (!SEC_SUCCESS(ss)) 
	{
	   fwritef (stderr, "encryptMessage failed: 0x%08x\n", ss);
	   return(false);
	}
	else
	{
	   writefln("The message has been encrypted.");
	}

	//------------------------------------------------------------------
	//  Indicate the size of the buffer in the first DWORD. 

	*((DWORD *) *ppOutput) = SecBuff[0].cbBuffer;

	//-----------------------------------------------------------------
	//  Append the encrypted data to our trailer block
	//  to form a single block. 
	//  Putting trailer at the beginning of the buffer works out 
	//  better. 

	memcpy (*ppOutput+SecBuff[0].cbBuffer+sizeof(DWORD), pMessage,
		cbMessage);

	*pcbOutput = cbMessage + SecBuff[0].cbBuffer + sizeof(DWORD);

	writefln ("data after encryption including trailer (%lu bytes):", *pcbOutput);
	printHexDump (*pcbOutput, *ppOutput);

	return true;

}  // end encryptThis



void printHexDump(DWORD length, PBYTE buffer)
{
	DWORD i,count,index;
	CHAR rgbDigits[]="0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;

	for(index = 0; length;
	   length -= count, buffer += count, index += count) 
	{
	   count = (length > 16) ? 16:length;

	   swritefln_s(rgbLine, 100, "%4.4x  ",index);
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
}  // end printHexDump


bool sendMessage ( SOCKET s, PBYTE pBuf, DWORD cbBuf)
{
	if (0 == cbBuf)
	   return(true);

	//----------------------------------------------------------------
	//  Send the size of the message.

	if (!sendBytes ( s, (PBYTE)&cbBuf, sizeof (cbBuf)))
	{
		return(false);
	}

	//----------------------------------------------------------------    
	//  Send the body of the message.

	if (!sendBytes ( s, pBuf, cbBuf))
	{
		return(false);
	}

	return(true);
} // end sendMessage    

bool receiveMessage ( SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead)
{
	DWORD cbRead;
	DWORD cbData;

	//-----------------------------------------------------------------
	//  Retrieve the number of bytes in the message.

	if (!receiveBytes ( s, (PBYTE)&cbData, sizeof (cbData), &cbRead))
	{
	  return(false);
	}

	if (sizeof (cbData) != cbRead)
	{
	   return(false);
	}

	//----------------------------------------------------------------
	//  Read the full message.

	if (!receiveBytes ( s, pBuf, cbData, &cbRead))
	{
	   return(false);
	}

	if (cbRead != cbData)
	{
	  return(false);
	}

	*pcbRead = cbRead;

	return(true);
}  // end receiveMessage    

bool sendBytes ( SOCKET s, PBYTE pBuf, DWORD cbBuf)
{
	PBYTE pTemp = pBuf;
	int cbSent, cbRemaining = cbBuf;

	if (0 == cbBuf)
	{
	   return(true);
	}

	while (cbRemaining) 
	{
		cbSent = send ( s, (const char *)pTemp, cbRemaining, 0);
		if (SOCKET_ERROR == cbSent) 
		{
		   fwritef (stderr, "send failed: %u\n", GetLastError ());
		   return false;
		}
		pTemp += cbSent;
		cbRemaining -= cbSent;
	}

	return true;
}  // end sendBytes

bool receiveBytes ( SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead)
{
	PBYTE pTemp = pBuf;
	int cbRead, cbRemaining = cbBuf;

	while (cbRemaining) 
	{
		cbRead = recv ( s, (char *)pTemp, cbRemaining, 0);
		if (0 == cbRead)
		{
			break;
		}

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
}  // end receivesBytes

void cleanup()
{
   if (g_pInBuf)
	  free (g_pInBuf);

   if (g_pOutBuf)
	  free (g_pOutBuf);

   WSACleanup ();
   exit(0);
}
