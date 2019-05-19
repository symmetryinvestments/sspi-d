module sspi;

/+
	Helper classes for SSPI authentication via the win32security module.
	SSPI authentication involves a token-exchange "dance", the exact details
	of which depends on the authentication provider used.  There are also
	a number of complex flags and constants that need to be used - in most
	cases, there are reasonable defaults.
	These classes attempt to hide these details from you until you really need
	to know.  They are not designed to handle all cases, just the common ones.
	If you need finer control than offered here, just use the win32security
	functions directly.
+/

/// Based on Roger Upole's sspi demos.
version(Windows):
import core.sys.windows.ntsecpkg;
import core.sys.windows.sspi;
import core.sys.windows.windef:DWORD;
import sspi.defines;
import sspi.helpers;
import std.datetime:DateTime;
import std.string:toStringz,fromStringz;
import std.conv:to;
import std.typecons:tuple;
import std.utf:toUTF16z;
import std.exception;

struct BaseAuth
{
	SecHandle context;
	CredHandle credentials;
	uint nextSequenceNumber;
	bool isAuthenticated;
	
	/// Reset everything to an unauthorized state
	void reset()
	{
		this.context = SecHandle.init;
		this.isAuthenticated = false;
		this.nextSequenceNumber = 0;
	}

	/// Get the next sequence number for a transmission.  Default implementation is to increment a counter
	auto getNextSequenceNumber()
	{
		auto ret = nextSequenceNumber;
		nextSequenceNumber++;
		return ret;
	}

	auto encrypt(string data)
	{
		// auto packageInfo = context.queryContextAttributes!SecPkgNegInfo(SecPackageAttribute.info);
		auto packageSizes= context.queryContextAttributes!SecPkgContext_Sizes(SecPackageAttribute.sizes);
		auto maxSignatureSize = packageSizes.cbMaxSignature;
		auto trailerSize = packageSizes.cbSecurityTrailer;

		SecBuffer[2] buffers;
		SecBufferDesc bufferDesc;

		bufferDesc.ulVersion = SECBUFFER_VERSION;
		bufferDesc.cBuffers = 2;
		bufferDesc.pBuffers = buffers.ptr;

		// initial DWORD specifies size of trailer block
		ubyte[] outputData;
		outputData.length = trailerSize + data.length + DWORD.sizeof;
		buffers[0].cbBuffer = trailerSize;
		buffers[0].BufferType = SECBUFFER_TOKEN;
		buffers[0].pvBuffer = data.ptr + DWORD.sizeof;

		buffers[1].cbBuffer = data.length.to!uint;
		buffers[1].BufferType = SECBUFFER_DATA;
		buffers[1].pvBuffer = cast(void*)data.ptr;

		context.encryptMessage(0, bufferDesc, getNextSequenceNumber());
		return tuple(buffers[0],buffers[1]);
	}


        /// Decrypt a previously encrypted string, returning the orignal data
	auto decrypt(string data, string trailer)
	{
		SecBuffer[2] buffers;
		SecBufferDesc bufferDesc;

		bufferDesc.ulVersion = SECBUFFER_VERSION;
		bufferDesc.cBuffers = 2;
		bufferDesc.pBuffers = buffers.ptr;

		buffers[0].cbBuffer = trailer.length.to!uint + 1;
		buffers[0].BufferType = SECBUFFER_TOKEN;
		buffers[0].pvBuffer = cast(void*)trailer.toStringz;

		buffers[1].cbBuffer = data.length.to!uint +1; // FIXME - might be null terminated already
		buffers[1].BufferType = SECBUFFER_DATA;
		buffers[1].pvBuffer = cast(void*)data.toStringz;

		auto fQOP = context.decryptMessage(bufferDesc, getNextSequenceNumber());
		return (cast(char*)buffers[0].pvBuffer).fromStringz;
	}

	/// sign a string suitable for transmission, returning the signature.
	/// Passing the data and signature to verify will determine if the data is unchanged.
	string sign(string data)
	{
		auto packageSizes = context.queryContextAttributes!SecPkgContext_Sizes(SecPackageAttribute.sizes);
		auto trailerSize = packageSizes.cbMaxSignature;

		SecBuffer[2] buffers;
		SecBufferDesc bufferDesc;

		bufferDesc.ulVersion = SECBUFFER_VERSION;
		bufferDesc.cBuffers = 2;
		bufferDesc.pBuffers = buffers.ptr;

		buffers[0].cbBuffer = data.length.to!uint +1; // FIXME - might be null terminated already
		buffers[0].BufferType = SECBUFFER_DATA;
		buffers[0].pvBuffer = cast(void*) data.toStringz;

		buffers[1].cbBuffer = trailerSize;
		buffers[1].BufferType = SECBUFFER_TOKEN;
		context.makeSignature(0,bufferDesc,this.getNextSequenceNumber());
		return (cast(char*)buffers[1].cbBuffer).fromStringz.idup;
	}

        /// Verifies data and its signature.  If verification fails, an sspi.error will be raised.
	void verifySignature(string data, string sig)
	{
		SecBuffer[2] buffers;
		SecBufferDesc bufferDesc;
		bufferDesc.ulVersion = SECBUFFER_VERSION;
		bufferDesc.cBuffers = 2;
		bufferDesc.pBuffers = buffers.ptr;

		buffers[0].cbBuffer = data.length.to!uint +1; // FIXME - might be null terminated already
		buffers[0].BufferType = SECBUFFER_DATA;
		buffers[0].pvBuffer = cast(void*) data.toStringz;

		buffers[1].cbBuffer = sig.length.to!uint +1; // FIXME
		buffers[1].BufferType = SECBUFFER_TOKEN;
		buffers[1].pvBuffer = cast(void*) sig.toStringz;

		context.verifySignature(bufferDesc, this.getNextSequenceNumber());
	}
}





struct ClientAuth
{
	BaseAuth base;
	alias base this;

	enum DefaultSecurityContextFlags = 	IscReq.integrity 	| IscReq.sequenceDetect |
						IscReq.replayDetect	| IscReq.confidentiality;

	IscReq securityContextFlags;
	long dataRep;
	string targetSecurityContextProvider;
	SecPkgInfoW* packageInfo;
	TimeStamp credentialsExpiry;
	string packageName;
	uint contextAttr;

	this(string packageName, string clientName, 
		string targetSecurityContextProvider = null,
		IscReq securityContextFlags = DefaultSecurityContextFlags, long dataRep = SECURITY_NETWORK_DREP)
	{
		this.securityContextFlags = securityContextFlags;
		this.dataRep = dataRep;
		this.targetSecurityContextProvider = targetSecurityContextProvider;
		this.packageInfo = querySecurityPackageInfo(packageName);
		auto result = acquireCredentialsHandle(packageName);  // clientName,packageInfo.Name, SECPKG_CRED_OUTBOUND,
		this.credentialsExpiry = result[0];
		this.base.credentials = result[1];
		this.packageName = packageName;
	}


	auto acquireCredentialsHandle(string packageName)
	{
		TimeStamp lifetime;
		SecurityStatus securityStatus = cast(SecurityStatus) AcquireCredentialsHandleW(
									null,
									cast(wchar*) packageName.toUTF16z,
									SECPKG_CRED_OUTBOUND,
									null,
									null,
									null,
									null,
									&this.base.credentials,
									&lifetime);
		enforce(securityStatus.secSuccess, securityStatus.to!string);
		this.credentialsExpiry = lifetime;
		return tuple(lifetime, base.credentials);
	}
	/// Perform *one* step of the server authentication process.
	auto authorize(string data = null)
	{
		SecurityStatus result;
		bool isFirstStage = (data.length == 0);
		ubyte[] retBuf;
		retBuf.length = isFirstStage ? 0 : packageInfo.cbMaxMessage;
		SecBuffer[1] buffersIn, buffersOut;
		SecBufferDesc bufferDescIn, bufferDescOut;
		DWORD cbOut = 0;

		bufferDescOut.ulVersion = SECBUFFER_VERSION;
		bufferDescOut.cBuffers = 1;
		bufferDescOut.pBuffers = buffersOut.ptr;

		buffersOut[0].cbBuffer = cbOut;
		buffersOut[0].BufferType = SECBUFFER_TOKEN;
		buffersOut[0].pvBuffer = retBuf.ptr;

		bufferDescOut.cbBuffer = packageInfo.cbMaxToken;
		bufferDescOut.BufferType = SECBUFFER_TOKEN;

		{
		if(!isFirstStage)
		{
			bufferDescIn.ulVersion = SECBUFFER_VERSION;
			bufferDescIn.cBuffers = 1;
			bufferDescIn.pBuffers = buffersIn.ptr;

			buffersIn[0].cbBuffer = packageInfo.cbMaxToken;
			buffersIn[0].BufferType = SECBUFFER_TOKEN;
			buffersIn[0].pvBuffer = data.toStringz;
			result = initializeSecurityContext(credentials, packageName, context, securityContextFlags, 0,dataRep, buffersIn,bufferDescOut);
		}
		else
		{
			result = initializeSecurityContext(credentials, packageName,context, securityContextFlags, 0,dataRep, null,bufferDescOut);
		}

		this.contextAttr = result[0];
		this.credentialsExpiry = result[1];
		auto securityStatus = result[2];
		this.context = result[3];

		if (securityStatus & SecurityStatus.completeNeeded || securityStatus & SecurityStatus.completeAndContinue)
			context.completeAuthToken(bufferDescOut);
		this.isAuthenticated = (securityStatus ==0);
		return tuple(securityStatus, buffersOut[0]);

	}
}

version(None):
/// Manages the server side of an SSPI authentication handshake
struct ServerAuth
{
	BaseAuth base;
	alias base this;
	string packageName;
	ulong datarap;
	IscReq securityContextFlags;
	void* packageInfo;
	DateTime credentialsExpiry;
	bool isAuthenticated;

	this(string packageName, securityContextFlags = 0UL, ulong datarep = SECURITY_NETWORK_DREP)
	{
		this.packageName = packageName;
		this.datarep = datarep;

		this.securityContextFlags = (securityContextFlags==0) ? 
	    		(ASC_REQ_INTEGRITY|ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT|ASC_REQ_CONFIDENTIALITY) :
			securityContextFlags;
		base = BaseAuth();
	}

	void setup()
	{

		packageInfo = QuerySecurityPackageInfo(packageName);
		this.credentialsExpiry = AcquireCredentialsHandle(packageName, this.packageInfo.Name, SECPKG_CRED_INBOUND, null, null);
	}

	/// Perform *one* step of the server authentication process.
	auto authorize(string data = null)
	{
		SecurityStatus result;
		bool isFirstStage = (data.length == 0);
		ubyte[] retBuf;
		retBuf.length = isFirstStage ? 0 : packageInfo.cbMaxMessage;
		SecBuffer[1] buffersIn, buffersOut;
		SecBufferDesc bufferDescIn, bufferDescOut;
		DWORD cbOut = 0;

		bufferDescOut.ulVersion = SECBUFFER_VERSION;
		bufferDescOut.cBuffers = 1;
		bufferDescOut.pBuffers = buffersOut.ptr;

		buffersOut[0].cbBuffer = cbOut;
		buffersOut[0].BufferType = SECBUFFER_TOKEN;
		buffersOut[0].pvBuffer = retBuf.ptr;

		bufferDescOut.cbBuffer = this.packageInfo.cbMaxToken;
		bufferDescOut.BufferType = SECBUFFER_TOKEN;

		if(!isFirstStage)
		{
			bufferDescIn.ulVersion = SECBUFFER_VERSION;
			bufferDescIn.cBuffers = 1;
			bufferDescIn.pBuffers = buffersIn.ptr;

			buffersIn[0].cbBuffer = this.packageInfo.cbMaxToken;
			buffersIn[0].BufferType = SECBUFFER_TOKEN;
			buffersIn[0].pvBuffer = data.toStringz;
			result = initializeSecurityContext(	credentials, context, buffersIn, securityContextFlags, dataRep, bufferDescOut);
		}
		else
		{
			result = initializeSecurityContext(	credentials, context, null, 	securityContextFlags, dataRep, bufferDescOut);
		}

		this.contextAttr = result[0];
		this.contextExpiry = result[1];
		auto securityStatus = result[2];
		this.context = result[3];

		if (securityStatus & SEC_I_COMPLETE_NEEDED || securityStatus & SEC_I_COMPLETE_AND_CONTINUE)
			context.completeAuthToken(bufferDescOut);
		this.isAuthenticated = (securityStatus ==0);
		return tuple(securityStatus, buffers[0]);

	}
}
