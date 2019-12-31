module sspi;

version(Windows):

import core.sys.windows.ntsecpkg;
import core.sys.windows.sspi;
import core.sys.windows.windef:DWORD;
import sspi.defines;
import sspi.helpers;

enum cbMaxMessage  = 12_000; // from SSPI MS example


struct BaseAuth
{
	SecHandle context;
	CredHandle credentials;
	uint nextSequenceNumber;
	bool isAuthenticated;
	string packageName;
	TimeStamp credentialsExpiry;
	SecPkgInfoW* packageInfo;
	enum DefaultSecurityContextFlags = 	IscReq.integrity 	| IscReq.sequenceDetect | IscReq.replayDetect	| IscReq.confidentiality;
	IscReq securityContextFlags = DefaultSecurityContextFlags;
	uint dataRep;
	uint contextAttr;


	void dispose()
	{
		if (this.context != SecHandle.init)
			deleteSecurityContext(&this.context);
		if (this.credentials != CredHandle.init)
			freeCredentialsHandle(&this.credentials);
	}

	/// Reset everything to an unauthorized state
	void reset()
	{
		this.dispose();
		this.context = SecHandle.init;
		this.credentials = CredHandle.init;
		this.isAuthenticated = false;
		this.nextSequenceNumber = 0;
		this.packageName = null;
		this.credentialsExpiry = TimeStamp.init;
		this.packageInfo = null;
		this.securityContextFlags = DefaultSecurityContextFlags;
		this.dataRep = 0;
		this.contextAttr = 0;
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
		import std.conv:to;
		import std.typecons:tuple;

		// auto packageInfo = context.queryContextAttributes!SecPkgNegInfo(SecPackageAttribute.info);
		auto packageSizes= queryContextAttributes!SecPkgContext_Sizes(&context,SecPackageAttribute.sizes);
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
		buffers[0].pvBuffer = cast(void*)data.ptr + cast(ptrdiff_t) DWORD.sizeof;

		buffers[1].cbBuffer = data.length.to!uint;
		buffers[1].BufferType = SECBUFFER_DATA;
		buffers[1].pvBuffer = cast(void*)data.ptr;

		context.encryptMessage(0, bufferDesc, getNextSequenceNumber());
		return outputData.idup;
	}


	/// Decrypt a previously encrypted string, returning the orignal data
	auto decrypt(string data, string trailer)
	{
		import std.conv:to;
		import std.string : toStringz,fromStringz;

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
		import std.conv:to;
		import std.string : toStringz,fromStringz;

		auto packageSizes = queryContextAttributes!SecPkgContext_Sizes(&context,SecPackageAttribute.sizes);
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
		import std.conv:to;
		import std.string : toStringz,fromStringz;

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

	auto acquireCredentialsHandle(string userName, string packageName, CredentialDirection credentialDirection)
	{
		import std.exception : enforce;
		import std.conv:to;
		import std.typecons:tuple;
		import std.utf:toUTF16z;

		TimeStamp lifetime;
		auto direction = (credentialDirection == CredentialDirection.inbound) ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND;
		SecurityStatus securityStatus = cast(SecurityStatus) AcquireCredentialsHandleW(
									(userName is null) ? null : cast(wchar*) userName.toUTF16z,
									cast(wchar*) packageName.toUTF16z,
									direction,
									null,
									null,
									null,
									null,
									&this.credentials,
									&lifetime);
		enforce(securityStatus.secSuccess, securityStatus.to!string);
		this.credentialsExpiry = lifetime;
		return tuple(lifetime, credentials);
	}
}


enum CredentialDirection
{
	inbound,
	outbound,
}


struct ClientAuth
{
	BaseAuth base;
	alias base this;
	alias DefaultSecurityContextFlags = BaseAuth.DefaultSecurityContextFlags;

	string targetSecurityContextProvider;

	this(string packageName, string clientName, 
		string targetSecurityContextProvider = null,
		IscReq securityContextFlags = DefaultSecurityContextFlags, uint dataRep = SECURITY_NETWORK_DREP)
	{
		import std.stdio;
		import std.string:fromStringz;

		this.securityContextFlags = securityContextFlags;
		this.dataRep = dataRep;
		this.targetSecurityContextProvider = targetSecurityContextProvider;
		this.packageInfo = querySecurityPackageInfo(packageName);
		auto result = acquireCredentialsHandle(clientName,packageName,CredentialDirection.outbound);
		this.credentialsExpiry = result[0];
		this.base.credentials = result[1];
		this.packageName = packageName;
	}


	/// Perform *one* step of the server authentication process.
	auto authorize(ubyte[] data=[])
	{
		import std.stdio;
		import std.conv:to;
		import std.typecons:tuple;

		SecurityContextResult result;
		bool isFirstStage = (data.length == 0);
		ubyte[] retBuf;
		retBuf.length = cbMaxMessage;
		SecBuffer[1] buffersIn, buffersOut;
		SecBufferDesc bufferDescIn, bufferDescOut;
		DWORD cbOut = isFirstStage?retBuf.length.to!int : 0;

		bufferDescOut.ulVersion = SECBUFFER_VERSION;
		bufferDescOut.cBuffers = 1;
		bufferDescOut.pBuffers = buffersOut.ptr;

		buffersOut[0].cbBuffer = cbOut;
		buffersOut[0].BufferType = SECBUFFER_TOKEN;
		buffersOut[0].pvBuffer = retBuf.ptr;
		auto securityContextModFlags = cast(uint)securityContextFlags | ISC_REQ_ALLOCATE_MEMORY;

		if(!isFirstStage)
		{
			bufferDescIn.ulVersion = SECBUFFER_VERSION;
			bufferDescIn.cBuffers = 1;
			bufferDescIn.pBuffers = buffersIn.ptr;

			buffersIn[0].cbBuffer = data.length.to!int;
			buffersIn[0].BufferType = SECBUFFER_TOKEN;
			buffersIn[0].pvBuffer = cast(void*) data.ptr;

			buffersOut[0].pvBuffer = null;
			buffersOut[0].cbBuffer   = 0;
			result = initializeSecurityContext(credentials, &context, packageName, securityContextModFlags, 0U, cast(uint)dataRep,bufferDescIn,bufferDescOut);
			bufferDescOut = result.outputBufferDesc;
		}
		else
		{
			buffersOut[0].pvBuffer = null;
			buffersOut[0].cbBuffer   = 0;
			result = initializeSecurityContextInitial(credentials, &context, this.targetSecurityContextProvider, securityContextModFlags, 0UL, dataRep,bufferDescOut);
			bufferDescOut=result.outputBufferDesc;
			//auto result2 = queryContextAttributes!SecPkgInfoW(&context,SecPackageAttribute.negotiationInfo);
		}

		scope(exit)
		{
			if (result.outputBufferDesc.pBuffers !is null)
				FreeContextBuffer(cast(void*)result.outputBufferDesc.pBuffers);
		}
		this.contextAttr = result.contextAttribute;
		this.credentialsExpiry = result.expiry;
		auto securityStatus = result.securityStatus;

		//auto result2 = context.queryContextAttributes!SecPkgInfoW(SecPackageAttribute.negotiationInfo);
		if (securityStatus == SecurityStatus.completeNeeded || securityStatus == SecurityStatus.completeAndContinue)
		{
			version(Trace) writefln("securityStatus: %s, completeneeded %s completecontinue%s",securityStatus,cast(long)SecurityStatus.completeNeeded,cast(long)SecurityStatus.completeAndContinue);
			completeAuthToken(&context,bufferDescOut);
		}
		this.isAuthenticated = (securityStatus ==0);
		auto returnBuffersOut = cast(SecBuffer*)(bufferDescOut.pBuffers);
		version(Trace)
		{
			stderr.writefln("authenticated = %s; %s byte token",securityStatus,returnBuffersOut.cbBuffer);
			stderr.writeln(this.isAuthenticated,securityStatus,this.credentialsExpiry);
		}
		return tuple(securityStatus, ((cast(ubyte*)(returnBuffersOut.pvBuffer)))[0 .. returnBuffersOut.cbBuffer].idup);

	}
}

/// Manages the server side of an SSPI authentication handshake
struct ServerAuth
{
	BaseAuth base;
	alias base this;
	alias DefaultSecurityContextFlags = BaseAuth.DefaultSecurityContextFlags;

	bool isAuthenticated = false;

	this(string packageName, 
		IscReq securityContextFlags = DefaultSecurityContextFlags, uint dataRep = SECURITY_NETWORK_DREP)
	{
		this.securityContextFlags = securityContextFlags;
		this.dataRep = dataRep;
		this.packageName = packageName;
		this.packageInfo = querySecurityPackageInfo(packageName);
	}

	void setup()
	{
		import std.format : format;
		import std.exception : enforce;

		packageInfo = querySecurityPackageInfo(packageName);
		auto result = acquireCredentialsHandle(null,packageName, CredentialDirection.inbound);
		this.credentialsExpiry = result[0];
	}

	/// Perform *one* step of the server authentication process.
	auto authorize(ubyte[] data = [])
	{
		import std.stdio;
		import std.typecons:tuple;

		bool isFirstStage = (data.length == 0);
		ubyte[] retBuf;
		retBuf.length = isFirstStage ? 0 : cbMaxMessage; // packageInfo.cbMaxMessage;
		SecBuffer[1] buffersIn, buffersOut;
		SecBufferDesc bufferDescIn, bufferDescOut;

		auto contextSizes= queryContextAttributes!SecPkgContext_Sizes(&context, SecPackageAttribute.sizes);
		auto negotiationInfo = queryContextAttributes!SecPkgContext_NegotiationInfoW(&context,SecPackageAttribute.negotiationInfo);

		bufferDescOut.ulVersion = 0;
		bufferDescOut.cBuffers = 1;
		bufferDescOut.pBuffers = buffersOut.ptr;

		buffersOut[0].cbBuffer = this.packageInfo.cbMaxToken; // CHECKME
		buffersOut[0].BufferType = SECBUFFER_TOKEN;
		buffersOut[0].pvBuffer = retBuf.ptr;

		SecurityContextResult result;

		auto securityContextModFlags = cast(uint)securityContextFlags | ISC_REQ_ALLOCATE_MEMORY;

		if(!isFirstStage)
		{
			bufferDescIn.ulVersion = 0;
			bufferDescIn.cBuffers = 1;
			bufferDescIn.pBuffers = buffersIn.ptr;

			buffersIn[0].cbBuffer = this.packageInfo.cbMaxToken;
			buffersIn[0].BufferType = SECBUFFER_TOKEN;
			buffersIn[0].pvBuffer = cast(void*) data.ptr;
			result = acceptSecurityContext(	credentials, &context, &bufferDescIn, securityContextModFlags, dataRep, &context,bufferDescOut);
		}
		else
		{
			SecHandle newContext;
			result = acceptSecurityContext(	credentials, null, &bufferDescIn, securityContextModFlags, dataRep, &newContext,bufferDescOut);
			this.context = newContext;
		}

		scope(exit)
		{
			if (result.outputBufferDesc.pBuffers !is null)
				FreeContextBuffer(cast(void*)result.outputBufferDesc.pBuffers);
		}

		this.base.contextAttr = result.contextAttribute;
		this.base.credentialsExpiry = result.expiry;
		auto securityStatus = result.securityStatus;
		bufferDescOut = result.outputBufferDesc;

		if (securityStatus == SecurityStatus.completeNeeded || securityStatus == SecurityStatus.completeAndContinue)
			completeAuthToken(&context,bufferDescOut);
		this.isAuthenticated = (securityStatus ==0);
		return tuple(securityStatus, buffersOut[0]);
	}

	string impersonate()
	{
		impersonateSecurityContext(&context);
		return getUserName();
	}

	void revertImpersonate()
	{
		revertSecurityContext(&context);
	}
}
