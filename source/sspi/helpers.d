module sspi.helpers;

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
import core.sys.windows.security;
import core.sys.windows.winbase : GetUserNameW;
import sspi.defines;

bool secSuccess(SECURITY_STATUS status)
{
	return status >= 0;
}

T queryContextAttributes(T)(SecHandle* context, SecPackageAttribute attribute)
{
	import std.exception : enforce;
	import std.conv:to;
	T ret;
	auto securityStatus = QueryContextAttributesW(context,attribute,cast(void*)&ret);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return ret;
}

uint decryptMessage(ref SecHandle context, ref SecBufferDesc message, uint messageSeqNo)
{
	import std.exception : enforce;
	import std.conv:to;
	uint fQOP;
	auto securityStatus = DecryptMessage(&context,&message,messageSeqNo,&fQOP);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return fQOP;
}

void encryptMessage(ref SecHandle context, uint fQOP, ref SecBufferDesc message, uint messageSeqNo)
{
	import std.exception : enforce;
	import std.conv:to;
	auto securityStatus = EncryptMessage(&context,fQOP, &message,messageSeqNo);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

void makeSignature(ref SecHandle context, uint fQOP, ref SecBufferDesc message, uint messageSeqNo)
{
	import std.exception : enforce;
	import std.conv:to;
	auto securityStatus = MakeSignature(&context,fQOP,&message,messageSeqNo);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

uint verifySignature(ref SecHandle context, ref SecBufferDesc message, uint messageSeqNo)
{
	import std.exception : enforce;
	import std.conv:to;
	uint pfQOP;
	auto securityStatus = VerifySignature(&context,&message,messageSeqNo,&pfQOP);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return pfQOP;
}

	
auto querySecurityPackageInfo(string packageName)
{
	import std.exception : enforce;
	import std.utf:toUTF16z;
	import std.conv:to;
	PSecPkgInfoW ret;
	SecurityStatus securityStatus = cast(SecurityStatus) QuerySecurityPackageInfoW(cast(wchar*)packageName.toUTF16z,&ret);
	enforce(securityStatus.secSuccess, securityStatus.to!string);
	return ret;
}

struct SecurityContextResult
{
	uint contextAttribute;
	TimeStamp expiry;
	SecurityStatus securityStatus;
	SecBufferDesc outputBufferDesc;
}

auto initializeSecurityContext(ref CredHandle credentials, SecHandle* context, string targetName, uint fContextReq, ulong reserved1, uint targetDataRep, SecBufferDesc* input, ref SecBufferDesc outputBufferDesc)
{
	import std.utf:toUTF16z;
	SecurityContextResult ret;
	ret.outputBufferDesc = outputBufferDesc;
	ret.securityStatus = cast(SecurityStatus) InitializeSecurityContextW(&credentials, context, cast(wchar*)targetName.toUTF16z, fContextReq, 0, targetDataRep,input,0,context,&ret.outputBufferDesc,&ret.contextAttribute,&ret.expiry);
	return ret;
}

auto initializeSecurityContext(ref CredHandle credentials, SecHandle* context, string targetName, uint fContextReq, ulong reserved1, uint targetDataRep, ref SecBufferDesc input, ref SecBufferDesc outputBufferDesc)
{
	return initializeSecurityContext(credentials, context, targetName, fContextReq, reserved1, targetDataRep,&input,outputBufferDesc);
}

auto initializeSecurityContextInitial(ref CredHandle credentials, SecHandle* context, string targetName, uint fContextReq, ulong reserved1, uint targetDataRep, ref SecBufferDesc outputBufferDesc)
{
	import std.utf:toUTF16z;
	SecurityContextResult ret;
	ret.outputBufferDesc = outputBufferDesc;
	version(Trace)
	{
		import std.stdio;
		writefln("targetName: %s",targetName);
		writefln("fcontextReq: %s",fContextReq);
		writeln("targetDataRep: %s",targetDataRep);
	}
	ret.securityStatus = cast(SecurityStatus) InitializeSecurityContextW(&credentials,null,(targetName.length==0)? null : cast(wchar*)targetName.toUTF16z, fContextReq, 0, targetDataRep,null,0,context,&ret.outputBufferDesc,&ret.contextAttribute,&ret.expiry);
	return ret;
}

auto acceptSecurityContext(ref CredHandle credentials, SecHandle* context, SecBufferDesc* input, uint fContextReq, uint targetDataRep, SecHandle* newContext, ref SecBufferDesc outputBufferDesc)
{
	import std.utf:toUTF16z;
	SecurityContextResult ret;
	ret.outputBufferDesc = outputBufferDesc;
	ret.securityStatus = cast(SecurityStatus) AcceptSecurityContext(&credentials, context, input, fContextReq, targetDataRep,newContext,&ret.outputBufferDesc,&ret.contextAttribute,&ret.expiry);
	return ret;
}

void completeAuthToken(SecHandle* context, ref SecBufferDesc token)
{
	import std.exception : enforce;
	import std.conv:to;
    auto securityStatus = CompleteAuthToken(context,&token);
    enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}


void impersonateSecurityContext(SecHandle* context)
{
	import std.exception : enforce;
	import std.conv:to;
	auto securityStatus = ImpersonateSecurityContext(context);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

void revertSecurityContext(SecHandle* context)
{
	import std.exception : enforce;
	import std.conv:to;
	auto securityStatus = RevertSecurityContext(context);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

string getUserName()
{
	import std.format : format;
	import std.exception : enforce;
	import std.conv : to;

	uint cbUserName;
	GetUserNameW(null,&cbUserName);
	enforce(cbUserName > 0, format!"unable to get username - cbUserName = %s"(cbUserName));
	auto ret = new wchar[cbUserName];
	auto result = GetUserNameW(ret.ptr,&cbUserName);
	enforce(result, format!"error getting username of length %s - status = %s"(cbUserName,result));	
	return ret.to!string;
}

void freeCredentialsHandle(CredHandle* pCredentials)
{
	import std.format : format;
	import std.exception : enforce;

	if (pCredentials is null)
		return;
	auto result = FreeCredentialsHandle(pCredentials);
	enforce(result == SEC_E_OK, format!"error freeing credentials handle for %s: %s"(*pCredentials, result));
}

void deleteSecurityContext(SecHandle* pContext)
{
	import std.format : format;
	import std.exception : enforce;

	if (pContext is null)
		return;
	auto result = DeleteSecurityContext(pContext);
	enforce(result == SEC_E_OK, format!"error deleting security context for %s: %s"(*pContext, result));
}

