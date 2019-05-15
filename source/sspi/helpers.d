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



bool secSuccess(SECURITY_STATUS status)
{
	return status >= 0;
}

T queryContextAttributes(T)(ref _SecHandle context, SecPackageAttribute attribute)
{
	T ret;
	auto securityStatus = QueryContextAttributesW(&context,attribute,cast(void*)&ret);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return ret;
}

ulong decryptMessage(ref _SecHandle context, ref SecBufferDesc message, ulong messageSeqNo)
{
	ulong fQOP;
	auto securityStatus = DecryptMessage(&context,&message,messageSeqNo,&fQOP);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return fQOP;
}

void encryptMessage(ref _SecHandle context, ulong fQOP, ref SecBufferDesc message, ulong messageSeqNo)
{
	auto securityStatus = EncryptMessageW(&context,fQOP, &message,cast(void*)&ret);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

void makeSignature(ref _SecHandle context, ulong fQOP, ref SecBufferDesc message, ulong messageSeqNo)
{
	auto securityStatus = MakeSignature(&context,fQOP,&message,messageSeqNo);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
}

ulong verifySignature(ref _SecHandle context, ref SecBufferDesc message, ulong messageSeqNo)
{
	ulong pfQOP;
	auto securityStatus = VerifySignature(&context,&message,messageSeqNo,&pfQOP);
	enforce(securityStatus.secSuccess, (cast(SecurityStatus)securityStatus).to!string);
	return pfQOP;
}

	
auto querySecurityPackageInfo(string packageName)
{
	PSecPkgInfoW ret;
	SecurityStatus securityStatus = cast(SecurityStatus) QuerySecurityPackageInfoW(packageName,&ret);
	enforce(securityStatus.secSuccess, securityStatus.to!string);
	return ret;
}

auto initializeSecurityContext(ref CredHandle credentials, SecHandle context, string targetName, ulong fContextReq, ulong reserved1, ulong targetDataRep, ref SecBufferDesc input, ref SecBufferDesc outputBufferDesc)
{
	ulong contextAttribute;
	SecHandle newContext;
	TimeStamp expiry;
	SecurityStatus securityStatus = cast(SecurityStatus) InitializeSecurityContextW(&credentials, context, targetName, fcontextReq, 0, targetDataRep,&input,0,&newContext,&output,&expiry);
	return tuple(contextAttribute,expiry,securityStatus,newContext,outputBufferDesc);
}


