module sspi.defines;

version(Windows):
import core.sys.windows.ntsecpkg;
import core.sys.windows.sspi;


enum SecPkgFlag
{
	integrity = SECPKG_FLAG_INTEGRITY,
	privacy = SECPKG_FLAG_PRIVACY,
	tokenOnly = SECPKG_FLAG_TOKEN_ONLY,
	datagram = SECPKG_FLAG_DATAGRAM,
	connection = SECPKG_FLAG_CONNECTION,
	multiRequired = SECPKG_FLAG_MULTI_REQUIRED,
	clientOnly = SECPKG_FLAG_CLIENT_ONLY,
	extendedError = SECPKG_FLAG_EXTENDED_ERROR,
	impersonation = SECPKG_FLAG_IMPERSONATION,
	acceptWin32Name = SECPKG_FLAG_ACCEPT_WIN32_NAME,
	stream = SECPKG_FLAG_STREAM,
}


enum SecPackageAttribute
{
	authority = SECPKG_ATTR_AUTHORITY,
	connectionInfo = SECPKG_ATTR_CONNECTION_INFO,
	issuerList = SECPKG_ATTR_ISSUER_LIST,
	issuerListEx = SECPKG_ATTR_ISSUER_LIST_EX,
	keyInfo = SECPKG_ATTR_KEY_INFO,
	lifespan = SECPKG_ATTR_LIFESPAN,
	localCertContext = SECPKG_ATTR_LOCAL_CERT_CONTEXT,
	localCred = SECPKG_ATTR_LOCAL_CRED,
	names = SECPKG_ATTR_NAMES,
	protoInfo = SECPKG_ATTR_PROTO_INFO,
	remoteCertContext = SECPKG_ATTR_REMOTE_CERT_CONTEXT,
	remoteCred = SECPKG_ATTR_REMOTE_CRED,
	sizes = SECPKG_ATTR_SIZES,
	streamSizes = SECPKG_ATTR_STREAM_SIZES,
}

struct SecPkgContext_NegotiationInfoW
{
	SecPkgInfoW*  packageInfo;
	ulong negotiationState;
}


enum SecurityStatus
{
	bufferTooSmall = SEC_E_BUFFER_TOO_SMALL,
	contextExpired = SEC_E_CONTEXT_EXPIRED,
	cryptoSystemInvalid = SEC_E_CRYPTO_SYSTEM_INVALID,
	insufficientMemory = SEC_E_INSUFFICIENT_MEMORY,
	invalidHandle = SEC_E_INVALID_HANDLE,
	invalidToken = SEC_E_INVALID_TOKEN,
	qopNotSupported = SEC_E_QOP_NOT_SUPPORTED,
	outOfSequence = SEC_E_OUT_OF_SEQUENCE,
	messageAltered = SEC_E_MESSAGE_ALTERED,
}


enum IscReq
{
	delegate_ = ISC_REQ_DELEGATE,
	mutualAuth = ISC_REQ_MUTUAL_AUTH,
	replayDetect = ISC_REQ_REPLAY_DETECT,
	sequenceDetect = ISC_REQ_SEQUENCE_DETECT,
	confidentiality = ISC_REQ_CONFIDENTIALITY,
	useSessionKey = ISC_REQ_USE_SESSION_KEY,
	promptForCreds = ISC_REQ_PROMPT_FOR_CREDS,
	useSuppliedCreds = ISC_REQ_USE_SUPPLIED_CREDS,
	allocateMemory = ISC_REQ_ALLOCATE_MEMORY,
	useDceStyle = ISC_REQ_USE_DCE_STYLE,
	datagram = ISC_REQ_DATAGRAM,
	connection = ISC_REQ_CONNECTION,
	extendedError = ISC_REQ_EXTENDED_ERROR,
	stream = ISC_REQ_STREAM,
	integrity = ISC_REQ_INTEGRITY,
	manualCredValidation = ISC_REQ_MANUAL_CRED_VALIDATION,
	http = ISC_REQ_HTTP,
}

