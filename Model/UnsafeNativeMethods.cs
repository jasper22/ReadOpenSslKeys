using System;
using System.Runtime.InteropServices;

namespace LoadOpenSslKeys.Model
{
	/// <summary>
	/// Win32 API calls
	/// </summary>
	internal static class UnsafeNativeMethods
	{
		/// <summary>
		/// The CertCreateSelfSignCertificate function builds a self-signed certificate and returns a pointer to a CERT_CONTEXT structure that represents 
		/// the certificate.
		/// </summary>
		/// <param name="hProv">
		/// A handle of a cryptographic provider used to sign the certificate created. If NULL, information from the pKeyProvInfo parameter is used 
		/// to acquire the needed handle. If pKeyProvInfo is also NULL, the default provider type, PROV_RSA_FULL provider type, the default key specification,
		/// AT_SIGNATURE, and a newly created key container with a unique container name are used.
		/// This handle must be an HCRYPTPROV handle that has been created by using the CryptAcquireContext function or an NCRYPT_KEY_HANDLE handle that has 
		/// been created by using the NCryptOpenKey function. New applications should always pass in the NCRYPT_KEY_HANDLE handle of a CNG cryptographic 
		/// service provider (CSP).
		/// </param>
		/// <param name="pSubjectIssuerBlob">
		/// A pointer to a BLOB that contains the distinguished name (DN) for the certificate subject. This parameter cannot be NULL. Minimally, a pointer 
		/// to an empty DN must be provided. This BLOB is normally created by using the CertStrToName function. It can also be created by using the 
		/// CryptEncodeObject function and specifying either the X509_NAME or X509_UNICODE_NAME StructType.
		/// </param>
		/// <param name="dwFlagsm">
		/// A set of flags that override the default behavior of this function. This can be zero or a combination of one or more of the following values.
		/// (CERT_CREATE_SELFSIGN_NO_KEY_INFO = 2 / CERT_CREATE_SELFSIGN_NO_SIGN = 1)
		/// </param>
		/// <param name="pKeyProvInfo">
		/// A pointer to a CRYPT_KEY_PROV_INFO structure. Before a certificate is created, the CSP is queried for the key provider, key provider type, 
		/// and the key container name. If the CSP queried does not support these queries, the function fails. If the default provider does not support 
		/// these queries, a pKeyProvInfo value must be specified. The RSA BASE does support these queries.
		/// If the pKeyProvInfo parameter is not NULL, the corresponding values are set in the CERT_KEY_PROV_INFO_PROP_ID value of the generated certificate. 
		/// You must ensure that all parameters of the supplied structure are correctly specified.
		/// </param>
		/// <param name="pSignatureAlgorithm">
		/// A pointer to a CRYPT_ALGORITHM_IDENTIFIER structure. If NULL, the default algorithm, SHA1RSA, is used.
		/// </param>
		/// <param name="pStartTime">A pointer to a SYSTEMTIME structure. If NULL, the system current time is used by default.</param>
		/// <param name="pEndTime">A pointer to a SYSTEMTIME structure. If NULL, the pStartTime value plus one year will be used by default.</param>
		/// <param name="other">
		/// A pointer to a CERT_EXTENSIONS array of CERT_EXTENSION structures. By default, the array is empty. An alternate subject name, if desired, 
		/// can be specified as one of these extensions.
		/// </param>
		/// <returns>
		/// If the function succeeds, a PCCERT_CONTEXT variable that points to the created certificate is returned. If the function fails, it returns NULL.
		/// For extended error information, call GetLastError.
		/// </returns>
		/// <remarks>http://msdn.microsoft.com/en-us/library/windows/desktop/aa376039(v=vs.85).aspx</remarks>
		[DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CertCreateSelfSignCertificate")]
		public static extern IntPtr CertCreateSelfSignCertificate(
																	IntPtr hProv,
																	ref CERT_NAME_BLOB pSubjectIssuerBlob,
																	uint dwFlagsm,
																	ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
																	IntPtr pSignatureAlgorithm,
																	IntPtr pStartTime,
																	IntPtr pEndTime,
																	IntPtr other);

		/// <summary>
		/// The CertStrToName function converts a null-terminated X.500 string to an encoded certificate name.
		/// </summary>
		/// <param name="dwCertEncodingType">
		/// The certificate encoding type that was used to encode the string. The message encoding type identifier, contained in the high WORD of this value, 
		/// is ignored by this function.
		/// This parameter can be the following currently defined certificate encoding type: X509_ASN_ENCODING = 1 (0x1)
		/// </param>
		/// <param name="pszX500">
		/// A pointer to the null-terminated X.500 string to be converted. The format of this string is specified by the dwStrType parameter. 
		/// This string is expected to be formatted the same as the output from the CertNameToStr function.
		/// </param>
		/// <param name="dwStrType">
		/// This parameter specifies the type of the string. This parameter also specifies other options for the contents of the string. 
		/// If no flags are combined with the string type specifier, the string can contain a comma (,) or a semicolon (;) as separators in the relative 
		/// distinguished name (RDN) and a plus sign (+) as the separator in multiple RDN values. 
		/// Quotation marks ("") are supported. A quotation can be included in a quoted value by using two sets of quotation marks, for example, 
		/// CN="User ""one""". 
		/// A value that starts with a number sign (#) is treated as ASCII hexadecimal and converted to a CERT_RDN_OCTET_STRING. Embedded white space is 
		/// ignored. For example, 1.2.3 = # AB CD 01 is the same as 1.2.3=#ABCD01. 
		/// White space that surrounds the keys, object identifiers, and values is ignored. 
		/// This parameter can be one of the following values.
		/// (CERT_SIMPLE_NAME_STR = 1, CERT_OID_NAME_STR = 2, CERT_X500_NAME_STR = 3)
		/// The following options can also be combined with the value above to specify additional options for the string.
		/// (CERT_NAME_STR_COMMA_FLAG = 0x04000000, CERT_NAME_STR_SEMICOLON_FLAG = 0x40000000, CERT_NAME_STR_CRLF_FLAG = 0x08000000,
		/// CERT_NAME_STR_NO_PLUS_FLAG = 0x20000000, CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000, CERT_NAME_STR_REVERSE_FLAG = 0x02000000,
		/// CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG = 0x00020000, CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG = 0x00040000,
		/// CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG = 0x00080000, CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG = 0x00100000,
		/// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG = 0x00200000)
		/// </param>
		/// <param name="pvReserved">Reserved for future use and must be NULL.</param>
		/// <param name="pbEncoded">
		/// A pointer to a buffer that receives the encoded structure. The size of this buffer is specified in the pcbEncoded parameter. 
		/// This parameter can be NULL to obtain the required size of the buffer for memory allocation purposes. For more information, 
		/// see Retrieving Data of Unknown Length.
		/// </param>
		/// <param name="pcbEncoded">
		/// A pointer to a DWORD that, before calling the function, contains the size, in bytes, of the buffer pointed to by the pbEncoded parameter. 
		/// When the function returns, the DWORD contains the number of bytes stored in the buffer.
		/// If pbEncoded is NULL, the DWORD receives the size, in bytes, required for the buffer.
		/// </param>
		/// <param name="other">
		/// A pointer to a string pointer that receives additional error information about an input string that is not valid. If the pszX500 string is not 
		/// valid, ppszError is updated by this function to point to the beginning of the character sequence that is not valid. If no errors are detected 
		/// in the input string, ppszError is set to NULL.
		/// If this information is not required, pass NULL for this parameter.
		/// </param>
		/// <returns><c>true</c> if success, otherwise <c>false</c></returns>
		[DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CertStrToName")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CertStrToName(
												 uint dwCertEncodingType,
												 String pszX500,
												 uint dwStrType,
												 IntPtr pvReserved,
												 [In, Out] byte[] pbEncoded,
												 ref uint pcbEncoded,
												 IntPtr other);

		/// <summary>
		/// Dispose/free certificate context.
		/// </summary>
		/// <param name="hCertStore">A pointer to the CERT_CONTEXT to be freed.</param>
		/// <returns><c>true</c> if success, otherwise <c>false</c></returns>
		[DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CertFreeCertificateContext")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool CertFreeCertificateContext(IntPtr hCertStore);

		/// <summary>
		/// The CRYPT_KEY_PROV_INFO structure contains information about a key container within a cryptographic service provider
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		public struct CRYPT_KEY_PROV_INFO
		{
			/// <summary>
			/// A pointer to a null-terminated Unicode string that contains the name of the key container.
			/// When the dwProvType member is zero, this string contains the name of a key within a CNG key storage provider. This string is passed as 
			/// the pwszKeyName parameter to the NCryptOpenKey function.
			/// </summary>
			[MarshalAs(UnmanagedType.LPWStr)]
			public String pwszContainerName;

			/// <summary>
			/// A pointer to a null-terminated Unicode string that contains the name of the CSP.
			/// When the dwProvType member is zero, this string contains the name of a CNG key storage provider. This string is passed as the 
			/// pwszProviderName parameter to the NCryptOpenStorageProvider function.
			/// </summary>
			[MarshalAs(UnmanagedType.LPWStr)]
			public String pwszProvName;

			/// <summary>
			/// Specifies the CSP type. This can be zero or one of the Cryptographic Provider Types. If this member is zero, the key container is one of the CNG key storage providers.
			/// </summary>
			public uint dwProvType;

			/// <summary>
			/// A set of flags that indicate additional information about the provider. This can be zero or one of the following values.
			/// (CERT_SET_KEY_PROV_HANDLE_PROP_ID / CERT_SET_KEY_CONTEXT_PROP_ID |  CRYPT_MACHINE_KEYSET / NCRYPT_MACHINE_KEY_FLAG | 
			/// CRYPT_SILENT / NCRYPT_SILENT_FLAG )
			/// </summary>
			public uint dwFlags;

			/// <summary>
			/// The number of elements in the rgProvParam array.
			/// When the dwProvType member is zero, this member is not used and must be zero.
			/// </summary>
			public uint cProvParam;

			/// <summary>
			/// An array of CRYPT_KEY_PROV_PARAM structures that contain the parameters for the key container. The cProvParam member contains the number of elements in this array.
			/// When the dwProvType member is zero, this member is not used and must be NULL.
			/// </summary>
			public IntPtr rgProvParam;

			/// <summary>
			/// The specification of the private key to retrieve. The following values are defined for the default provider.
			/// When the dwProvType member is zero, this value is passed as the dwLegacyKeySpec parameter to the NCryptOpenKey function.
			/// (AT_KEYEXCHANGE / AT_SIGNATURE )
			/// </summary>
			public uint dwKeySpec;
		}

		/// <summary>
		/// Struct define blob for 'key name'
		/// </summary>
		[StructLayout(LayoutKind.Sequential)]
		public struct CERT_NAME_BLOB
		{
			/// <summary>
			/// Length of data
			/// </summary>
			public int cbData;

			/// <summary>
			/// Pointer to data
			/// </summary>
			public IntPtr pbData;
		}
	}
}
