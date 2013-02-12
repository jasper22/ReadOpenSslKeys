using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace LoadOpenSslKeys.Model.Cert
{
    /// <summary>
    /// Function that help to create/manage certificate
    /// </summary>
    internal class Utilites
    {
        internal const uint AT_KEYEXCHANGE = 0x00000001;
        internal const uint AT_SIGNATURE = 0x00000002;
        internal const uint CRYPT_MACHINE_KEYSET = 0x00000020;
        internal const uint PROV_RSA_FULL = 0x00000001;
        internal const String MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
        internal const String MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
        internal const String MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
        internal const uint CERT_CREATE_SELFSIGN_NO_SIGN = 1;
        internal const uint X509_ASN_ENCODING = 0x00000001;
        internal const uint CERT_X500_NAME_STR = 3;

        /// <summary>
        /// Creates the unsigned certificate
        /// </summary>
        /// <param name="keycontainer">The key-container name</param>
        /// <param name="DN">The x509 name of certificate</param>
        /// <param name="provider">The cryptography provider (MS_DEF_PROV/MS_STRONG_PROV/MS_ENHANCED_PROV)</param>
        /// <param name="KEYSPEC">The key specification (AT_KEYEXCHANGE/AT_SIGNATURE) </param>
        /// <param name="cspflags">The CSP flags (only 0 = 'Current User' is used)</param>
        /// <returns>Pointer to created certificate context</returns>
        /// <exception cref="System.ApplicationException">Error occurred while trying to create certificate. Error is:  +  e.Message</exception>
        internal static IntPtr CreateUnsignedCertCntxt(String keycontainer, String DN, String provider = MS_DEF_PROV, uint KEYSPEC = AT_KEYEXCHANGE, uint cspflags = 0)
        {
            IntPtr hCertCntxt = IntPtr.Zero;
            byte[] encodedName = null;
            uint cbName = 0;

            if (provider != MS_DEF_PROV && provider != MS_STRONG_PROV && provider != MS_ENHANCED_PROV)
            {
                return IntPtr.Zero;
            }

            if (keycontainer == "")
            {
                return IntPtr.Zero;
            }

            if (KEYSPEC != AT_SIGNATURE && KEYSPEC != AT_KEYEXCHANGE)
            {
                return IntPtr.Zero;
            }

            if (cspflags != 0 && cspflags != CRYPT_MACHINE_KEYSET)   //only 0 (Current User) keyset is currently used.
            {
                return IntPtr.Zero;
            }

            if (DN == "")
            {
                return IntPtr.Zero;
            }


            if (UnsafeNativeMethods.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
            {
                encodedName = new byte[cbName];
                UnsafeNativeMethods.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
            }

            UnsafeNativeMethods.CERT_NAME_BLOB subjectblob = new UnsafeNativeMethods.CERT_NAME_BLOB();
            subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
            Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
            subjectblob.cbData = encodedName.Length;

            UnsafeNativeMethods.CRYPT_KEY_PROV_INFO pInfo = new UnsafeNativeMethods.CRYPT_KEY_PROV_INFO();
            pInfo.pwszContainerName = keycontainer;
            pInfo.pwszProvName = provider;
            pInfo.dwProvType = PROV_RSA_FULL;
            pInfo.dwFlags = cspflags;
            pInfo.cProvParam = 0;
            pInfo.rgProvParam = IntPtr.Zero;
            pInfo.dwKeySpec = KEYSPEC;

            try
            {
                hCertCntxt = UnsafeNativeMethods.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (hCertCntxt == IntPtr.Zero)
                {
                    System.ComponentModel.Win32Exception e = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    throw new ApplicationException("Error occurred while trying to create certificate. Error is: " +  e.Message, e);
                }

                return hCertCntxt;
            }
            finally
            {
                Marshal.FreeHGlobal(subjectblob.pbData);
            }
        }

        /// <summary>
        /// Function will create and export certificate to PKCS12 format (PFX) with password (if any)
        /// </summary>
        /// <param name="keyContainerName">Name of the key container.</param>
        /// <param name="cspProvider">The CSP provider.</param>
        /// <param name="keySpec">The key specification</param>
        /// <param name="cspFlags">The CSP flags.</param>
        /// <param name="pfxPassword">The PFX password.</param>
        /// <returns>Certificate exported to PKCS#12 format and converted to bytes</returns>
        internal byte[] ExportCertToPKCS12(String keyContainerName, String cspProvider = MS_DEF_PROV, uint keySpec = AT_KEYEXCHANGE, uint cspFlags = 0, string pfxPassword = "")
        {
            byte[] pfxblob = null;
            IntPtr hCertCntxt = IntPtr.Zero;

            String DN = "CN=Opensslkey Unsigned Certificate";

            hCertCntxt = CreateUnsignedCertCntxt(keyContainerName, DN, cspProvider, keySpec, cspFlags);
            if (hCertCntxt == IntPtr.Zero)
            {
                throw new ApplicationException("Could not create certificate");
            }

            try
            {
                X509Certificate cert = new X509Certificate(hCertCntxt);	//create certificate object from cert context.
                //X509Certificate2UI.DisplayCertificate(new X509Certificate2(cert));	// display it, showing linked private key
                pfxblob = cert.Export(X509ContentType.Pkcs12, pfxPassword);
            }
            catch (Exception exc)
            {
                throw new ApplicationException("Could not create certificate. Message: " + exc.Message, exc);
            }

            if (hCertCntxt != IntPtr.Zero)
            {
                UnsafeNativeMethods.CertFreeCertificateContext(hCertCntxt);
            }

            return pfxblob;
        }
    }
}
