using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Parser for OpenSSL Private key
    /// </summary>
    internal class OpenSslPrivKeyParser : ParserBase, IParser
    {
        internal const String HEADER = "-----BEGIN RSA PRIVATE KEY-----";
        internal const String FOOTER = "-----END RSA PRIVATE KEY-----";

        private byte[] keyRawData;
        private string password;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslPrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data.</param>
        /// <param name="password">In case that private key is encrypted this is the password to open it</param>
        /// <exception cref="System.ApplicationException">Invalid OpenSSL Private key</exception>
        internal OpenSslPrivKeyParser(string data, string password = "")
            : base(HEADER, FOOTER, data)
        {
            this.Rsa = null;
            this.password = password;

            try
            {
                keyRawData = DecodeKey();
            }
            catch (Exception exp_gen)
            {
                throw new ApplicationException("Invalid OpenSSL Private key", exp_gen);
            }

            this.Rsa = base.DecodeRSAPrivateKey(keyRawData);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslPrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data.</param>
        internal OpenSslPrivKeyParser(byte[] data)
            : base()
        {
            keyRawData = data;
            this.Rsa = base.DecodeRSAPrivateKey(keyRawData);
        }

        internal override byte[] DecodeKey()
        {
            try
            {
                keyRawData = base.DecodeKey();
            }
            catch (Exception exp_gen)
            {
                // May be it's encrypted OpenSSL private key
            }

            //-------- read PEM encryption info. lines and extract salt -----
            StringReader strReader = new StringReader(base.KeyRawData);
            if (strReader.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED") == false)
            {
                throw new ApplicationException("Invalid OpenSSL Private key");
            }

            String saltline = strReader.ReadLine();
            if (saltline.StartsWith("DEK-Info: DES-EDE3-CBC,") == false)
            {
                throw new ApplicationException("Invalid OpenSSL Private key");
            }

            String saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
            byte[] salt = new byte[saltstr.Length / 2];
            for (int i = 0; i < salt.Length; i++)
            {
                salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
            }

            if (strReader.ReadLine() != "")
            {
                throw new ApplicationException("Invalid OpenSSL Private key");
            }

            //------ remaining b64 data is encrypted RSA key ----
            String encryptedstr = strReader.ReadToEnd();

            try
            {	//should have b64 encrypted RSA key now
                keyRawData = Convert.FromBase64String(encryptedstr);
            }
            catch (System.FormatException e)
            {  
                // bad b64 data.
                throw new ApplicationException("Invalid OpenSSL (Encrypted) Private key", e);
            }

            //------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

            SecureString despswd = new SecureString();
            foreach (char singleChar in password)
            {
                despswd.AppendChar(singleChar);
            }

            byte[] deskey = GetOpenSSL3DesKey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
            if (deskey == null)
            {
                throw new ApplicationException("Invalid OpenSSL (Encrypted) Private key");
            }


            //------ Decrypt the encrypted 3des-encrypted RSA private key ------
            byte[] rsakey = DecryptKey(keyRawData, deskey, salt);	//OpenSSL uses salt value in PEM header also as 3DES IV
            if (rsakey != null)
            {
                return rsakey;	//we have a decrypted RSA private key
            }
            else
            {
                throw new ApplicationException("Failed to decrypt OpenSSL (Encrypted) Private key; probably wrong password.");
            }
        }

        /// <summary>
        /// Gets the RSA.
        /// </summary>
        /// <value>
        /// The RSA.
        /// </value>
        public RSACryptoServiceProvider Rsa
        {
            get;
            private set;
        }


        /// <summary>
        /// Gets the open SSL 3 DES key.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="secpswd">The password to open</param>
        /// <param name="count">The hash cycle count.</param>
        /// <param name="miter">The number of iterations required to build sufficient bytes</param>
        /// <returns>DES key</returns>
        /// <remarks>
        /// OpenSSL PBKD uses only one hash cycle (count)
        /// </remarks>
        private byte[] GetOpenSSL3DesKey(byte[] salt, SecureString secpswd, int count, int miter)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            int HASHLENGTH = 16;	//MD5 bytes
            byte[] keymaterial = new byte[HASHLENGTH * miter];     //to accumulate Mi hashed results


            byte[] psbytes = new byte[secpswd.Length];
            unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
            Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

            // --- set salt and password bytes into fixed data array ---
            byte[] data00 = new byte[psbytes.Length + salt.Length];
            Array.Copy(psbytes, data00, psbytes.Length);		//copy the password bytes
            Array.Copy(salt, 0, data00, psbytes.Length, salt.Length);	//concatenate the salt bytes

            // ---- do multi-hashing and accumulate results  D1, D2 ...  into key-material bytes ----
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = null;
            byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hash target

            for (int j = 0; j < miter; j++)
            {
                // ----  Now hash consecutively for 'count' times ------
                if (j == 0)
                {
                    result = data00;   	//initialize 
                }
                else
                {
                    Array.Copy(result, hashtarget, result.Length);
                    Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                    result = hashtarget;
                }

                for (int i = 0; i < count; i++)
                {
                    result = md5.ComputeHash(result);
                }

                Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //accumulate to key-material
            }

            byte[] deskey = new byte[24];
            Array.Copy(keymaterial, deskey, deskey.Length);

            return deskey; 
        }


        /// <summary>
        /// Decrypts the key.
        /// </summary>
        /// <param name="cipherData">The cipher data.</param>
        /// <param name="desKey">The DES key.</param>
        /// <param name="IV">The IV vector</param>
        /// <returns>Decrypted key</returns>
        private byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
        {
            MemoryStream memst = new MemoryStream();
            TripleDES alg = TripleDES.Create();
            alg.Key = desKey;
            alg.IV = IV;
            
            try
            {
                CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(cipherData, 0, cipherData.Length);
                cs.Close();
            }
            catch (Exception exc)
            {
                throw new ApplicationException("Could not decrypt OpenSLL (Encrypted) Private key!", exc);
            }

            byte[] decryptedData = memst.ToArray();
            return decryptedData; 
        }
    }
}
