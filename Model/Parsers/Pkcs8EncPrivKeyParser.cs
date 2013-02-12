using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Parser for PKCS #8 (Encrypted) Private key
    /// </summary>
    internal class Pkcs8EncPrivKeyParser : ParserBase, IParser
    {
        internal const String HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        internal const String FOOTER = "-----END ENCRYPTED PRIVATE KEY-----";

        private byte[] keyRawData;
        private string password;

        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs8EncPrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="System.ApplicationException">Invalid PKCS #8 (Encrypted) Private key</exception>
        internal Pkcs8EncPrivKeyParser(string data, string password)
            : base(HEADER, FOOTER, data)
        {
            this.Rsa = null;
            this.password = password;

            try
            {
                this.keyRawData = DecodeKey();
            }
            catch (Exception exp_gen)
            {
                throw new ApplicationException("Invalid PKCS #8 (Encrypted) Private key", exp_gen);
            }

            this.Rsa = DecodeEncryptedPrivateKeyInfo(keyRawData);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs8EncPrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data.</param>
        internal Pkcs8EncPrivKeyParser(byte[] data, string password)
            : base()
        {
            this.keyRawData = data;
            this.password = password;
            this.Rsa = DecodeEncryptedPrivateKeyInfo(keyRawData);
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
        /// Decodes the encrypted private key info.
        /// </summary>
        /// <param name="privKeyEncrypted">The private key</param>
        /// <returns><see cref="RSACryptoServiceProvider"/></returns>
        private RSACryptoServiceProvider DecodeEncryptedPrivateKeyInfo(byte[] privKeyEncrypted)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            // this byte[] includes the sequence byte and terminal encoded null 
            byte[] OIDpkcs5PBES2 = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };
            byte[] OIDpkcs5PBKDF2 = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
            byte[] OIDdesEDE3CBC = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07 };
            byte[] seqdes = new byte[10];
            byte[] seq = new byte[11];
            byte[] salt;
            byte[] IV;
            byte[] encryptedpkcs8;
            byte[] pkcs8;

            int saltsize, ivsize, encblobsize;
            int iterations;

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream memoryStream = new MemoryStream(privKeyEncrypted))
            {
                int lenstream = (int)memoryStream.Length;

                using (BinaryReader binr = new BinaryReader(memoryStream)) //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    try
                    {

                        twobytes = binr.ReadUInt16();
                        if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                        {
                            binr.ReadByte();	//advance 1 byte
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();	//advance 2 bytes
                        }
                        else
                        {
                            return null;
                        }

                        twobytes = binr.ReadUInt16();	//inner sequence
                        if (twobytes == 0x8130)
                        {
                            binr.ReadByte();
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();
                        }


                        seq = binr.ReadBytes(11);		//read the Sequence OID
                        //if (!CompareBytearrays(seq, OIDpkcs5PBES2))	//is it a OIDpkcs5PBES2 ?
                        if (seq.Except(OIDpkcs5PBES2).Any())	//is it a OIDpkcs5PBES2 ?
                        {
                            return null;
                        }

                        twobytes = binr.ReadUInt16();	//inner sequence for pswd salt
                        if (twobytes == 0x8130)
                        {
                            binr.ReadByte();
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();
                        }

                        twobytes = binr.ReadUInt16();	//inner sequence for pswd salt
                        if (twobytes == 0x8130)
                        {
                            binr.ReadByte();
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();
                        }

                        seq = binr.ReadBytes(11);		//read the Sequence OID
                        //if (!CompareBytearrays(seq, OIDpkcs5PBKDF2))	//is it a OIDpkcs5PBKDF2 ?
                        if (seq.Except(OIDpkcs5PBKDF2).Any())	//is it a OIDpkcs5PBKDF2 ?
                        {
                            return null;
                        }

                        twobytes = binr.ReadUInt16();
                        if (twobytes == 0x8130)
                        {
                            binr.ReadByte();
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();
                        }

                        bt = binr.ReadByte();
                        if (bt != 0x04)		//expect octet string for salt
                        {
                            return null;
                        }

                        saltsize = binr.ReadByte();
                        salt = binr.ReadBytes(saltsize);

                        //if (verbose)
                        //    showBytes("Salt for pbkd", salt);
                        bt = binr.ReadByte();
                        if (bt != 0x02) 	//expect an integer for PBKF2 iteration count
                        {
                            return null;
                        }

                        int itbytes = binr.ReadByte();	//PBKD2 iterations should fit in 2 bytes.
                        if (itbytes == 1)
                        {
                            iterations = binr.ReadByte();
                        }
                        else if (itbytes == 2)
                        {
                            iterations = 256 * binr.ReadByte() + binr.ReadByte();
                        }
                        else
                        {
                            return null;
                        }
                        
                        //if (verbose)
                        //    Console.WriteLine("PBKD2 iterations {0}", iterations);

                        twobytes = binr.ReadUInt16();
                        if (twobytes == 0x8130)
                        {
                            binr.ReadByte();
                        }
                        else if (twobytes == 0x8230)
                        {
                            binr.ReadInt16();
                        }


                        seqdes = binr.ReadBytes(10);		//read the Sequence OID
                        //if (!CompareBytearrays(seqdes, OIDdesEDE3CBC))	//is it a OIDdes-EDE3-CBC ?
                        if (seqdes.Except(OIDdesEDE3CBC).Any())	//is it a OIDdes-EDE3-CBC ?
                        {
                            return null;
                        }

                        bt = binr.ReadByte();
                        if (bt != 0x04)		//expect octet string for IV
                        {
                            return null;
                        }

                        ivsize = binr.ReadByte();	// IV byte size should fit in one byte (24 expected for 3DES)
                        IV = binr.ReadBytes(ivsize);
                        
                        //if (verbose)
                        //    showBytes("IV for des-EDE3-CBC", IV);

                        bt = binr.ReadByte();
                        if (bt != 0x04)		// expect octet string for encrypted PKCS8 data
                        {
                            return null;
                        }


                        bt = binr.ReadByte();
                        if (bt == 0x81)
                        {
                            encblobsize = binr.ReadByte();	// data size in next byte
                        }
                        else if (bt == 0x82)
                        {
                            encblobsize = 256 * binr.ReadByte() + binr.ReadByte();
                        }
                        else
                        {
                            encblobsize = bt;		// we already have the data size
                        }


                        encryptedpkcs8 = binr.ReadBytes(encblobsize);
                        //if(verbose)
                        //	showBytes("Encrypted PKCS8 blob", encryptedpkcs8) ;


                        //SecureString secpswd = GetSecPswd("Enter password for Encrypted PKCS #8 ==>");
                        SecureString secpswd = new SecureString();
                        foreach (char singleChar in this.password)
                        {
                            secpswd.AppendChar(singleChar);
                        }
                        
                        pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations);
                        if (pkcs8 == null)	// probably a bad pswd entered.
                        {
                            return null;
                        }

                        //if(verbose)
                        //	showBytes("Decrypted PKCS #8", pkcs8) ;
                        //----- With a decrypted pkcs #8 PrivateKeyInfo blob, decode it to an RSA ---

                        RSACryptoServiceProvider rsa = DecodePrivateKeyInfo(pkcs8);
                        return rsa;
                    }

                    catch (Exception)
                    {
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the PBD k2.
        /// </summary>
        /// <param name="edata">The edata.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="IV">The IV vector</param>
        /// <param name="secpswd">The password.</param>
        /// <param name="iterations">The iterations.</param>
        /// <returns>Un-encrypted key</returns>
        /// <exception cref="System.ApplicationException">Problem in decrypting of PKCS #8 (Encrypted) Private key</exception>
        private byte[] DecryptPBDK2(byte[] edata, byte[] salt, byte[]IV, SecureString secpswd, int iterations)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            byte[] psbytes = new byte[secpswd.Length];
            unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
            Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length);
            Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

            try
            {
                Rfc2898DeriveBytes kd = new Rfc2898DeriveBytes(psbytes, salt, iterations);
                TripleDES decAlg = TripleDES.Create();
                decAlg.Key = kd.GetBytes(24);
                decAlg.IV = IV;

                byte[] cleartext = null;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream decrypt = new CryptoStream(memoryStream, decAlg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        decrypt.Write(edata, 0, edata.Length);
                        decrypt.Flush();
                        decrypt.Close();	// this is REQUIRED.
                    }

                    cleartext = memoryStream.ToArray();
                }

                return cleartext;
            }
            catch (Exception e)
            {
                throw new ApplicationException("Problem in decrypting of PKCS #8 (Encrypted) Private key", e);
            }
        }
    }
}
