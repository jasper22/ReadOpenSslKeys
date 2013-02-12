using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Parser for OpenSSL Public key
    /// </summary>
    internal class OpenSslPubKeyParser : ParserBase, IParser
    {
        internal const string HEADER = "-----BEGIN PUBLIC KEY-----";
        internal const string FOOTER = "-----END PUBLIC KEY-----";

        private byte[] keyRawData = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslPubKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key data as text</param>
        /// <exception cref="System.ApplicationException">Invalid OpenSSL Public key!</exception>
        internal OpenSslPubKeyParser(string data)
            : base(HEADER, FOOTER, data)
        {
            this.Rsa = null;

            try
            {
                keyRawData = base.DecodeKey();
            }
            catch (Exception exp_gen)
            {
                throw new ApplicationException("Invalid OpenSSL Public key!", exp_gen);
            }

            this.Rsa = DecodeX509PublicKey(keyRawData);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSslPubKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data.</param>
        internal OpenSslPubKeyParser(byte[] data)
            : base()
        {
            this.keyRawData = data;

            this.Rsa = DecodeX509PublicKey(keyRawData);
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
        /// Decodes the X509 public key.
        /// </summary>
        /// <param name="x509Key">The X509 key.</param>
        /// <returns><see cref="RSACryptoServiceProvider"/></returns>
        private RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509Key)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream memoryStream = new MemoryStream(x509Key))
            {
                using (BinaryReader binaryReader = new BinaryReader(memoryStream))    //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twoBytes = 0;

                    try
                    {

                        twoBytes = binaryReader.ReadUInt16();
                        if (twoBytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                        {
                            binaryReader.ReadByte();	//advance 1 byte
                        }
                        else if (twoBytes == 0x8230)
                        {
                            binaryReader.ReadInt16();	//advance 2 bytes
                        }
                        else
                        {
                            return null;
                        }

                        seq = binaryReader.ReadBytes(15);		//read the Sequence OID
                        //if (!CompareBytearrays(seq, SeqOID))	//make sure Sequence for OID is correct
                        if (seq.Except(SeqOID).Any())        //make sure Sequence for OID is correct
                        {
                            return null;
                        }

                        twoBytes = binaryReader.ReadUInt16();
                        if (twoBytes == 0x8103)	//data read as little endian order (actual data order for Bit String is 03 81)
                        {
                            binaryReader.ReadByte();	//advance 1 byte
                        }
                        else if (twoBytes == 0x8203)
                        {
                            binaryReader.ReadInt16();	//advance 2 bytes
                        }
                        else
                        {
                            return null;
                        }

                        bt = binaryReader.ReadByte();
                        if (bt != 0x00)		//expect null byte next
                        {
                            return null;
                        }

                        twoBytes = binaryReader.ReadUInt16();
                        if (twoBytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                        {
                            binaryReader.ReadByte();	//advance 1 byte
                        }
                        else if (twoBytes == 0x8230)
                        {
                            binaryReader.ReadInt16();	//advance 2 bytes
                        }
                        else
                        {
                            return null;
                        }

                        twoBytes = binaryReader.ReadUInt16();
                        byte lowbyte = 0x00;
                        byte highbyte = 0x00;

                        if (twoBytes == 0x8102)	//data read as little endian order (actual data order for Integer is 02 81)
                        {
                            lowbyte = binaryReader.ReadByte();	// read next bytes which is bytes in modulus
                        }
                        else if (twoBytes == 0x8202)
                        {
                            highbyte = binaryReader.ReadByte();	//advance 2 bytes
                            lowbyte = binaryReader.ReadByte();
                        }
                        else
                        {
                            return null;
                        }

                        byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                        int modsize = BitConverter.ToInt32(modint, 0);

                        byte firstbyte = binaryReader.ReadByte();
                        binaryReader.BaseStream.Seek(-1, SeekOrigin.Current);

                        if (firstbyte == 0x00)
                        {	//if first byte (highest order) of modulus is zero, don't include it
                            binaryReader.ReadByte();	//skip this null byte
                            modsize -= 1;	//reduce modulus buffer size by 1
                        }

                        byte[] modulus = binaryReader.ReadBytes(modsize);	//read the modulus bytes

                        if (binaryReader.ReadByte() != 0x02)			//expect an Integer for the exponent data
                        {
                            return null;
                        }

                        int expbytes = (int)binaryReader.ReadByte();		// should only need one byte for actual exponent data (for all useful values)
                        byte[] exponent = binaryReader.ReadBytes(expbytes);


                        // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSAParameters RSAKeyInfo = new RSAParameters();
                        RSAKeyInfo.Modulus = modulus;
                        RSAKeyInfo.Exponent = exponent;
                        RSA.ImportParameters(RSAKeyInfo);
                        return RSA;
                    }
                    catch (Exception)
                    {
                        return null;
                    }
                }
            }

        }
    }
}
