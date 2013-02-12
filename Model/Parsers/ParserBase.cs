using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Base class for all parsers
    /// </summary>
    internal abstract class ParserBase
    {
        private string header, footer, data;

        /// <summary>
        /// Initializes a new instance of the <see cref="ParserBase" /> class.
        /// </summary>
        internal ParserBase()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ParserBase" /> class.
        /// </summary>
        /// <param name="header">The 'header' in text file</param>
        /// <param name="footer">The 'footer' in text file</param>
        /// <param name="data">The key data as text</param>
        internal ParserBase(string header, string footer, string data)
        {
            this.header = header;
            this.footer = footer;
            this.data = data;
        }

        /// <summary>
        /// Gets the key raw data.
        /// </summary>
        /// <value>
        /// The key raw data.
        /// </value>
        internal string KeyRawData
        {
            get
            {
                return data;
            }
        }

        /// <summary>
        /// Decodes the key from text and return it as byte array
        /// </summary>
        /// <returns>Key data as byte array</returns>
        internal virtual byte[] DecodeKey()
        {
            Contract.Requires(string.IsNullOrEmpty(data) == false);

            StringBuilder strBuilder = new StringBuilder(data);
            strBuilder.Replace(header, string.Empty);
            strBuilder.Replace(footer, string.Empty);

            string strKeyData = strBuilder.ToString().Trim();
            byte[] keyData = null;

            try
            {
                keyData = Convert.FromBase64String(strKeyData);
                return keyData;
            }
            catch (Exception exp_gen)
            {
                throw exp_gen;
            }
        }

        /// <summary>
        /// Parses binary ans.1 RSA private key
        /// </summary>
        /// <param name="x509Key">Raw key data</param>
        /// <returns><see cref="RSACryptoServiceProvider"/></returns>
        internal virtual RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] x509Key)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            using (MemoryStream memoryStream = new MemoryStream(x509Key))
            {
                using (BinaryReader binr = new BinaryReader(memoryStream))    //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;
                    int elems = 0;

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

                        twobytes = binr.ReadUInt16();
                        if (twobytes != 0x0102)	//version number
                        {
                            return null;
                        }

                        bt = binr.ReadByte();
                        if (bt != 0x00)
                        {
                            return null;
                        }


                        //------  all private key components are Integer sequences ----
                        elems = GetIntegerSize(binr);
                        MODULUS = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        E = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        D = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        P = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        Q = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        DP = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        DQ = binr.ReadBytes(elems);

                        elems = GetIntegerSize(binr);
                        IQ = binr.ReadBytes(elems);

                        // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                        RSAParameters RSAparams = new RSAParameters();
                        RSAparams.Modulus = MODULUS;
                        RSAparams.Exponent = E;
                        RSAparams.D = D;
                        RSAparams.P = P;
                        RSAparams.Q = Q;
                        RSAparams.DP = DP;
                        RSAparams.DQ = DQ;
                        RSAparams.InverseQ = IQ;
                        RSA.ImportParameters(RSAparams);
                        return RSA;
                    }
                    catch (Exception)
                    {
                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Gets the size of the integer.
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns>Integer size</returns>
        private int GetIntegerSize(BinaryReader reader)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;

            bt = reader.ReadByte();
            if (bt != 0x02)		//expect integer
            {
                return 0;
            }

            bt = reader.ReadByte();
            if (bt == 0x81)
            {
                count = reader.ReadByte();	// data size in next byte
            }
            else
            {
                if (bt == 0x82)
                {
                    highbyte = reader.ReadByte();	// data size in next 2 bytes
                    lowbyte = reader.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;		// we already have the data size
                }
            }

            while (reader.ReadByte() == 0x00)
            {	//remove high order zeros in data
                count -= 1;
            }

            reader.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte

            return count;
        }

        /// <summary>
        /// Parses binary asn.1 PKCS #8 PrivateKeyInfo
        /// </summary>
        /// <param name="pkcs8Key">Raw key data</param>
        /// <returns><see cref="RSACryptoServiceProvider"/></returns>
        internal RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8Key)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            // this byte[] includes the sequence byte and terminal encoded null 
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream memoryStream = new MemoryStream(pkcs8Key))
            {
                int lenstream = (int)memoryStream.Length;

                using (BinaryReader binr = new BinaryReader(memoryStream))    //wrap Memory Stream with BinaryReader for easy reading
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


                        bt = binr.ReadByte();
                        if (bt != 0x02)
                        {
                            return null;
                        }

                        twobytes = binr.ReadUInt16();
                        if (twobytes != 0x0001)
                        {
                            return null;
                        }

                        seq = binr.ReadBytes(15);		//read the Sequence OID
                        //if (!CompareBytearrays(seq, SeqOID))	//make sure Sequence for OID is correct
                        if (seq.Except(SeqOID).Any())
                        {
                            return null;
                        }

                        bt = binr.ReadByte();
                        if (bt != 0x04)	//expect an Octet string 
                        {
                            return null;
                        }

                        bt = binr.ReadByte();		//read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                        if (bt == 0x81)
                        {
                            binr.ReadByte();
                        }
                        else
                        {
                            if (bt == 0x82)
                            {
                                binr.ReadUInt16();
                            }
                        }
                        //------ at this stage, the remaining sequence should be the RSA private key

                        byte[] rsaprivkey = binr.ReadBytes((int)(lenstream - memoryStream.Position));
                        RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
                        return rsacsp;
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
