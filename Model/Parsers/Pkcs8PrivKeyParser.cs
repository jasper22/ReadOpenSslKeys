using System;
using System.Security.Cryptography;

namespace LoadOpenSslKeys.Model.Parsers
{
    internal class Pkcs8PrivKeyParser : ParserBase, IParser
    {
        internal const String HEADER = "-----BEGIN PRIVATE KEY-----";
        internal const String FOOTER = "-----END PRIVATE KEY-----";

        private byte[] keyRawData;

        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs8PrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data as text</param>
        /// <exception cref="System.ApplicationException">Invalid PKCS # 8 Private key</exception>
        internal Pkcs8PrivKeyParser(string data)
            : base(HEADER, FOOTER, data)
        {
            this.Rsa = null;

            try
            {
                this.keyRawData = base.DecodeKey();
            }
            catch (Exception exp_gen)
            {
                throw new ApplicationException("Invalid PKCS # 8 Private key", exp_gen);
            }

            this.Rsa = DecodePrivateKeyInfo(keyRawData);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Pkcs8PrivKeyParser" /> class.
        /// </summary>
        /// <param name="data">The key raw data.</param>
        internal Pkcs8PrivKeyParser(byte[] data)
            : base()
        {
            this.keyRawData = data;
            this.Rsa = DecodePrivateKeyInfo(keyRawData);
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
    }
}
