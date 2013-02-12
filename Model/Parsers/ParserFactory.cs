using System;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Represent 'factory' that will build correct <see cref="IParser"/> object
    /// </summary>
    /// <remarks>
    /// Parsers implementation was taken from: http://www.jensign.com/opensslkey/opensslkey.cs
    /// </remarks>
    internal class ParserFactory
    {
        /// <summary>
        /// Creates the PEM parser.
        /// </summary>
        /// <param name="data">The key data as text</param>
        /// <param name="password">The password (used for PKCS #8 (Encrypted) Private Key parser)</param>
        /// <returns>Parser that could extract the key</returns>
        /// <exception cref="System.ApplicationException">Unknown file format. Currently supported: OpenSSL Public/Private key, PKCS #8 Private key and PKCS #8 (Encrypted) Private key.</exception>
        internal static IParser CreatePEMParser(string data, string password = "")
        {
            IParser parser = null;

            if (data.StartsWith(OpenSslPubKeyParser.HEADER) && data.EndsWith(OpenSslPubKeyParser.FOOTER))
            {
                System.Diagnostics.Trace.WriteLine("PEM public key");
                parser = new OpenSslPubKeyParser(data);
            }

            if (data.StartsWith(OpenSslPrivKeyParser.HEADER) && data.EndsWith(OpenSslPrivKeyParser.FOOTER))
            {
                System.Diagnostics.Trace.WriteLine("PEM private key");
                parser = new OpenSslPrivKeyParser(data);
            }

            if (data.StartsWith(Pkcs8PrivKeyParser.HEADER) && data.EndsWith(Pkcs8PrivKeyParser.FOOTER))
            {
                System.Diagnostics.Trace.WriteLine("PKCS #8 Private key");
                parser = new Pkcs8PrivKeyParser(data);
            }

            if (data.StartsWith(Pkcs8EncPrivKeyParser.HEADER) && data.EndsWith(Pkcs8EncPrivKeyParser.FOOTER))
            {
                System.Diagnostics.Trace.WriteLine("PKCS #8 (Encoded) Private key");
                parser = new Pkcs8EncPrivKeyParser(data, password);
            }

            if (parser == null)
            {
                throw new ApplicationException("Unknown file format. Currently supported: OpenSSL Public/Private key, PKCS #8 Private key and PKCS #8 (Encrypted) Private key.");
            }

            return parser;
        }

        /// <summary>
        /// Creates the DER parser.
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <param name="password">The password (used for PKCS #8 (Encrypted) Private Key parser)</param>
        /// <returns>Parser that could extract the key</returns>
        internal static IParser CreateDERParser(string fileName, string password = "")
        {
            IParser parser = null;
            byte[] fileData = LoadFileData(fileName);

            if (fileData == null)
            {
                throw new ApplicationException("Key file: " + fileName + " is empty");
            }

            //
            // Try OpenSSSL Public key parser
            parser = new OpenSslPubKeyParser(fileData);
            if (parser.Rsa != null)
            {
                return parser;
            }

            //
            // Try OpenSSL Private key parser
            parser = new OpenSslPrivKeyParser(fileData);
            if (parser.Rsa != null)
            {
                return parser;
            }

            //
            // Try PKCS #8 Private key parser
            parser = new Pkcs8PrivKeyParser(fileData);
            if (parser.Rsa != null)
            {
                return parser;
            }

            //
            // Try PKCS #8 (Encrypted) Private key
            parser = new Pkcs8EncPrivKeyParser(fileData, password);
            if (parser.Rsa != null)
            {
                return parser;
            }

            throw new ApplicationException("Unknown file format. Currently supported: OpenSSL Public/Private key, PKCS #8 Private key and PKCS #8 (Encrypted) Private key.");
        }

        /// <summary>
        /// Loads the file data in binary format
        /// </summary>
        /// <param name="fileName">Name of the file.</param>
        /// <returns>Binary file data</returns>
        private static byte[] LoadFileData(string fileName)
        {
            byte[] data = null;

            using (System.IO.FileStream fStream = new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                using (System.IO.BinaryReader reader = new System.IO.BinaryReader(fStream))
                {
                    data = new byte[fStream.Length];
                    reader.Read(data, 0, data.Length);
                }
            }

            return data;
        }
    }
}
