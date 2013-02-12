using LoadOpenSslKeys.Model.Parsers;
using System.Diagnostics.Contracts;
using System.IO;
using System.Security.Cryptography;

namespace LoadOpenSslKeys.Model
{
    /// <summary>
    /// Main 'model' object
    /// </summary>
    internal class MainModel
    {
        /// <summary>
        /// Loads the keys file.
        /// </summary>
        /// <param name="fileNameAndPath">The file name and path.</param>
        /// <returns><see cref="RSACryptoServiceProvider"/></returns>
        internal RSACryptoServiceProvider LoadKeysFile(string fileNameAndPath)
        {
            Contract.Requires(string.IsNullOrEmpty(fileNameAndPath) == false);

            string fileData = string.Empty;

            using (StreamReader streamReader = File.OpenText(fileNameAndPath))
            {
                fileData = streamReader.ReadToEnd().Trim();
            }

            IParser parser = null;

            if (fileData.StartsWith("-----BEGIN"))
                parser = ParserFactory.CreatePEMParser(fileData);
            else
                parser = ParserFactory.CreateDERParser(fileNameAndPath);

            return parser.Rsa;
        }
    }
}
