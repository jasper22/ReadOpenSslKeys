using System.Security.Cryptography;

namespace LoadOpenSslKeys.Model.Parsers
{
    /// <summary>
    /// Interface declaration for any parser
    /// </summary>
    internal interface IParser
    {
        /// <summary>
        /// Gets the RSA.
        /// </summary>
        /// <value>
        /// The RSA.
        /// </value>
        RSACryptoServiceProvider Rsa { get; }
    }
}
