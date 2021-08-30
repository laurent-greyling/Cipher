namespace Cipher.Services
{
    public interface ISymmetric
    {
        /// <summary>
        /// Generates the public key for semmetric
        /// </summary>
        /// <returns></returns>
        string KeyGenerator();

        /// <summary>
        /// Decrypt string data in a Symmetric fashion
        /// </summary>
        /// <param name="cipherText">Text to be decrypted</param>
        /// <param name="key">key used for encryption</param>
        /// <returns>Decrypted string</returns>
        string Decrypt(string cipherText, string key);

        /// <summary>
        /// Decrypt string data in a Symmetric fashion
        /// </summary>
        /// <param name="cipherData">Text to be decrypted</param>
        /// <param name="key">key used for encryption</param>
        /// <returns>Decrypted string</returns>
        T Decrypt<T>(string cipherData, string key);

        /// <summary>
        /// Encrypt string data in a Symmetric fashion
        /// </summary>
        /// <param name="text">Text to be decrypted</param>
        /// /// <param name="key">key to be used for decryption and encryption</param>
        /// <returns>Encrypted string</returns>
        string Encrypt(string text, string key);

        /// <summary>
        /// Encrypt generic type data in a Symmetric fashion
        /// </summary>
        /// <param name="data">data to be decrypted</param>
        /// /// <param name="key">key to be used for decryption and encryption</param>
        /// <returns>Encrypted string</returns>
        string Encrypt<T>(T data, string key);
    }
}
