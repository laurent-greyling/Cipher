namespace Cipher.Services
{
    public interface IAsymmetric
    {
        /// <summary>
        /// Generates the public and private keys for asymmetric 
        /// </summary>
        /// <returns></returns>
        (string publicKey, string privateKey) KeyGenerator();

        /// <summary>
        /// Encrypt string data in an Asymmetric fashion
        /// </summary>
        /// <param name="text">Text to be decrypted</param>
        /// /// <param name="publicKey">public key to be used for encryption</param>
        /// <returns>Encrypted string</returns>
        string Encrypt(string text, string publicKey);

        /// <summary>
        /// Encrypt generic type data in an Asymmetric fashion
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        string Encrypt<T>(T data, string publicKey);

        /// <summary>
        /// Decrypt string data in an Asymmetric fashion
        /// </summary>
        /// <param name="cipherData">Text to be decrypted</param>
        /// <param name="privateKey">key used for decryption</param>
        /// <returns>Decrypted string</returns>
        string Decrypt(string cipherData, string privateKey);

        /// <summary>
        /// Decrypt string data in an Asymmetric fashion
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="cipherData">Text to be decrypted</param>
        /// <param name="privateKey">key used for decryption</param>
        /// <returns></returns>
        T Decrypt<T>(string cipherData, string privateKey);
    }
}
