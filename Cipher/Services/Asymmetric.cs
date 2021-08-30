using Cipher.Utilities;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Cipher.Services
{
    public class Asymmetric: IAsymmetric
    {
        private readonly RSACryptoServiceProvider _rsa;
        public Asymmetric()
        {
            _rsa = new RSACryptoServiceProvider(2048);
        }

        public (string publicKey, string privateKey) KeyGenerator() => (_rsa.ToXmlString(false), _rsa.ToXmlString(true));

        public string Encrypt(string text, string publicKey)
        {
            Ensure.ArgumentNotNullOrEmptyString(text, nameof(text));
            Ensure.ArgumentNotNullOrEmptyString(publicKey, nameof(publicKey));

            return RsaEncrypt(text, publicKey);
        }

        public string Encrypt<T>(T data, string publicKey)
        {
            Ensure.ArgumentNotNull(data, nameof(data));
            Ensure.ArgumentNotNullOrEmptyString(publicKey, nameof(publicKey));

            var serializedData = JsonConvert.SerializeObject(data);

            return RsaEncrypt(serializedData, publicKey);
        }

        public string Decrypt(string cipherData, string privateKey)
        {
            Ensure.ArgumentNotNullOrEmptyString(privateKey, nameof(privateKey));
            Ensure.ArgumentNotNullOrEmptyString(cipherData, nameof(cipherData));

            return RsaDecrypt(cipherData, privateKey);
        }

        public T Decrypt<T>(string cipherData, string privateKey)
        {
            Ensure.ArgumentNotNullOrEmptyString(privateKey, nameof(privateKey));
            Ensure.ArgumentNotNullOrEmptyString(cipherData, nameof(cipherData));

            var decryptedData = RsaDecrypt(cipherData, privateKey);

            var result = JsonConvert.DeserializeObject<T>(decryptedData);

            return result;
        }

        private string RsaEncrypt(string text, string publicKey) 
        {
            var byteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = byteConverter.GetBytes(text);

            _rsa.FromXmlString(publicKey);

            return Convert.ToBase64String(_rsa.Encrypt(dataToEncrypt, true));
        }

        private string RsaDecrypt(string cipherData, string privateKey)
        {
            byte[] decryptedData;

            _rsa.FromXmlString(privateKey);

            var cipherArray = Convert.FromBase64String(cipherData);

            decryptedData = _rsa.Decrypt(cipherArray, true);

            var byteConverter = new UnicodeEncoding();

            return byteConverter.GetString(decryptedData);
        }
    }
}
