using Cipher.Utilities;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cipher.Services
{
    public class Symmetric: ISymmetric
    {
        public string KeyGenerator()
        {
            var cryptoProvider = new AesCryptoServiceProvider
            {
                KeySize = 128,
                BlockSize = 128
            };

            cryptoProvider.GenerateKey();

            var keyGenerated = cryptoProvider.Key;

            return Convert.ToBase64String(keyGenerated);
        }

        public string Decrypt(string cipherText, string key)
        {
            Ensure.ArgumentNotNullOrEmptyString(cipherText, nameof(cipherText));
            Ensure.ArgumentNotNullOrEmptyString(key, nameof(key));

            return AesDecrypt(cipherText, key);
        }

        public T Decrypt<T>(string cipherData, string key)
        {
            Ensure.ArgumentNotNull(cipherData, nameof(cipherData));
            Ensure.ArgumentNotNullOrEmptyString(key, nameof(key));

            var decryptedData = AesDecrypt(cipherData, key);

            var result = JsonConvert.DeserializeObject<T>(decryptedData);

            return result;
        }

        public string Encrypt(string text, string key)
        {
            Ensure.ArgumentNotNullOrEmptyString(text, nameof(text));
            Ensure.ArgumentNotNullOrEmptyString(key, nameof(key));

            return AesEncrypt(text, key);
        }

        public string Encrypt<T>(T data, string key)
        {
            Ensure.ArgumentNotNull(data, nameof(data));
            Ensure.ArgumentNotNullOrEmptyString(key, nameof(key));

            var serializedData = JsonConvert.SerializeObject(data);
            return AesEncrypt(serializedData, key);
        }

        private string AesEncrypt(string text, string key) 
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);

                aes.GenerateIV();
                var iv = Convert.ToBase64String(aes.IV);

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using var memoryStream = new MemoryStream();
                using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(text);
                }

                var encryptedText = Convert.ToBase64String(memoryStream.ToArray());

                return $"{ encryptedText }#{iv}";
            }
        }

        private string AesDecrypt(string cipherText, string key)
        {
            var cipherData = cipherText.Split('#');

            byte[] buffer = Convert.FromBase64String(cipherData[0]);
            byte[] vector = Convert.FromBase64String(cipherData[1]);

            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = vector;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using var memoryStream = new MemoryStream(buffer);
                using CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                using StreamReader streamReader = new StreamReader(cryptoStream);
                return streamReader.ReadToEnd();
            }
        }
    }
}
