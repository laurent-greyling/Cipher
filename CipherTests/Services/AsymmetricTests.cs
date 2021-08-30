using Cipher.Services;
using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace CipherTests.Services
{
    [ExcludeFromCodeCoverage]
    public class AsymmetricTests
    {
        private readonly Asymmetric _asymmetric;

        private readonly string _cipherText = "FakeCipherText";
        private readonly object[] _cipherObject = new object[] { 1, "FakeCipherText" };
        private readonly string _publicKey;
        private readonly string _privateKey;

        public AsymmetricTests()
        {
            _asymmetric = new Asymmetric();

            var (publicKey, privateKey) = _asymmetric.KeyGenerator();

            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        [Fact]
        public void Asymmetric_Encrypt_Text_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Encrypt(null, _publicKey));
        }

        [Fact]
        public void Asymmetric_Encrypt_Text_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Encrypt("", _publicKey));
        }

        [Fact]
        public void Asymmetric_Encrypt_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Encrypt(_cipherText, null));
        }

        [Fact]
        public void Asymmetric_Encrypt_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Encrypt(_cipherText, ""));
        }

        [Fact]
        public void Asymmetric_Encrypt_Object_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Encrypt<object>(null, _publicKey));
        }

        [Fact]
        public void Asymmetric_Encrypt_Object_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Encrypt(_cipherObject, null));
        }

        [Fact]
        public void Asymmetric_Encrypt_Object_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Encrypt(_cipherObject, ""));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Object_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Decrypt<object>(_cipherText, null));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Object_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Decrypt<object>(_cipherText, ""));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Decrypt(_cipherText, null));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Decrypt(_cipherText, ""));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Object_Data_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Decrypt<object>(null, _privateKey));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Object_Data_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Decrypt<object>("", _privateKey));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Data_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _asymmetric.Decrypt(null, _privateKey));
        }

        [Fact]
        public void Asymmetric_Dencrypt_Data_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _asymmetric.Decrypt("", _privateKey));
        }

        [Fact]
        public void Asymmetric_Decrypt_Returns_Correct_Result()
        {
            var encrypt = _asymmetric.Encrypt(_cipherText, _publicKey);
            var result = _asymmetric.Decrypt(encrypt, _privateKey);

            Assert.Equal(_cipherText, result);
        }

        [Fact]
        public void Asymmetric_Decrypt_Object_Returns_Correct_Result()
        {
            var encrypt = _asymmetric.Encrypt(_cipherObject, _publicKey);
            var result = _asymmetric.Decrypt<object[]>(encrypt, _privateKey);

            Assert.Equal(_cipherObject[1], result[1]);
        }

        [Fact]
        public void Asymmetric_Decrypt_Manipulated_String_Exception_Returns_Nonsense()
        {
            var encrypt = _asymmetric.Encrypt(_cipherText, _publicKey);

            Assert.Throws<FormatException>(() => _asymmetric.Decrypt($"{encrypt.Trim('=')}123", _privateKey));
        }
        [Fact]
        public void Asymmetric_Encrypt_Text()
        {
            var result = _asymmetric.Encrypt(_cipherText, _publicKey);
            Assert.True(result != _cipherText && result != string.Empty);
        }

        [Fact]
        public void Asymmetric_Encrypt_Object()
        {
            var result = _asymmetric.Encrypt<int>(1, _publicKey);
            Assert.True(result != _cipherText && result != string.Empty);
        }

        [Fact]
        public void Asymmetric_GenerateKey_ReturnKey()
        {
            var (publicKey, privateKey) = _asymmetric.KeyGenerator();
            Assert.True(publicKey != string.Empty);
            Assert.True(privateKey != string.Empty);
        }
    }
}
