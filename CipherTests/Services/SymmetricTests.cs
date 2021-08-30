using Cipher.Services;
using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace CipherTests.Services
{
    [ExcludeFromCodeCoverage]
    public class SymmetricTests
    {
        private const string _fakeCipherText = "FakeCipherText12";
        private readonly string _aesKey;

        private readonly Symmetric _symmetric;

        public SymmetricTests()
        {
            _symmetric = new Symmetric();

            _aesKey = _symmetric.KeyGenerator();
        }

        [Fact]
        public void Symmetric_Decrypt_Text_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Decrypt(null, _aesKey));
        }

        [Fact]
        public void Symmetric_Decrypt_Text_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Decrypt("", _aesKey));
        }

        [Fact]
        public void Symmetric_Decrypt_Object_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Decrypt<object>(null, _aesKey));
        }

        [Fact]
        public void Symmetric_Decrypt_Overload_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Decrypt<object>(_fakeCipherText, null));
        }

        [Fact]
        public void Symmetric_Decrypt_Overload_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Decrypt<object>(_fakeCipherText, ""));
        }

        [Fact]
        public void Symmetric_Decrypt_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Decrypt(_fakeCipherText, null));
        }

        [Fact]
        public void Symmetric_Decrypt_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Decrypt(_fakeCipherText, ""));
        }

        [Fact]
        public void Symmetric_Encrypt_Text_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Encrypt(null, _aesKey));
        }

        [Fact]
        public void Symmetric_Encrypt_Object_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Encrypt<object>(null, _aesKey));
        }

        [Fact]
        public void Symmetric_Encrypt_Overload_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Encrypt(new object[] { }, null));
        }

        [Fact]
        public void Symmetric_Encrypt_Overload_Key_Èmpty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Encrypt(new object[] { }, ""));
        }

        [Fact]
        public void Symmetric_Encrypt_Text_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Encrypt("", _aesKey));
        }

        [Fact]
        public void Symmetric_Encrypt_Key_Null_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => _symmetric.Encrypt(_fakeCipherText, null));
        }

        [Fact]
        public void Symmetric_Encrypt_Key_Empty_Throws()
        {
            Assert.Throws<ArgumentException>(() => _symmetric.Encrypt(_fakeCipherText, ""));
        }

        [Fact]
        public void Symmetric_Decrypt_String_Executed()
        {
            var encrypt = _symmetric.Encrypt(_fakeCipherText, _aesKey);
            var result = _symmetric.Decrypt(encrypt, _aesKey);
            Assert.Equal(_fakeCipherText, result);
        }

        [Fact]
        public void Symmetric_Decrypt_Object_Result_Correct()
        {
            var fakeObject = new object[] { _fakeCipherText };
            var encrypt = _symmetric.Encrypt(fakeObject, _aesKey);
            var result = _symmetric.Decrypt<object[]>(encrypt, _aesKey);
            Assert.Equal(fakeObject[0], result[0]);
        }

        [Fact]
        public void Symmetric_Decrypt_Manipulated_String_Exception_Returns_Nonsense()
        {
            var encrypt = _symmetric.Encrypt(_fakeCipherText, _aesKey);

            Assert.Throws<FormatException>(() => _symmetric.Decrypt($"{encrypt.Trim('=')}123", _aesKey));
        }

        [Fact]
        public void Symmetric_Encrypt_Text()
        {
            var result = _symmetric.Encrypt(_fakeCipherText, _aesKey);
            Assert.True(result != _fakeCipherText && result != string.Empty);
        }

        [Fact]
        public void Symmetric_Encrypt_Object()
        {
            var result = _symmetric.Encrypt<int>(1, _aesKey);
            Assert.True(result != _fakeCipherText && result != string.Empty);
        }

        [Fact]
        public void Symmetric_GenerateKey_ReturnKey()
        {
            var result = _symmetric.KeyGenerator();
            Assert.True(result != string.Empty);
        }
    }
}
