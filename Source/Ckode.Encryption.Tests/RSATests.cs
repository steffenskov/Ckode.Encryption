using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Ckode.Encryption.Tests
{
	public class RSATests
	{
		[Fact]
		public void RSA_EncryptStringIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null, Encoding.UTF8, keyPair));
		}

		[Fact]
		public void RSA_DecryptStringIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(null, Encoding.UTF8, keyPair));
		}

		[Fact]
		public void RSA_EncryptStringKeyIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt("Hello world", Encoding.UTF8, publicKey: null));
		}

		[Fact]
		public void RSA_DecryptStringKeyIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted, Encoding.UTF8, privateKey: null));
		}

		[Fact]
		public void RSA_EncryptStringKeyPairIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt("Hello world", Encoding.UTF8, keyPair: null));
		}

		[Fact]
		public void RSA_DecryptStringKeyPairIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted, Encoding.UTF8, keyPair: null));
		}

		[Fact]
		public void RSA_EncryptStringWithKeyPairEncodingIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt("Hello world", null, keyPair));
		}

		[Fact]
		public void RSA_EncryptStringWithPublicKeyEncodingIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt("Hello world", null, keyPair.PublicKey));
		}

		[Fact]
		public void RSA_DecryptStringWithKeyPairEncodingIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted, null, keyPair));
		}

		[Fact]
		public void RSA_DecryptStringWithPrivateKeyEncodingIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted, null, keyPair.PrivateKey));
		}

		[Fact]
		public void RSA_EncryptString_CanDecryptUsingPrivateKey()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);
			var decrypted = rsa.Decrypt(encrypted, Encoding.UTF8, keyPair);

			// Assert
			Assert.Equal("Hello world", decrypted);
		}

		[Fact]
		public void RSA_EncryptString_CannotDecryptUsingDifferentKey()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var wrongKey = rsa.GenerateKeyPair();
			var encrypted = rsa.Encrypt("Hello world", Encoding.UTF8, keyPair);

			// Assert
			Assert.ThrowsAny<CryptographicException>(() => rsa.Decrypt(encrypted, Encoding.UTF8, wrongKey));
		}

		[Fact]
		public void RSA_EncryptBytesIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var keyPair = rsa.GenerateKeyPair();

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(null,  keyPair));
		}

		[Fact]
		public void RSA_EncryptBytesKeyIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(bytes, publicKey: null));
		}

		[Fact]
		public void RSA_DecryptBytesKeyIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt(bytes, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted, privateKey: null));
		}

		[Fact]
		public void RSA_EncryptBytesKeyPairIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Encrypt(bytes, keyPair: null));
		}

		[Fact]
		public void RSA_DecryptBytesKeyPairIsNull_Throws()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt(bytes, keyPair);

			// Assert
			Assert.Throws<ArgumentNullException>(() => rsa.Decrypt(encrypted,  keyPair: null));
		}

		[Fact]
		public void RSA_EncryptBytes_CanDecryptUsingSameKey()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var encrypted = rsa.Encrypt(bytes, keyPair);
			var decrypted = rsa.Decrypt(encrypted, keyPair);

			// Assert
			Assert.Equal(bytes, decrypted);
		}

		[Fact]
		public void RSA_EncryptBytes_CannotDecryptUsingDifferentKey()
		{
			// Arrange
			var rsa = new RSA();
			var bytes = new byte[] { 1, 2, 3, 4, 5 };
			var keyPair = rsa.GenerateKeyPair();

			// Act
			var wrongKey = rsa.GenerateKeyPair();
			var encrypted = rsa.Encrypt(bytes, keyPair);

			// Assert
			Assert.ThrowsAny<CryptographicException>(() => rsa.Decrypt(encrypted, wrongKey));
		}
	}
}
