using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Ckode.Encryption.Tests;

public class AESTests
{
	[Fact]
	public void AES_GenerateKey_GivesProperAESKey()
	{
		// Arrange
		var aes = new AES();

		// Act
		var key = aes.GenerateKey();

		// Assert
		using var managedAes = Aes.Create();
		Assert.Equal(managedAes.KeySize / 8, key.Length);
	}

	[Fact]
	public void AES_EncryptString_CanDecryptUsingSameKey()
	{
		// Arrange
		var aes = new AES();
		var key = aes.GenerateKey();

		// Act
		var encrypted = aes.Encrypt("Hello world", Encoding.UTF8, key);
		var decrypted = aes.Decrypt(encrypted, Encoding.UTF8, key);

		// Assert
		Assert.Equal("Hello world", decrypted);
	}

	[Fact]
	public void AES_EncryptString_CannotDecryptUsingDifferentKey()
	{
		// Arrange
		var aes = new AES();
		var key = aes.GenerateKey();

		// Act
		var wrongKey = aes.GenerateKey();
		var encrypted = aes.Encrypt("Hello world", Encoding.UTF8, key);

		// Assert
		Assert.Throws<CryptographicException>(() => aes.Decrypt(encrypted, Encoding.UTF8, wrongKey));
	}

	[Fact]
	public void AES_EncryptBytes_CanDecryptUsingSameKey()
	{
		// Arrange
		var aes = new AES();
		byte[] bytes = { 1, 2, 3, 4, 5 };
		var key = aes.GenerateKey();

		// Act
		var encrypted = aes.Encrypt(bytes, key);
		var decrypted = aes.Decrypt(encrypted, key);

		// Assert
		Assert.Equal(bytes, decrypted);
	}

	[Fact]
	public void AES_EncryptBytes_CannotDecryptUsingDifferentKey()
	{
		// Arrange
		var aes = new AES();
		byte[] bytes = { 1, 2, 3, 4, 5 };
		var key = aes.GenerateKey();

		// Act
		var wrongKey = aes.GenerateKey();
		var encrypted = aes.Encrypt(bytes, key);

		// Assert
		Assert.Throws<CryptographicException>(() => aes.Decrypt(encrypted, wrongKey));
	}
}