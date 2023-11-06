using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Ckode.Encryption.Tests;

public class AESWithPasswordTests
{
	[Fact]
	public void AESWithPassword_EncryptString_CanDecryptUsingSameKey()
	{
		// Arrange
		var aes = new AESWithPassword();
		var key = "My secret";

		// Act
		var encrypted = aes.Encrypt("Hello world", Encoding.UTF8, key);
		var decrypted = aes.Decrypt(encrypted, Encoding.UTF8, key);

		// Assert
		Assert.Equal("Hello world", decrypted);
	}

	[Fact]
	public void AESWithPassword_EncryptString_CannotDecryptUsingDifferentKey()
	{
		// Arrange
		var aes = new AESWithPassword();
		var key = "My secret";

		// Act
		var wrongKey = "Could this be the secret?";
		var encrypted = aes.Encrypt("Hello world", Encoding.UTF8, key);

		// Assert
		Assert.Throws<CryptographicException>(() => aes.Decrypt(encrypted, Encoding.UTF8, wrongKey));
	}

	[Fact]
	public void AESWithPassword_EncryptBytes_CanDecryptUsingSameKey()
	{
		// Arrange
		var aes = new AESWithPassword();
		byte[] bytes = { 1, 2, 3, 4, 5 };
		var key = "My secret";

		// Act
		var encrypted = aes.Encrypt(bytes, key);
		var decrypted = aes.Decrypt(encrypted, key);

		// Assert
		Assert.Equal(bytes, decrypted);
	}

	[Fact]
	public void AESWithPassword_EncryptBytes_CannotDecryptUsingDifferentKey()
	{
		// Arrange
		var aes = new AESWithPassword();
		byte[] bytes = { 1, 2, 3, 4, 5 };
		var key = "My secret";

		// Act
		var wrongKey = "Could this be the secret?";
		var encrypted = aes.Encrypt(bytes, key);

		// Assert
		Assert.Throws<CryptographicException>(() => aes.Decrypt(encrypted, wrongKey));
	}
}