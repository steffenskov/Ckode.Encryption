using System.Security.Cryptography;
using Xunit;

namespace Ckode.Encryption.Tests
{
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
	}
}
