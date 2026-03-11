using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Ckode.Encryption.Tests;

public class HMACTests
{
	[Fact]
	public void GenerateKey_CalledMultipleTimes_ReturnsUniqueValues()
	{
		// Act
		var keys = Enumerable.Range(0, 100)
			.AsParallel()
			.Select(_ => Convert.ToBase64String(HMAC.GenerateKey(() => new HMACSHA3_256())))
			.ToList();

		// Assert
		Assert.Distinct(keys, StringComparer.Ordinal);
	}

	[Fact]
	public void Sign_ByteMessage_CanVerify()
	{
		// Arrange
		var hmac = new HMAC();
		var message = "Hello world"u8.ToArray();
		var key = HMAC.GenerateKey();

		// Act
		var signed = hmac.Sign(message, key);

		// Assert
		var (isValid, retrievedMessage) = hmac.Verify(signed, key);
		Assert.True(isValid);
		Assert.True(message.SequenceEqual(retrievedMessage));
	}

	[Fact]
	public void Sign_StringMessage_CanVerify()
	{
		// Arrange
		var hmac = new HMAC(key => new HMACSHA1(key));
		var message = "Hello world";
		var key = HMAC.GenerateKey(() => new HMACSHA1());

		// Act
		var signed = hmac.Sign(message, Encoding.UTF8, key);

		// Assert
		var (isValid, retrievedMessage) = hmac.Verify(signed, Encoding.UTF8, key);
		Assert.True(isValid);
		Assert.Equal(message, retrievedMessage);
	}

	[Fact]
	public void Verify_MismatchedEncoding_SignatureValidButMessageScrambled()
	{
		// Arrange
		var hmac = new HMAC(key => new HMACSHA384(key));
		var message = "Hello world";
		var key = HMAC.GenerateKey(() => new HMACSHA384());
		var signed = hmac.Sign(message, Encoding.UTF8, key);

		// Act
		var (isValid, retrievedMessage) = hmac.Verify(signed, Encoding.UTF32, key);

		// Assert
		Assert.True(isValid);
		Assert.NotEqual(message, retrievedMessage);
	}
}