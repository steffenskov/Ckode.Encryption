using System.Security.Cryptography;
using System.Text;

namespace Ckode.Encryption;

public delegate KeyedHashAlgorithm KeyedHashAlgorithmFactory(byte[] key);

/// <summary>
///     Wrapper class around HMAC based algorithms. Offer signing and verification of messages using fixed-time
///     comparison for verification.
/// </summary>
public class HMAC
{
	private readonly KeyedHashAlgorithmFactory _algorithmFactory;

	/// <summary>
	///     Instantiate a new HMAC using SHA3-512
	/// </summary>
	public HMAC() : this(key => new HMACSHA3_512(key))
	{
	}

	/// <summary>
	///     Instantiate a new HMAC with the algorithm of your choice.
	/// </summary>
	/// <param name="algorithmFactory">Factory method to instantiate the desired algorithm</param>
	public HMAC(KeyedHashAlgorithmFactory algorithmFactory)
	{
		_algorithmFactory = algorithmFactory;
	}

	/// <summary>
	///     Generate a key for the default SHA3-512 algorithm using its default constructor.
	/// </summary>
	/// <returns>Randomly generated key to use for signing</returns>
	public static byte[] GenerateKey()
	{
		return GenerateKey(() => new HMACSHA3_512());
	}

	/// <summary>
	///     Generate a key for the given algorithm using its default constructor.
	/// </summary>
	/// <param name="algorithmFactory">Factory method to instantiate the desired algorithm</param>
	/// <returns>Randomly generated key to use for signing</returns>
	public static byte[] GenerateKey(Func<KeyedHashAlgorithm> algorithmFactory)
	{
		using var hmac = algorithmFactory();
		return hmac.Key;
	}

	#region Sign

	/// <summary>
	///     Signs a message using the supplied encoding and key.
	/// </summary>
	/// <param name="message">message to sign</param>
	/// <param name="encoding">encoding to use for signing</param>
	/// <param name="key">key to use for signing</param>
	/// <returns>HMAC signature and message combined</returns>
	public byte[] Sign(string message, Encoding encoding, byte[] key)
	{
		return Sign(encoding.GetBytes(message), key);
	}

	/// <summary>
	///     Signs a message using the supplied key.
	/// </summary>
	/// <param name="message">message to sign</param>
	/// <param name="key">key to use for signing</param>
	/// <returns>HMAC signature and message combined</returns>
	public byte[] Sign(byte[] message, byte[] key)
	{
		using var hmac = _algorithmFactory(key);

		var hash = hmac.ComputeHash(message);

		return [..hash, ..message];
	}

	#endregion

	#region Verify

	/// <summary>
	///     Verifies a combined HMAC signature and message, and returns the message as a string using the supplied encoding.
	/// </summary>
	/// <param name="combinedMessage">The combined HMAC signature and message.</param>
	/// <param name="encoding">encoding to use for decoding the message</param>
	/// <param name="key">key that was used for signing</param>
	/// <returns>Verification answer as well as message</returns>
	public (bool IsValid, string Message) Verify(byte[] combinedMessage, Encoding encoding, byte[] key)
	{
		var (isValid, message) = Verify(combinedMessage, key);
		return (isValid, encoding.GetString(message));
	}

	/// <summary>
	///     Verifies a combined HMAC signature and message, and returns the message.
	/// </summary>
	/// <param name="combinedMessage">The combined HMAC signature and message.</param>
	/// <param name="key">key that was used for signing</param>
	/// <returns>Verification answer as well as message</returns>
	public (bool IsValid, byte[] Message) Verify(byte[] combinedMessage, byte[] key)
	{
		using var hmac = _algorithmFactory(key);
		var hashLength = hmac.HashSize / 8;
		var signedHmac = combinedMessage[..hashLength];
		var message = combinedMessage[hashLength..];

		var computedHmac = hmac.ComputeHash(message);
		var isValid = CryptographicOperations.FixedTimeEquals(computedHmac, signedHmac);

		return (isValid, message);
	}

	#endregion
}