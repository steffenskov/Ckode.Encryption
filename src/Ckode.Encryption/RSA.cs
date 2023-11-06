using System.Security.Cryptography;
using System.Text;

namespace Ckode.Encryption;

/// <summary>
///     Wrapper around the asymmetrical RSA encryption. Offers encryption/decryption using a pair of
///     keys (public / private).
/// </summary>
public class RSA
{
	/// <summary>
	///     Initializes a new instance of the <see cref="Ckode.Encryption.RSA" /> class.
	/// </summary>
	public RSA()
	{
	}

	/// <summary>
	///     Generates a new unique key pair.
	/// </summary>
	/// <returns>The key pair.</returns>
	public RSAKeyPair GenerateKeyPair()
	{
		using var cipher = new RSACryptoServiceProvider();
		cipher.PersistKeyInCsp = false;
		return new RSAKeyPair(cipher.ToXmlString(false), cipher.ToXmlString(true));
	}

	/// <summary>
	///     Represent a pair of matching public and private keys.
	/// </summary>
	public class RSAKeyPair
	{
		/// <summary>
		///     Initializes a new instance of the <see cref="Ckode.Encryption.RSA.RSAKeyPair" /> class.
		/// </summary>
		/// <param name="publicKey">Public key.</param>
		/// <param name="privateKey">Private key.</param>
		public RSAKeyPair(string publicKey, string privateKey)
		{
			PublicKey = publicKey;
			PrivateKey = privateKey;
		}

		/// <summary>
		///     Gets the private key.
		/// </summary>
		/// <value>The private key.</value>
		public string PrivateKey { get; }

		/// <summary>
		///     Gets the public key.
		/// </summary>
		/// <value>The public key.</value>
		public string PublicKey { get; }
	}

	#region Encryption

	/// <summary>
	///     Encrypt the specified text using the given encoding to get the bytes, and using the given
	///     key pair.
	/// </summary>
	/// <param name="text">Text to encrypt.</param>
	/// <param name="encoding">Encoding of the string.</param>
	/// <param name="keyPair">Key pair to use for the encryption.</param>
	public byte[] Encrypt(string text, Encoding encoding, RSAKeyPair keyPair)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		return Encrypt(text, encoding, keyPair.PublicKey);
	}

	/// <summary>
	///     Encrypt the specified text using the given encoding to get the bytes, and using the given
	///     public key.
	/// </summary>
	/// <param name="text">Text to encrypt.</param>
	/// <param name="encoding">Encoding of the string.</param>
	/// <param name="publicKey">Public key to use for the encryption.</param>
	public byte[] Encrypt(string text, Encoding encoding, string publicKey)
	{
		if (text == null) throw new ArgumentNullException(nameof(text));

		if (encoding == null) throw new ArgumentNullException(nameof(encoding));

		return Encrypt(encoding.GetBytes(text), publicKey);
	}

	/// <summary>
	///     Encrypt the specified bytes using the given key pair.
	/// </summary>
	/// <param name="bytes">Bytes to encrypt.</param>
	/// <param name="keyPair">Key pair to use for the encryption.</param>
	public byte[] Encrypt(byte[] bytes, RSAKeyPair keyPair)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		return Encrypt(bytes, keyPair.PublicKey);
	}

	/// <summary>
	///     Encrypt the specified bytes using the given encryption key.
	/// </summary>
	/// <param name="bytes">Bytes to encrypt.</param>
	/// <param name="publicKey">Encryption key to use for the encryption.</param>
	public byte[] Encrypt(byte[] bytes, string publicKey)
	{
		using var cipher = CreateCipherForEncryption(publicKey);
		return cipher.Encrypt(bytes, false);
	}

	#endregion Encryption

	#region Decryption

	/// <summary>
	///     Decrypt the specified bytes using the key pair into a string, encoded using the
	///     given encoding.
	/// </summary>
	/// <param name="bytes">Bytes to decrypt.</param>
	/// <param name="encoding">Encoding of the string.</param>
	/// <param name="keyPair">Key pair to use for the decryption.</param>
	public string Decrypt(byte[] bytes, Encoding encoding, RSAKeyPair keyPair)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		return Decrypt(bytes, encoding, keyPair.PrivateKey);
	}

	/// <summary>
	///     Decrypt the specified bytes using the decryption key into a string, encoded using the
	///     given encoding.
	/// </summary>
	/// <param name="bytes">Bytes to decrypt.</param>
	/// <param name="encoding">Encoding of the string.</param>
	/// <param name="privateKey">Decryption key to use for the decryption.</param>
	public string Decrypt(byte[] bytes, Encoding encoding, string privateKey)
	{
		if (encoding == null) throw new ArgumentNullException(nameof(encoding));

		return encoding.GetString(Decrypt(bytes, privateKey));
	}

	/// <summary>
	///     Decrypt the specified bytes using the given key pair.
	/// </summary>
	/// <param name="bytes">Bytes to decrypt.</param>
	/// <param name="keyPair">Key pair to use for the decryption.</param>
	public byte[] Decrypt(byte[] bytes, RSAKeyPair keyPair)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		return Decrypt(bytes, keyPair.PrivateKey);
	}

	/// <summary>
	///     Decrypt the specified bytes using the given private key.
	/// </summary>
	/// <param name="bytes">Bytes to decrypt.</param>
	/// <param name="privateKey">Private key to use for the decryption.</param>
	public byte[] Decrypt(byte[] bytes, string privateKey)
	{
		if (bytes == null) throw new ArgumentNullException(nameof(bytes));

		using var cipher = CreateCipherForDecryption(privateKey);
		return cipher.Decrypt(bytes, false);
	}

	#endregion Decryption

	#region Cipher creation

	private static RSACryptoServiceProvider CreateCipherForDecryption(string privateKey)
	{
		if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));

		var cipher = new RSACryptoServiceProvider { PersistKeyInCsp = false };
		cipher.FromXmlString(privateKey);
		return cipher;
	}

	private static RSACryptoServiceProvider CreateCipherForEncryption(string publicKey)
	{
		if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));

		var cipher = new RSACryptoServiceProvider { PersistKeyInCsp = false };
		cipher.FromXmlString(publicKey);
		return cipher;
	}

	#endregion Cipher creation
}