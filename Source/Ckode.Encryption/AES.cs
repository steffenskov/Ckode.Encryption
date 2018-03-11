using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Ckode.Encryption.Helpers;

namespace Ckode.Encryption
{
	/// <summary>
	/// Wrapper around the symmetrical AES encryption. Offers encryption/decryption using a byte[] key.
	/// </summary>
	public class AES
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="Ckode.Encryption.AES"/> class.
		/// </summary>
		public AES()
		{
		}

		/// <summary>
		/// Generates a new random key for encryption.
		/// </summary>
		/// <returns>The key.</returns>
		public byte[] GenerateKey()
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = aes.LegalKeySizes.Max(keySize => keySize.MaxSize);

				aes.GenerateKey();
				return aes.Key;
			}
		}

		private byte[] Transform(byte[] bytes, Func<ICryptoTransform> selectCryptoTransform)
		{
			using (var transform = selectCryptoTransform())
			using (var memoryStream = new MemoryStream())
			{
				using (var cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
				{
					cryptoStream.Write(bytes, 0, bytes.Length);
				}
				return memoryStream.ToArray();
			}
		}

		#region Encryption

		/// <summary>
		/// Creates a CryptoStream that encrypts the given input when written to.
		/// </summary>
		/// <param name="input">Input stream to encrypt</param>
		/// <param name="key">Key to use for encryption.</param>
		public CryptoStream Encrypt(Stream input, byte[] key)
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = aes.LegalKeySizes.Max(keySize => keySize.MaxSize);

				aes.GenerateIV();
				aes.Key = key;

				var encryptedCipherHeader = new EncryptedCipher
				{
					Keysize = aes.KeySize,
					Cipher = new byte[0],
					IV = aes.IV
				};

				var headerBytes = encryptedCipherHeader.ToBytes();
				input.Write(headerBytes, 0, headerBytes.Length);

				return new CryptoStream(input, aes.CreateEncryptor(), CryptoStreamMode.Write);
			}
		}

		/// <summary>
		/// Encrypt the specified text using the given encoding to get the bytes, and the password as
		/// encryption key.
		/// </summary>
		/// <param name="text">Text to encrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="key">Key to use for encryption.</param>
		public byte[] Encrypt(string text, Encoding encoding, byte[] key)
		{
			return Encrypt(encoding.GetBytes(text), key);
		}

		/// <summary>
		/// Encrypt the specified bytes using the given key.
		/// </summary>
		/// <param name="bytes">Bytes to encrypt.</param>
		/// <param name="key">Key to use for encryption.</param>
		public byte[] Encrypt(byte[] bytes, byte[] key)
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = aes.LegalKeySizes.Max(keySize => keySize.MaxSize);

				aes.GenerateIV();
				aes.Key = key;

				var cipher = Transform(bytes, aes.CreateEncryptor);

				return new EncryptedCipher
				{
					Keysize = aes.KeySize,
					Cipher = cipher,
					IV = aes.IV
				}.ToBytes();
			}
		}

		#endregion Encryption

		#region Decryption

		/// <summary>
		/// Creates a CryptoStream that decrypts the given input stream when read from.
		/// </summary>
		/// <param name="input">Input stream to decrypts</param>
		/// <param name="key">The key the cipher was encrypted with.</param>
		public Stream Decrypt(Stream input, byte[] key)
		{
			var encryptedCipher = new EncryptedCipher(input);

			using (var aes = new AesManaged())
			{
				aes.KeySize = encryptedCipher.Keysize;
				aes.IV = encryptedCipher.IV;
				aes.Key = key;

				return new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
			}
		}

		/// <summary>
		/// Decrypt the specified bytes using the password into a string, encoded using the given encoding.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="key">The key the cipher was encrypted with.</param>
		public string Decrypt(byte[] bytes, Encoding encoding, byte[] key)
		{
			return encoding.GetString(Decrypt(bytes, key));
		}

		/// <summary>
		/// Decrypt the specified bytes using the password.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="key">The key the cipher was encrypted with.</param>
		public byte[] Decrypt(byte[] bytes, byte[] key)
		{
			var encryptedCipher = new EncryptedCipher(bytes);

			using (var aes = new AesManaged())
			{
				aes.KeySize = encryptedCipher.Keysize;
				aes.IV = encryptedCipher.IV;
				aes.Key = key;

				return Transform(encryptedCipher.Cipher, aes.CreateDecryptor);
			}
		}

		#endregion Decryption
	}
}