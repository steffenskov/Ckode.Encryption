using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Ckode.Encryption.Helpers;

namespace Ckode.Encryption
{
	/// <summary>
	/// Wrapper around the symmetrical AES encryption. Offers encryption/decryption using a string
	/// password. The password will automatically be strongly hashed.
	/// </summary>
	public class AESWithPassword
	{
		private readonly int _iterations;

		/// <summary>
		/// Initializes a new instance of the <see cref="Ckode.Encryption.AESWithPassword"/> class,
		/// setting how many iterations the used passwords should be hashed with.
		/// </summary>
		/// <param name="iterations">Number of iterations to use for hashing the passwords.</param>
		public AESWithPassword(int iterations = 1 << 15)
		{
			_iterations = iterations;
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

		#region ICipher methods

		#region Encryption

		/// <summary>
		/// Encrypt the specified text using the given encoding to get the bytes, and the password as
		/// encryption key.
		/// </summary>
		/// <param name="text">Text to encrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="password">Password to use as encryption key.</param>
		public byte[] Encrypt(string text, Encoding encoding, string password)
		{
			return Encrypt(encoding.GetBytes(text), password);
		}

		/// <summary>
		/// Encrypt the specified bytes using the password as encryption key.
		/// </summary>
		/// <param name="bytes">Bytes to encrypt.</param>
		/// <param name="password">Password to use as encryption key.</param>
		public byte[] Encrypt(byte[] bytes, string password)
		{
			using (var aes = new AesManaged())
			{
				aes.KeySize = aes.LegalKeySizes.Max(keySize => keySize.MaxSize);
				var saltLength = aes.KeySize / 8;
				var cryptoKey = CreateSaltAndKey(password, saltLength);

				aes.GenerateIV();
				aes.Key = cryptoKey.Key;

				var cipher = Transform(bytes, aes.CreateEncryptor);

				return new EncryptedCipherWithSalt
				{
					Keysize = aes.KeySize,
					Cipher = cipher,
					CryptoSalt = cryptoKey.Salt,
					IV = aes.IV
				}.ToBytes();
			}
		}

		#endregion Encryption

		#region Decryption

		/// <summary>
		/// Decrypt the specified bytes using the password.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="password">Password the cipher was encrypted with.</param>
		public byte[] Decrypt(byte[] bytes, string password)
		{
			var encryptedCipher = new EncryptedCipherWithSalt(bytes);

			using (var aes = new AesManaged())
			{
				aes.KeySize = encryptedCipher.Keysize;
				aes.IV = encryptedCipher.IV;
				aes.Key = CreateKey(password, encryptedCipher.CryptoSalt);

				return Transform(encryptedCipher.Cipher, aes.CreateDecryptor);
			}
		}

		/// <summary>
		/// Decrypt the specified bytes using the password into a string, encoded using the given encoding.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="password">Password the cipher was encrypted with.</param>
		public string Decrypt(byte[] bytes, Encoding encoding, string password)
		{
			return encoding.GetString(Decrypt(bytes, password));
		}

		#endregion Decryption

		#endregion ICipher methods

		#region Key creation

		private byte[] CreateKey(string password, byte[] salt)
		{
			using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, _iterations))
			{
				return deriveBytes.GetBytes(salt.Length);
			}
		}

		private SaltAndKey CreateSaltAndKey(string password, int saltLength)
		{
			using (var deriveBytes = new Rfc2898DeriveBytes(password, saltLength, _iterations))
			{
				return new SaltAndKey
				{
					Salt = deriveBytes.Salt,
					Key = deriveBytes.GetBytes(saltLength)
				};
			}
		}

		private class SaltAndKey
		{
			public byte[] Key { get; set; }
			public byte[] Salt { get; set; }
		}

		#endregion Key creation
	}
}