using System;
using System.Security.Cryptography;
using System.Text;

namespace Ckode.Encryption
{
	/// <summary>
	/// Wrapper around the asymmetrical RSA encryption. Offers encryption/decryption using a pair of
	/// keys (public / private).
	/// </summary>
	public class RSA
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="Ckode.Encryption.RSA"/> class.
		/// </summary>
		public RSA()
		{
		}

		/// <summary>
		/// Generates a new unique key pair.
		/// </summary>
		/// <returns>The key pair.</returns>
		public RSAKeyPair GenerateKeyPair()
		{
			using (var cipher = new RSACryptoServiceProvider())
			{
				cipher.PersistKeyInCsp = false;
				return new RSAKeyPair(cipher.ToXmlString(false), cipher.ToXmlString(true));
			}
		}

		/// <summary>
		/// Represent a pair of matching public and private keys.
		/// </summary>
		public class RSAKeyPair
		{
			/// <summary>
			/// Initializes a new instance of the <see cref="Ckode.Encryption.RSA.RSAKeyPair"/> class.
			/// </summary>
			/// <param name="publicKey">Public key.</param>
			/// <param name="privateKey">Private key.</param>
			public RSAKeyPair(string publicKey, string privateKey)
			{
				this.PublicKey = publicKey;
				this.PrivateKey = privateKey;
			}

			/// <summary>
			/// Gets the private key.
			/// </summary>
			/// <value>The private key.</value>
			public string PrivateKey { get; private set; }

			/// <summary>
			/// Gets the public key.
			/// </summary>
			/// <value>The public key.</value>
			public string PublicKey { get; private set; }
		}

		#region Encryption

		/// <summary>
		/// Encrypt the specified bytes using the given encryption key.
		/// </summary>
		/// <param name="bytes">Bytes to encrypt.</param>
		/// <param name="encryptionKey">Encryption key to use for the encryption.</param>
		public byte[] Encrypt(byte[] bytes, string encryptionKey)
		{
			using (var cipher = CreateCipherForEncryption(encryptionKey))
			{
				return cipher.Encrypt(bytes, false);
			}
		}

		/// <summary>
		/// Encrypt the specified text using the given encoding to get the bytes, and using the given
		/// encryption key.
		/// </summary>
		/// <param name="text">Text to encrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="encryptionKey">Encryption key to use for the encryption.</param>
		public byte[] Encrypt(string text, Encoding encoding, string encryptionKey)
		{
			return Encrypt(encoding.GetBytes(text), encryptionKey);
		}

		#endregion Encryption

		#region Decryption

		/// <summary>
		/// Decrypt the specified bytes using the given decryption key.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="decryptionKey">Decryption key to use for the decryption.</param>
		public byte[] Decrypt(byte[] bytes, string decryptionKey)
		{
			using (var cipher = CreateCipherForDecryption(decryptionKey))
			{
				return cipher.Decrypt(bytes, false);
			}
		}

		/// <summary>
		/// Decrypt the specified bytes using the decryption key into a string, encoded using the
		/// given encoding.
		/// </summary>
		/// <param name="bytes">Bytes to decrypt.</param>
		/// <param name="encoding">Encoding of the string.</param>
		/// <param name="decryptionKey">Decryption key to use for the decryption.</param>
		public string Decrypt(byte[] bytes, Encoding encoding, string decryptionKey)
		{
			return encoding.GetString(Decrypt(bytes, decryptionKey));
		}

		#endregion Decryption

		#region Cipher creation

		private RSACryptoServiceProvider CreateCipherForDecryption(string privateKey)
		{
			if (privateKey == null)
				throw new ArgumentNullException(nameof(privateKey));

			var cipher = new RSACryptoServiceProvider
			{
				PersistKeyInCsp = false
			};
			cipher.FromXmlString(privateKey);
			return cipher;
		}

		private RSACryptoServiceProvider CreateCipherForEncryption(string publicKey)
		{
			if (publicKey == null)
				throw new ArgumentNullException(nameof(publicKey));
			var cipher = new RSACryptoServiceProvider
			{
				PersistKeyInCsp = false
			};
			cipher.FromXmlString(publicKey);
			return cipher;
		}

		#endregion Cipher creation
	}
}