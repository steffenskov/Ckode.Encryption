using System;
using System.IO;
using System.Linq;

namespace Ckode.Encryption.Helpers
{
	internal class EncryptedCipher
	{
		public EncryptedCipher(byte[] bytes)
		{
			var position = 0;

			var keysizeBytes = GetArrayPart(bytes, position);
			position += keysizeBytes.Length + 1;
			Keysize = BitConverter.ToInt32(keysizeBytes, 0);

			IV = GetArrayPart(bytes, position);
			position += IV.Length + 1;

			CipherPosition = position;
			Cipher = bytes.GetSubArray(position);
		}

		public EncryptedCipher()
		{
		}

		public byte[] Cipher { get; set; }
		public int CipherPosition { get; protected set; }
		public byte[] IV { get; set; }
		public int Keysize { get; set; }

		public virtual byte[] ToBytes()
		{
			var keysizeBytes = BitConverter.GetBytes(Keysize);
			return CombineArrays(keysizeBytes, IV, Cipher);
		}

		protected static byte[] CombineArrays(params byte[][] byteArrays)
		{
			var totalSize = byteArrays.Length - 1 + byteArrays.Sum(innerArray => innerArray.Length); // 1 byte overhead per element except the last, to prepend length
			var result = new byte[totalSize];

			var position = 0;
			var lastIndex = byteArrays.Length - 1;
			for (var i = 0; i < byteArrays.Length; i++)
			{
				var innerArray = byteArrays[i];
				if (i != lastIndex)
				{
					result[position++] = (byte)innerArray.Length;
				}

				result.Insert(position, innerArray);
				position += innerArray.Length;
			}

			return result;
		}

		protected static byte[] GetArrayPart(byte[] cipher, int position)
		{
			var partLength = cipher[position];
			return cipher.GetSubArray(1 + position, partLength);
		}
	}
}