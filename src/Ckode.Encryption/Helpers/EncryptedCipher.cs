using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Ckode.Encryption.Helpers;

internal class EncryptedCipher
{
	[SetsRequiredMembers]
	public EncryptedCipher(byte[] bytes)
	{
		var position = 0;

		var keySizeBytes = GetArrayPart(bytes, position);
		position += keySizeBytes.Length + 1;
		KeySize = BitConverter.ToInt32(keySizeBytes, 0);

		IV = GetArrayPart(bytes, position);
		position += IV.Length + 1;

		CipherPosition = position;
		Cipher = bytes.GetSubArray(position);
	}

	public EncryptedCipher()
	{
	}

	public required byte[] Cipher { get; init; }
	public int CipherPosition { get; protected set; }
	public required byte[] IV { get; init; }
	public required int KeySize { get; init; }

	public virtual byte[] ToBytes()
	{
		var keySizeBytes = BitConverter.GetBytes(KeySize);
		return CombineArrays(keySizeBytes, IV, Cipher);
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
			if (i != lastIndex) result[position++] = (byte)innerArray.Length;

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