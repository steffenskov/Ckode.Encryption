using System;
using System.Diagnostics.CodeAnalysis;

namespace Ckode.Encryption.Helpers;

internal class EncryptedCipherWithSalt : EncryptedCipher
{
	public EncryptedCipherWithSalt()
	{
	}

	[SetsRequiredMembers]
	public EncryptedCipherWithSalt(byte[] bytes)
	{
		var position = 0;

		var keySizeBytes = GetArrayPart(bytes, position);
		position += keySizeBytes.Length + 1;
		KeySize = BitConverter.ToInt32(keySizeBytes, 0);

		IV = GetArrayPart(bytes, position);
		position += IV.Length + 1;

		CryptoSalt = GetArrayPart(bytes, position);
		position += CryptoSalt.Length + 1;

		CipherPosition = position;
		Cipher = bytes.GetSubArray(position);
	}

	public required byte[] CryptoSalt { get; init; }

	public override byte[] ToBytes()
	{
		var keySizeBytes = BitConverter.GetBytes(KeySize);
		return CombineArrays(keySizeBytes, IV, CryptoSalt, Cipher);
	}
}