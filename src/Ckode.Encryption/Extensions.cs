namespace Ckode.Encryption;

internal static class Extensions
{
	public static T[] GetSubArray<T>(this T[] array, int startIndex)
	{
		if (array == null) throw new ArgumentNullException(nameof(array));

		var length = array.Length - startIndex;
		return array.GetSubArray(startIndex, length);
	}

	public static T[] GetSubArray<T>(this T[] array, int startIndex, int length)
	{
		if (array == null) throw new ArgumentNullException(nameof(array));

		if (startIndex < 0) throw new ArgumentOutOfRangeException(nameof(startIndex), $"startIndex ({startIndex}) cannot be less than zero.");

		if (startIndex > array.Length)
			throw new ArgumentOutOfRangeException(nameof(startIndex), $"startIndex ({startIndex}) cannot be higher than the length of the array ({array.Length}).");

		if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), $"length ({length}) cannot be less than zero.");

		if (startIndex + length > array.Length)
			throw new ArgumentOutOfRangeException(nameof(length),
				$"startIndex ({startIndex}) plus length ({length}) cannot be higher than the length of the array ({array.Length}).");

		var result = new T[length];
		Array.Copy(array, startIndex, result, 0, length);
		return result;
	}

	public static void Insert<T>(this T[] destinationArray, int startIndex, T[] subArray)
	{
		if (destinationArray == null) throw new ArgumentNullException(nameof(destinationArray));

		if (subArray == null) throw new ArgumentNullException(nameof(subArray));

		if (startIndex < 0) throw new ArgumentOutOfRangeException(nameof(startIndex), $"startIndex ({startIndex}) cannot be less than zero.");

		if (startIndex > destinationArray.Length)
			throw new ArgumentOutOfRangeException(nameof(startIndex), $"startIndex ({startIndex}) cannot be higher than the length of the array ({destinationArray.Length}).");

		if (subArray.Length + startIndex > destinationArray.Length)
			throw new ArgumentOutOfRangeException(nameof(subArray),
				$"Cannot insert subArray of length {subArray.Length} into destinationArray at position {startIndex}. Destination array isn't large enough (length: {destinationArray.Length}).");

		Array.Copy(subArray, 0, destinationArray, startIndex, subArray.Length);
	}
}