using System;

namespace Ckode.Encryption
{
    internal static class Extensions
    {
        public static T[] GetSubArray<T>(this T[] array, int startIndex)
        {
            var length = array.Length - startIndex;
            return array.GetSubArray(startIndex, length);
        }

        public static T[] GetSubArray<T>(this T[] array, int startIndex, int length)
        {
            var result = new T[length];
            Array.Copy(array, startIndex, result, 0, length);
            return result;
        }

        public static void Insert<T>(this T[] destinationArray, int startIndex, T[] subArray)
        {
            if (subArray.Length + startIndex > destinationArray.Length)
                throw new IndexOutOfRangeException("Cannot insert subArray into array at position " + startIndex + ". Destination array isn't large enough.");

            Array.Copy(subArray, 0, destinationArray, startIndex, subArray.Length);
        }
    }
}