using System;
using Xunit;

namespace Ckode.Encryption.Tests
{
	public class ExtensionTests
	{
		[Fact]
		public void GetSubArray_ValidSubArray_GivesProperArray()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act
			var subArray = array.GetSubArray(2);

			// Assert
			for (var i = 2; i < array.Length; i++)
			{
				Assert.Equal(array[i], subArray[i - 2]);
			}
		}

		[Fact]
		public void GetSubArray_StartIndexOutside_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.GetSubArray(array.Length + 1));
		}

		[Fact]
		public void GetSubArray_StartIndexNegative_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.GetSubArray(-1));
		}

		[Fact]
		public void GetSubArray_StartIndexEqualsArrayLength_GivesEmptyArray()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act
			var subArray = array.GetSubArray(array.Length);

			// Assert
			Assert.Empty(subArray);
		}

		[Fact]
		public void GetSubArray_ArrayIsNull_Throws()
		{
			// Arrange
			int[] array = null;

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => array.GetSubArray(2));
		}

		[Fact]
		public void GetSubArrayWithLength_ArrayIsNull_Throws()
		{
			// Arrange
			int[] array = null;

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => array.GetSubArray(2, 2));
		}

		[Fact]
		public void GetSubArrayWithLength_LengthIsNegative_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.GetSubArray(2, -1));
		}

		[Fact]
		public void GetSubArrayWithLength_StartIndexPlusLengthIsHigherThanArrayLength_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.GetSubArray(2, 5));
		}

		[Fact]
		public void GetSubArrayWithLength_StartIndexOutside_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.GetSubArray(array.Length + 1, 1));
		}

		[Fact]
		public void Insert_DestinationArrayIsNull_Throws()
		{
			// Arrange
			int[] array = null;
			var subArray = new[] { 6, 7 };

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => array.Insert(0, subArray));
		}

		[Fact]
		public void Insert_SubArrayIsNull_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };

			// Act && Assert
			Assert.Throws<ArgumentNullException>(() => array.Insert(0, null));
		}

		[Fact]
		public void Insert_SubArrayDoesntFit_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };
			var subArray = new[] { 6, 7 };

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.Insert(array.Length - 1, subArray));
		}

		[Fact]
		public void Insert_StartIndexOutside_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };
			var subArray = Array.Empty<int>();

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.Insert(array.Length + 1, subArray));
		}

		[Fact]
		public void Insert_StartIndexNegative_Throws()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };
			var subArray = Array.Empty<int>();

			// Act && Assert
			Assert.Throws<ArgumentOutOfRangeException>(() => array.Insert(-1, subArray));
		}

		[Fact]
		public void Insert_BothArraysAreValid_GivesProperArray()
		{
			// Arrange
			var array = new[] { 1, 2, 3, 4, 5 };
			var subArray = new[] { 6, 7 };

			// Act 
			array.Insert(2, subArray);

			// Assert
			Assert.Equal(1, array[0]);
			Assert.Equal(2, array[1]);
			Assert.Equal(6, array[2]);
			Assert.Equal(7, array[3]);
			Assert.Equal(5, array[4]);
		}

	}
}
