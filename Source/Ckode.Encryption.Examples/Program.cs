using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ckode.Encryption.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            AesString();
            AesBytes();
            AesStream();

            AesStringWithPassword();
            AesBytesWithPassword();

            RsaString();
            RsaBytes();
        }

        private static void AesString()
        {
            var aes = new AES();
            var key = aes.GenerateKey(); // Use this method to generate a random key in a secure way. Do not roll your own randomizer.
            var messageToEncrypt = "Hello world, this is AES encrypted";
            var encryptedBytes = aes.Encrypt(messageToEncrypt, Encoding.UTF8, key);

            var decryptedMessage = aes.Decrypt(encryptedBytes, Encoding.UTF8, key);

            Console.WriteLine($@"AesString: Encrypted ""{messageToEncrypt}"" into {encryptedBytes.Length} bytes. Then decrypted back into ""{decryptedMessage}""");
            Console.WriteLine();
        }

        private static void AesBytes()
        {
            var aes = new AES();
            var key = aes.GenerateKey(); // Use this method to generate a random key in a secure way. Do not roll your own randomizer.
            var bytesToEncrypt = new byte[] { 1, 2, 3, 4, 5 };
            var encryptedBytes = aes.Encrypt(bytesToEncrypt, key);

            var decryptedBytes = aes.Decrypt(encryptedBytes, key);

            Console.WriteLine($"AesBytes: Encrypted bytes {{ {String.Join(", ", bytesToEncrypt)} }} into {encryptedBytes.Length} bytes. Then decrypted back into {{ {String.Join(", ", decryptedBytes)} }}");
            Console.WriteLine();
        }

        private static void AesStream()
        {
            var aes = new AES();
            var key = aes.GenerateKey(); // Use this method to generate a random key in a secure way. Do not roll your own randomizer.

            var bytesToEncrypt = new byte[] { 1, 2, 3, 4, 5 };

            byte[] encryptedBytes, decryptedBytes;

            using (var inputStream = new MemoryStream(bytesToEncrypt))
            using (var resultStream = new MemoryStream())
            using (var cryptoStream = aes.Encrypt(resultStream, key))
            {
                inputStream.CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();
                resultStream.Seek(0, SeekOrigin.Begin);
                encryptedBytes = resultStream.ToArray();
            }

            using (var inputStream = new MemoryStream(encryptedBytes))
            using (var resultStream = new MemoryStream())
            using (var cryptoStream = aes.Decrypt(inputStream, key))
            {
                cryptoStream.CopyTo(resultStream);
                resultStream.Seek(0, SeekOrigin.Begin);
                decryptedBytes = resultStream.ToArray();
            }

            Console.WriteLine($"AesStream: Encrypted bytes {{ {String.Join(", ", bytesToEncrypt)} }} into {encryptedBytes.Length} bytes. Then decrypted back into {{ {String.Join(", ", decryptedBytes)} }}");
            Console.WriteLine();
        }

        private static void AesStringWithPassword()
        {
            var aes = new AESWithPassword();
            var password = "my super secret password";

            var messageToEncrypt = "Hello world, this is AES encrypted";
            var encryptedBytes = aes.Encrypt(messageToEncrypt, Encoding.UTF8, password);

            var decryptedMessage = aes.Decrypt(encryptedBytes, Encoding.UTF8, password);

            Console.WriteLine($@"AesStringWithPassword: Encrypted ""{messageToEncrypt}"" into {encryptedBytes.Length} bytes. Then decrypted back into ""{decryptedMessage}""");
            Console.WriteLine();
        }

        private static void AesBytesWithPassword()
        {
            var aes = new AESWithPassword();
            var password = "my super secret password";
            var bytesToEncrypt = new byte[] { 1, 2, 3, 4, 5 };
            var encryptedBytes = aes.Encrypt(bytesToEncrypt, password);

            var decryptedBytes = aes.Decrypt(encryptedBytes, password);

            Console.WriteLine($"AesBytesWithPassword: Encrypted bytes {{ {String.Join(", ", bytesToEncrypt)} }} into {encryptedBytes.Length} bytes. Then decrypted back into {{ {String.Join(", ", decryptedBytes)} }}");
            Console.WriteLine();
        }

        private static void RsaString()
        {
            var rsa = new RSA();
            var keyPair = rsa.GenerateKeyPair(); // Use this method to generate a random key pair in a secure way. Do not roll your own randomizer.

            var messageToEncrypt = "Hello world, this is AES encrypted";
            var encryptedBytes = rsa.Encrypt(messageToEncrypt, Encoding.UTF8, keyPair.PublicKey); // Encrypt with the public key

            var decryptedMessage = rsa.Decrypt(encryptedBytes, Encoding.UTF8, keyPair.PrivateKey); // And decrypt with the private key

            Console.WriteLine($@"RsaString: Encrypted ""{messageToEncrypt}"" into {encryptedBytes.Length} bytes. Then decrypted back into ""{decryptedMessage}""");
            Console.WriteLine();
        }

        private static void RsaBytes()
        {
            var rsa = new RSA();
            var keyPair = rsa.GenerateKeyPair(); // Use this method to generate a random key pair in a secure way. Do not roll your own randomizer.

            var bytesToEncrypt = new byte[] { 1, 2, 3, 4, 5 };
            var encryptedBytes = rsa.Encrypt(bytesToEncrypt, keyPair.PublicKey); // Encrypt with the public key

            var decryptedBytes = rsa.Decrypt(encryptedBytes, keyPair.PrivateKey); // And decrypt with the private key

            Console.WriteLine($"RsaBytes: Encrypted bytes {{ {String.Join(", ", bytesToEncrypt)} }} into {encryptedBytes.Length} bytes. Then decrypted back into {{ {String.Join(", ", decryptedBytes)} }}");
            Console.WriteLine();
        }
    }
}
