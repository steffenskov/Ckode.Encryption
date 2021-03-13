# Ckode.Encryption
Ckode.Encryption is a small collection of simplified wrappers for common encryption algorithms.

Currently supports the following algorithms:
- AES
- AES with a string password used as encryption key
- RSA

All algorithms are from the .NET framework.

The AES and RSA classes both offer a GenerateKey or GenerateKeyPair method which should be used to generate new keys (do not roll your own key generator, it'll probably have insecurities)

## Installation:

I recommend using the NuGet package: https://www.nuget.org/packages/Ckode.Encryption/ however you can also simply clone the repository and use the pre-compiled binaries or compile the project yourself.
As the project is licensed under MIT you're free to use it for pretty much anything you want.

## Examples:

*Encrypt a file with AES:*

    var aes = new Ckode.Encryption.AES();
    var key = aes.GenerateKey(); // Make sure to store the key somewhere for decryption later on
    
    var rawBytes = File.ReadAllBytes(filePath);
    var encrypted = aes.Encrypt(rawBytes, key);
    File.WriteAllBytes(encryptedFilePath, encrypted);
    
*Encrypt a string with AES, using a password as key:*

    var aes = new Ckode.Encryption.AESWithPassword();
    var key = "My secret";
    
    var rawString = "Something nobody but me should read";
    var encryptedString = aes.Encrypt(rawString, Encoding.UTF8, key);
    
    // To decrypt:
    var decryptedString = aes.Decrypt(encryptedString, Encoding.UTF8, key);
    
*Encrypt a file with RSA:*

    var rsa = new Ckode.Encryption.RSA();
    var keyPair = rsa.GenerateKeyPair(); // Make sure to store the key pair, and keep the private key private.
    
    var rawBytes = File.ReadAllBytes(filePath);
    var encrypted = rsa.Encrypt(rawBytes, keyPair);
    File.WriteAllBytes(encryptedFilePath, encrypted);
    
    // To decrypt
    rsa.Decrypt(encrypted, keyPair);
    // or
    rsa.Decrypt(encrypted, keyPair.PrivateKey);
