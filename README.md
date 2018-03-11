# Ckode.Encryption
Ckode.Encryption is a small collection of simplified wrappers for common encryption algorithms.

Currently supports the following algorithms:
- AES
- AES with a string password used as encryption key
- RSA

All algorithms are from the .NET framework.

The AES and RSA classes both offer a GenerateKey or GenerateKeyPair method which should be used to generate new keys (do not roll your own key generator, it'll probably have insecurities)

Be sure to look at the Ckode.Encryption.Examples project to see how the different algorithms work.
