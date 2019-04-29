using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CustomDev.Security.Cryptography
{
    /// <summary>
    /// Implement the encryption/decryption of data using AES algorithm.
    /// 
    /// This class hides the complex configuration to correclty secure data:
    /// <list type="bullet">
    /// <item><description>it handles the initialization vector generation using a cryptographic random generator;</description></item>
    /// <item><description>it uses a secure mode for AES algorithm (CBC or Cipher Block Chaining); </description></item>
    /// <item><description>it adds a signature to the encrypted data to ensure the data integrity; </description></item>
    /// <item><description>it allows to derivate a key from a password and a salt using standard algorithm (PKPB2) with a proper configuration.</description></item>
    /// </list>
    /// 
    /// <example>
    /// Usage: 
    /// <code>
    /// class ExampleClass
    /// {
    ///     static int Main()
    ///     {
    ///         // Password must never be hardcoded. It just an example !!!
    ///         string password = "123456"; 
    ///         
    ///         // the salt can be hardocded. It does not have to be keep secret (but it is better if it is)
    ///         byte[] salt = {0x00, 0x57, 0x97, 0xab, 0x9b, 0xcc, 0x31, 0x00}; 
    ///         string plainData = "This string will be encrypted"; 
    ///         byte[] key = AesCryptography.GetKeyFromPassword(passord, salt);
    ///         byte[] encryptedData = AesCryptography.EncryptWithAes(plainData, key);
    ///         string decryptedData = AesCryptography.DecryptWithAes(encryptedData, key);
    ///         
    ///         if (plainData == decryptedData)
    ///         {
    ///             Console.Write("Encryption / decryption are ok: ");
    ///             Console.WriteLine(decryptedData);
    ///         }
    ///         else
    ///         {
    ///             Console.WriteLine("An error occured during the encryption/decryption process");
    ///         }
    ///     }
    /// }
    /// </code>
    /// </example>
    /// </summary>
    public static class AesCryptography
    {
        private const int ITERATION_COUNT = 10000;

        /// <summary>
        /// Derives a key from a password and a salt.
        /// </summary>
        /// <param name="password">password</param>
        /// <param name="salt">salt</param>
        /// <returns>The derivated key as a 32-bytes array</returns>
        public static byte[] GetKeyFromPassword(string password, byte[] salt)
        {
            Rfc2898DeriveBytes derivator = new Rfc2898DeriveBytes(password, salt, ITERATION_COUNT);
            return derivator.GetBytes(32);
        }
        
        /// <summary>
        /// Helper function to encrypt data and getting a base64 output.
        /// </summary>
        /// <param name="plainContent">data to encrypt</param>
        /// <param name="key">key used for the encryption</param>
        /// <returns>encrypted data in a base64 encoded string</returns>
        public static string EncryptBase64(byte[] plainContent, byte[] key)
        {
            byte[] encodedContent = Encrypt(plainContent, key);
            string base64 = Convert.ToBase64String(encodedContent);
            return base64;
        }

        /// <summary>
        /// Herlper function to decrypt data from base64 data
        /// </summary>
        /// <param name="encodedBase64Content">data to decrypt, in base64</param>
        /// <param name="key">key used for the decryption</param>
        /// <returns>decrypted data</returns>
        public static byte[] DecryptBase64(string encodedBase64Content, byte[] key)
        {
            byte[] encodedContent = Convert.FromBase64String(encodedBase64Content);
            byte[] content = Decrypt(encodedContent, key);
            return content;
        }

        /// <summary>
        /// Helper function to encrypt text to a base64 string
        /// </summary>
        /// <param name="plainText">text to crypt</param>
        /// <param name="key">key used for the encryption</param>
        /// <returns>encrypted data in a base64 encoded string</returns>
        public static string EncryptTextBase64(string plainText, byte[] key)
        {
            byte[] content = Encoding.UTF8.GetBytes(plainText);
            string base64 = EncryptBase64(content, key);
            return base64;
        }

        /// <summary>
        /// Helper function to decrypt a string previously encoded by <see cref="EncryptTextBase64(string, byte[])"/>
        /// </summary>
        /// <param name="encodedBase64Content">encrypted data</param>
        /// <param name="key">key used for the decryption</param>
        /// <returns>decrypted string</returns>
        public static string DecryptTextBase64(string encodedBase64Content, byte[] key)
        {
            byte[] content = DecryptBase64(encodedBase64Content, key);
            string plainText = Encoding.UTF8.GetString(content);
            return plainText;
        }

        /// <summary>
        /// Encrypts data in <paramref name="plainContent"/> using the specified <paramref name="key" />.
        /// </summary>
        /// <remarks>
        /// The key must be 32bits long.
        /// 
        /// The method <seealso cref="GetKeyFromPassword"/> can be used to derive a key from a password and a salt.
        /// 
        /// The output if computed as follow :
        /// <list type="table">
        /// <listheader>
        /// <term>bytes</term>
        /// <description>description</description>
        /// </listheader>
        /// <item>
        /// <term>bytes 0 - 15</term>
        /// <description>initialisation vector</description>
        /// </item>
        /// <item>
        /// <term>bytes 16 - n</term>
        /// <description>encrypted data</description>
        /// </item>
        /// </list>
        /// 
        /// The unciphered data corresponding to the encryption data are :
        /// <list type="table">
        /// <item>
        /// <term>byte 0</term> 
        /// <description>signature version. Must be 1 for SHA256</description>
        /// </item>
        /// <item>
        /// <term>bytes 1 - 16</term>
        /// <description>signature (SHA256 of data)</description>
        /// </item>
        /// <item>
        /// <term>bytes 16 - n</term>
        /// <description>data</description>
        /// </item>
        /// </list>
        /// 
        /// </remarks>
        /// <param name="plainContent">data to cipher</param>
        /// <param name="key">cipher key</param>
        /// <returns>Encrypted data</returns>
        public static byte[] Encrypt(byte[] plainContent, byte[] key)
        {
            if (plainContent == null || plainContent.Length == 0) { throw new ArgumentNullException("plainText"); }
            if (key == null || key.Length == 0) { throw new ArgumentNullException("key"); }

            byte[] encrypted;
            using (Aes aes = Aes.Create())
            using (SHA256 sha256 = SHA256.Create())
            {
                ICryptoTransform encryptor;
                byte[] signature = sha256.ComputeHash(plainContent);

                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                if (aes.IV == null || aes.IV.Length != 16)
                {
                    throw new Exception("Invalid initialization vector");
                }

                encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(aes.IV, 0, aes.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.WriteByte(1);
                        cryptoStream.Write(signature, 0, signature.Length);
                        cryptoStream.Write(plainContent, 0, plainContent.Length);
                    }

                    encrypted = memoryStream.ToArray();
                }
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypt data previously ciphered by <see cref="Encrypt"/>.
        /// </summary>
        /// <remarks>
        /// For a description of the format of the <paramref name="cipherData"/>, please see <see cref="Encrypt"/> method.
        /// </remarks>
        /// <param name="cipherData">data to decipher</param>
        /// <param name="key">key to use to decipher</param>
        /// <returns>deciphered data</returns>
        /// <exception cref="Exception">Corrupted data</exception>
        public static byte[] Decrypt(byte[] cipherData, byte[] key)
        {
            if (cipherData == null || cipherData.Length == 0) { throw new ArgumentNullException("cipherText"); }
            if (key == null || key.Length == 0) { throw new ArgumentNullException("Key"); }

            byte[] plainContent = null;

            using (SHA256 sha256 = SHA256.Create())
            using (Aes aes = Aes.Create())
            using (MemoryStream msDecrypt = new MemoryStream(cipherData))
            {
                byte[] initializationVector = new byte[16];
                ICryptoTransform decryptor;

                msDecrypt.Read(initializationVector, 0, initializationVector.Length);
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = initializationVector;

                decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream outputDecrypt = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        int hashAlgorithm = cryptoStream.ReadByte();

                        if (hashAlgorithm == 1)
                        {
                            byte[] signature = new byte[32];
                            byte[] computedSignature;

                            cryptoStream.Read(signature, 0, 32);
                            cryptoStream.CopyTo(outputDecrypt);
                            plainContent = outputDecrypt.ToArray();
                            computedSignature = sha256.ComputeHash(plainContent);

                            if (!CompareByteArray(computedSignature, signature))
                            {
                                throw new Exception("Corrupted data");
                            }
                        }
                    }
                }

            }

            return plainContent;
        }

        private static bool CompareByteArray(byte[] array1, byte[] array2)
        {
            if (array1 == array2) { return true; }
            if (array1 == null && array2 != null) { return false; }
            if (array1 != null && array2 == null) { return false; }
            if (array1.Length != array2.Length) { return false; }

            for (int i = 0; i < array1.Length; ++i)
            {
                if (array1[i] != array2[i]) { return false; }
            }

            return true;
        }
    }
}
