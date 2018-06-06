using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomDev.Security
{    
    public static class TokenManager
    {
        private static readonly byte[] _key;

        static TokenManager()
        {             
            try
            {
                string base64Key = Configuration.ConfigurationManager.GetString("CustomDev.Security.TokenManager.Key");

                if (String.IsNullOrEmpty(base64Key))
                {
                    throw new ArgumentException("Key not found");
                }

                _key = Convert.FromBase64String(base64Key);

                if (_key.Length != 32)
                {
                    throw new ArgumentException("Key size must be 32 bytes");
                }
            }
            catch(Exception ex)
            {
                throw new InvalidDataException("Invalid key", ex);
            }
        }

        public static string Encrypt(string data)
        {
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(_key, aes.IV);
                byte[] encryptedBytes;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    memoryStream.Write(BitConverter.GetBytes(aes.IV.Length), 0, sizeof(int));
                    memoryStream.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(data);
                        }
                        encryptedBytes = memoryStream.ToArray();
                    }
                }

                return EncodePlusSlash(Convert.ToBase64String(encryptedBytes));
            }
        }

        public static string Decrypt(string encryptedData)
        {
            using (Aes aes = Aes.Create())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(_key, aes.IV);

                byte[] encryptedBytes = Convert.FromBase64String(DecodePlusSlash(encryptedData));

                using (MemoryStream memoryStream = new MemoryStream(encryptedBytes))
                {
                    byte[] bIVsize = new byte[sizeof(int)];
                    byte[] IV;
                    int IVsize;
                    ICryptoTransform decryptor;

                    memoryStream.Read(bIVsize, 0, sizeof(int));
                    IVsize = BitConverter.ToInt32(bIVsize, 0);
                    IV = new byte[IVsize];
                    memoryStream.Read(IV, 0, IVsize);
                    decryptor = aes.CreateDecryptor(_key, IV);

                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static string EncodePlusSlash(string str)
        {
            return str.Replace('/', '_').Replace('+', '-');
        }

        public static string DecodePlusSlash(string str)
        {
            return str.Replace('_', '/').Replace('-', '+');
        }
    }
}
