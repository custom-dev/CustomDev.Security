using CustomDev.Runtime.Serialization;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CustomDev.Security
{
    /// <summary>
    /// This class manage token generation.
    /// 
    /// Generated token are information encrypted and encoded in a base64 variant compatible
    /// with URL :
    /// <list type="bullet">
    /// <item><description>'+' sign is replaced by '-'</description></item>
    /// <item><description>'/' sign is replaced by '_'</description></item>
    /// </list>
    /// </summary>
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

        /// <summary>
        /// Encodes an object into a token.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="expirationDate"></param>
        /// <returns></returns>
        public static string Encrypt<T>(T data, DateTime? expirationDate = null)
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
                        byte[] tokenArray = data.SerializeToBinary();
                        long nbTicks = expirationDate?.ToBinary() ?? 0;
                        byte[] nbTicksArray = BitConverter.GetBytes(nbTicks);
                        cryptoStream.Write(nbTicksArray, 0, nbTicksArray.Length);
                        cryptoStream.Write(tokenArray, 0, tokenArray.Length);
                    }
                    encryptedBytes = memoryStream.ToArray();

                }


                return EncodePlusSlash(Convert.ToBase64String(encryptedBytes));
            }
        }
        
        /// <summary>
        /// Decodes a token into an object
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="encryptedData">token</param>
        /// <returns></returns>
        public static T Decrypt<T>(string encryptedData)
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
                        byte[] nbTicksArray = new byte[sizeof(long)];
                        long nbTicks;
                        DateTime? expirationDate = null;
                        T data;
                        cryptoStream.Read(nbTicksArray, 0, nbTicksArray.Length);
                        nbTicks = BitConverter.ToInt64(nbTicksArray, 0);
                        expirationDate = nbTicks != 0 ? DateTime.FromBinary(nbTicks) : (DateTime?)null;

                        data = BinarySerializer.Deserialize<T>(cryptoStream);

                        if (expirationDate.HasValue && expirationDate.Value < DateTime.UtcNow)
                        {
                            throw new SecurityException("Expired token");
                        }

                        return data;
                    }
                }
            }
        }

        private static string EncodePlusSlash(string str)
        {
            return str.Replace('/', '_').Replace('+', '-');
        }

        private static string DecodePlusSlash(string str)
        {
            return str.Replace('_', '/').Replace('-', '+');
        }
    }
}
