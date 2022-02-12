using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;


/* Reference for AES Decryption and Encryption
 * Convert key to base64 and store in appsettings.json
 * Convert IV to base64 and prepend it to ciphertext, IV length is 24 characters
 * https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged?redirectedfrom=MSDN&view=net-6.0#code-try-3
 */

namespace SITConnect200600M.Areas.Identity.Data
{
    public class CreditCardCryptography
    {
        public static string EncryptStringAes(string plainText, string key)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");

            byte[] encrypted;
            byte[] IV;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                // Don't need to define IV because it'll be auto generated
                IV = aesAlg.IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return $"{Convert.ToBase64String(IV)}{Convert.ToBase64String(encrypted)}";
        }
        
        public static string DecryptStringAes(string cipherText, string key)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));

            // First 24 characters is the IV
            byte[] IV = Convert.FromBase64String(cipherText[..24]);
            byte[] byteCipherText = Convert.FromBase64String(cipherText[24..]);
            
            // Declare the string used to hold
            // the decrypted text.
            string plaintext; 

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key.ToString());
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(byteCipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
        
    }
}