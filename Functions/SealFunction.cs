using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using RemaSealService.Models;
using RemaSealService.Interfaces;
using Microsoft.Azure.WebJobs.Hosting;
using RemaSealService;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using Nancy.Json;

[assembly: WebJobsStartup(typeof(Startup))]
namespace RemaSealService
{
    public class SealFunction
    {
        private readonly ISealService sealService;
        public SealFunction(ISealService sealService)
        {
            this.sealService = sealService;
        }

        [FunctionName("Encrypt")]
        public async Task<IActionResult> RunEncrypt(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = "Encrypt")] HttpRequest req,
            ILogger log)
        {
            if (req.Method == HttpMethod.Post.Method)
                {
                var request = await req.ReadAsStringAsync();
                var transaction = JsonConvert.DeserializeObject<Transaction>(request);

                var result = sealService.EncrypTransactionAmount(transaction);

                return new OkObjectResult(result);
            }
            else
            {
                return new NotFoundResult();
            }
        }

        [FunctionName("Decrypt")]
        public async Task<IActionResult> RunDecrypt(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "CalculateFee")] HttpRequest req,
            ILogger log)
        {
            if (req.Method == HttpMethod.Get.Method)
            {
                var request = await req.ReadAsStringAsync();
                var encryptedValue = Base64Decode(req.Query["value"]);

                var result = sealService.DecryptTransactionAmount(encryptedValue);

                return new OkObjectResult(result);
            }
            else
            {
                return new NotFoundResult();
            }
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }


        [FunctionName("CalculateFee")]
        public async Task<IActionResult> RunFeeCalculation(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "Calculate/Fee")] HttpRequest req,
            ILogger log)
        {
            if (req.Method == HttpMethod.Get.Method)
            {
                var request = await req.ReadAsStringAsync();
                var transaction = new Transaction();

                string password = "3sc3RLrpd17";

                SHA256 mySHA256 = SHA256Managed.Create();
                byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));

                byte[] iv = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

                transaction.amount = long.Parse(DecryptString(Base64Decode(req.Query["amount"]), key, iv));
                transaction.encryptedAmount = req.Query["amount"];

                var result = sealService.CalculateFee(transaction);

                return new OkObjectResult(result);
            }
            else
            {
                return new NotFoundResult();
            }
        }

        public string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            // Instantiate a new Aes object to perform string symmetric encryption
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(key, 0, aesKey, 0, 32);
            encryptor.Key = aesKey;
            encryptor.IV = iv;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Will contain decrypted plaintext
            string plainText = String.Empty;

            try
            {
                // Convert the ciphertext string into a byte array
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                // Decrypt the input ciphertext string
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

                // Complete the decryption process
                cryptoStream.FlushFinalBlock();

                // Convert the decrypted data from a MemoryStream to a byte array
                byte[] plainBytes = memoryStream.ToArray();

                // Convert the decrypted byte array to string
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();
            }

            // Return the decrypted data as a string
            return plainText;
        }
    }

        /**
         * A class to encrypt and decrypt strings using the cipher AES-256-CBC used in Laravel.
         */
        class Aes256CbcEncrypter
        {
            private static readonly Encoding encoding = Encoding.UTF8;

            public static string Encrypt(string plainText, string key)
            {
                try
                {
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;

                    aes.Key = encoding.GetBytes(key);
                    aes.GenerateIV();

                    ICryptoTransform AESEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
                    byte[] buffer = encoding.GetBytes(plainText);

                    string encryptedText = Convert.ToBase64String(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

                    String mac = "";

                    mac = BitConverter.ToString(HmacSHA256(Convert.ToBase64String(aes.IV) + encryptedText, key)).Replace("-", "").ToLower();

                    var keyValues = new Dictionary<string, object>
                {
                    { "iv", Convert.ToBase64String(aes.IV) },
                    { "value", encryptedText },
                    { "mac", mac },
                };

                    JavaScriptSerializer serializer = new JavaScriptSerializer();

                    return Convert.ToBase64String(encoding.GetBytes(serializer.Serialize(keyValues)));
                }
                catch (Exception e)
                {
                    throw new Exception("Error encrypting: " + e.Message);
                }
            }

            public static string Decrypt(string plainText, string key)
            {
                try
                {
                    RijndaelManaged aes = new RijndaelManaged();
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;
                    aes.Key = encoding.GetBytes(key);

                    // Base 64 decode
                    byte[] base64Decoded = Convert.FromBase64String(plainText);
                    string base64DecodedStr = encoding.GetString(base64Decoded);

                    // JSON Decode base64Str
                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    var payload = serializer.Deserialize<Dictionary<string, string>>(base64DecodedStr);

                    aes.IV = Convert.FromBase64String(payload["iv"]);

                    ICryptoTransform AESDecrypt = aes.CreateDecryptor(aes.Key, aes.IV);
                    byte[] buffer = Convert.FromBase64String(payload["value"]);

                    return encoding.GetString(AESDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
                }
                catch (Exception e)
                {
                    throw new Exception("Error decrypting: " + e.Message);
                }
            }

            static byte[] HmacSHA256(String data, String key)
            {
                using (HMACSHA256 hmac = new HMACSHA256(encoding.GetBytes(key)))
                {
                    return hmac.ComputeHash(encoding.GetBytes(data));
                }
            }
        }
}
