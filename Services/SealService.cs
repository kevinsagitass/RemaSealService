using Microsoft.Research.SEAL;
using Newtonsoft.Json;
using RemaSealService.Interfaces;
using RemaSealService.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace RemaSealService.Services
{
    public class SealService : ISealService
    {
        private MemoryStream parmsStream = new MemoryStream();
        private MemoryStream dataStream = new MemoryStream();
        private MemoryStream skStream = new MemoryStream();
        private MemoryStream buffer;

    public SealService()
        {
            ulong polyModulusDegree = 8192;
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[] { 50, 20, 50 });

            long size = parms.Save(parmsStream);

            parmsStream.Seek(0, SeekOrigin.Begin);

            buffer = new MemoryStream(new byte[parms.SaveSize()]);
            parms.Save(buffer);
        }

        public string EncrypTransactionAmount(Transaction transaction)
        {
            using EncryptionParameters parms = new EncryptionParameters();
            parms.Load(parmsStream);

            parmsStream.Seek(0, SeekOrigin.Begin);

            using SEALContext context = new SEALContext(parms);

            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey sk = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey pk);

            sk.Save(skStream);
            skStream.Seek(0, SeekOrigin.Begin);

            using Serializable<RelinKeys> rlk = keygen.CreateRelinKeys();

            keygen.CreateRelinKeys(out RelinKeys rlkBig);

            long sizeRlk = rlk.Save(dataStream);
            long sizeRlkBig = rlkBig.Save(dataStream);

            dataStream.Seek(-sizeRlkBig, SeekOrigin.Current);

            double scale = Math.Pow(2.0, 20);
            CKKSEncoder encoder = new CKKSEncoder(context);
            using Plaintext amountPlain = new Plaintext(), 
                feePlain = new Plaintext();
            encoder.Encode(transaction.amount, scale, amountPlain);
            encoder.Encode(Constant.Fee, scale, feePlain);

            using Encryptor encryptor = new Encryptor(context, pk);

            long sizeEncrypted1 = encryptor.Encrypt(amountPlain).Save(dataStream);
          
            encryptor.SetSecretKey(sk);
            long sizeSymEncrypted2 = encryptor.EncryptSymmetric(feePlain).Save(dataStream);

            dataStream.Seek(0, SeekOrigin.Begin);

            return Base64Encode(JsonConvert.SerializeObject(encryptor.EncryptSymmetric(amountPlain)));
        }

        public double DecryptTransactionAmount(string encryptedValue)
        {
            using EncryptionParameters parms = new EncryptionParameters();
            parms.Load(parmsStream);
            parmsStream.Seek(0, SeekOrigin.Begin);
            using SEALContext context = new SEALContext(parms);

            using Evaluator evaluator = new Evaluator(context);

            using RelinKeys rlk = new RelinKeys();
            using Ciphertext amountEncrypted = new Ciphertext(), feeEncrypted = new Ciphertext();

            rlk.Load(context, dataStream);
            amountEncrypted.Load(context, dataStream);
            feeEncrypted.Load(context, dataStream);

            using Ciphertext encryptedProd = new Ciphertext();

            evaluator.Multiply(amountEncrypted, feeEncrypted, encryptedProd);
            evaluator.RelinearizeInplace(encryptedProd, rlk);
            evaluator.RescaleToNextInplace(encryptedProd);

            dataStream.Seek(0, SeekOrigin.Begin);
            long sizeEncryptedProd = encryptedProd.Save(dataStream);
            dataStream.Seek(0, SeekOrigin.Begin);

            using SecretKey sk = new SecretKey();
            sk.Load(context, skStream);
            using Decryptor decryptor = new Decryptor(context, sk);
            using CKKSEncoder encoder = new CKKSEncoder(context);

            using Ciphertext encryptedResult = new Ciphertext();
            encryptedResult.Load(context, dataStream);

            using Plaintext plainResult = new Plaintext();
            decryptor.Decrypt(encryptedResult, plainResult);
            List<double> result = new List<double>();
            encoder.Decode(plainResult, result);

            return Math.Round(result[0] / 100);
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }
       
        public Fee CalculateFee(Transaction transaction)
        {
            //Setting Up Parameter
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 32768;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(1024);
            using SEALContext context = new SEALContext(parms);

            // Make Public and Secret Key (Public Key is for Encryption Secret Key is for Decryption)
            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            //// Encryptor Instance
            using Encryptor encryptor = new Encryptor(context, publicKey);

            //// Evaluator Instance
            using Evaluator evaluator = new Evaluator(context);

            //// Decryptor Instance
            using Decryptor decryptor = new Decryptor(context, secretKey);

            keygen.CreateRelinKeys(out RelinKeys relinKeys);

            ulong fee = Convert.ToUInt64(Constant.Fee);
            using Plaintext feePlain = new Plaintext(fee.ToString());

            using Plaintext amountPlain = new Plaintext(transaction.amount.ToString());

            // Encrypt Value
            using Ciphertext feeEncrypted = new Ciphertext();
            encryptor.Encrypt(feePlain, feeEncrypted);

            using Ciphertext amountEncrypted = new Ciphertext();
            encryptor.Encrypt(amountPlain, amountEncrypted);

            evaluator.MultiplyPlainInplace(amountEncrypted, feePlain);
            evaluator.RelinearizeInplace(amountEncrypted, relinKeys);

            using Plaintext totalFee = new Plaintext();
            decryptor.Decrypt(amountEncrypted, totalFee);
            transaction.fee = Double.Parse(totalFee.ToString());

            var total = JsonConvert.SerializeObject(amountEncrypted);

            return new Fee
            {
                amount = transaction.encryptedAmount,
                fee = Base64Encode(transaction.fee.ToString()),
                total = Base64Encode(total)
            };
        }
    }
}
