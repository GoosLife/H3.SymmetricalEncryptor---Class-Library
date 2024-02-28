using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SymmetricalEncryption
{
	public class SymmetricalEncryptor : ISymmetricalEncryptor
	{
		private SymmetricAlgorithm _algorithm;
		private byte[] _key;
		private byte[] _iv;

		public SymmetricalEncryptor(SymmetricAlgorithm algorithm)
		{
			// Create a new instance of the algorithm
			_algorithm = algorithm;

			// We use Microsofts default algorithms to generate key and IV
			_key = _algorithm.Key;
            _iv = _algorithm.IV;
		}

		public byte[] Decrypt(byte[] cipher)
		{
			ICryptoTransform cryptoTransform = _algorithm.CreateDecryptor(_key, _iv);
			return cryptoTransform.TransformFinalBlock(cipher, 0, cipher.Length);
		}

		public byte[] Encrypt(string data)
		{
			ICryptoTransform cryptoTransform = _algorithm.CreateEncryptor(_key, _iv);

			using (MemoryStream ms = new MemoryStream())
			{
				using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
				{
					byte[] dataBytes = Encoding.UTF8.GetBytes(data);
					cs.Write(dataBytes, 0, dataBytes.Length);
				}
				return ms.ToArray();
			}

			throw new Exception("Encryption failed");
		}

		public void GenerateKeyAndIv()
		{
			GenerateKey();
			GenerateIV();
		}

		public void GenerateIV()
		{
			int ivSize = _algorithm.LegalBlockSizes[0].MaxSize;
			_algorithm.BlockSize = ivSize / 8;
			byte[] iv = new byte[_algorithm.BlockSize];

			RandomNumberGenerator.Fill(iv);

			_iv = iv;
			_algorithm.IV = _iv;
		}

		public void GenerateKey()
		{
			int keySize = _algorithm.LegalKeySizes[0].MaxSize;
			_algorithm.KeySize = keySize / 8;
			byte[] key = new byte[_algorithm.KeySize];

			RandomNumberGenerator.Fill(key);
			
			_algorithm.Key = key;
			_key = _algorithm.Key;
		}

		public byte[] GetKey()
		{
			return _key;
		}

		public byte[] GetIV()
		{
			return _iv;
		}
	}
}
