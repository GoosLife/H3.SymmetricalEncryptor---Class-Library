namespace SymmetricalEncryption
{
	public interface ISymmetricalEncryptor
	{
		public void GenerateKey();
		public void GenerateIV();
		public byte[] Encrypt(string data);
		public byte[] Decrypt(byte[] cipher);
	}
}
