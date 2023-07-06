using System;
using System.Security.Cryptography;

namespace BackendAuthDemo.Helpers
{
    public class EncryptPassword
    {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        public static readonly int SaltSize = 16;
        public static readonly int HashSize = 20;
        public static readonly int Iterations = 1000;

        public static string HashPassword(string password)
        {
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            var key = new Rfc2898DeriveBytes(password, salt);
            var hash = key.GetBytes(HashSize);

            var hashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

            var base64Hash = Convert.ToBase64String(hashBytes);

            return base64Hash;
        }

        public static bool VerifyPassword(string password,string base64Hash)
        {
            var hashBytes = Convert.FromBase64String(base64Hash);
            var salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            var key = new Rfc2898DeriveBytes(password, salt,Iterations);
            byte[] hash = key.GetBytes(HashSize);

            for(int i=0;i< HashSize;i++)
            {
                if (hashBytes[i + SaltSize] != hash[i])
                    return false;
            }
            return true;
        }
    }
}
