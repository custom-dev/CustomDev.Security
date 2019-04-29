using CustomDev.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security;
using System.Threading;

namespace Test.Security
{
    [TestClass]
    public class TokenManagerTest
    {
        [TestMethod]
        public void TestToken()
        {
            string data = "This is a data to encrypt";

            string token = TokenManager.Encrypt(data);

            Assert.IsFalse(String.IsNullOrEmpty(token));
            Assert.AreEqual(data, TokenManager.Decrypt<string>(token));
        }

        [TestMethod]
        public void TestTokenWithValidExpirationDate()
        {
            string data = "This is a data to encrypt";
            DateTime expirationDate = DateTime.UtcNow.AddMilliseconds(50);
            string token = TokenManager.Encrypt(data, expirationDate);

            Assert.AreEqual(data, TokenManager.Decrypt<string>(token));
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void TestTokenWithInvalidExpirationDate()
        {
            string data = "This is a data to encrypt";
            DateTime expirationDate = DateTime.UtcNow.AddMilliseconds(50);
            string token = TokenManager.Encrypt(data, expirationDate);

            Thread.Sleep(50);
            Assert.AreEqual(data, TokenManager.Decrypt<string>(token));
        }
    }
}
