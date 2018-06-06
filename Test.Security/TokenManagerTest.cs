using CustomDev.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

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
            Assert.AreEqual(data, TokenManager.Decrypt(token));
        }
    }
}
