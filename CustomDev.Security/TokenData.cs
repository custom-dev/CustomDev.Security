using System;
using System.Collections.Generic;
using System.Text;

namespace CustomDev.Security
{
    [Serializable]
    internal class TokenData<T>
    {
        public DateTime? ExpirationDate { get; set; }
        public T Data { get; set; }
    }
}
