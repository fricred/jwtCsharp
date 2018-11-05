using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CesviAUTH.Models
{
    public class TokenRequest
    {
        public string token { get; set; }
        public string refreshToken { get; set; }
    }
}
