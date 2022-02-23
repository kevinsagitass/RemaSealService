using System;
using System.Collections.Generic;
using System.Text;

namespace RemaSealService.Models
{
    public class Transaction
    {
        public string _token { get; set; }
        public string id { get; set; }
        public long amount { get; set; }
        public long multiplier { get; set; }
        public string encryptedAmount { get; set; }
        public string encryptedMultiplier { get; set; }
        public double fee { get; set; }
    }
}
