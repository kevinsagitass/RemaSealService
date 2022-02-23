using Microsoft.Research.SEAL;
using RemaSealService.Models;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace RemaSealService.Interfaces
{
    public interface ISealService
    {
        public string EncrypTransactionAmount(Transaction transaction);
        public double DecryptTransactionAmount(string value);
        public Fee CalculateFee(Transaction transaction);
    }
}
