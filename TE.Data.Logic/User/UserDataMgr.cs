using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TE.Data.Contract;
using TE.Entities;
using TE.Helpers;

namespace TE.Data.Logic
{
    public class UserDataMgr: IUserDataMgr
    {
        private readonly DataContext _context;

        public UserDataMgr(
            DataContext context
            )
        {
            _context = context;
        }

        public void DeleteUser(Account account) 
        {
            _context.Accounts.Remove(account);
            _context.SaveChanges();
        }

        public Account GetUserById(int id)
        {
            var account = _context.Accounts.Find(id);
            if (account == null) throw new KeyNotFoundException("Account not found");
            return account;
        }

        public IEnumerable<Account> GetAllUsers()
        {
            return _context.Accounts;
        }

        public Account GetUserByResetToken(string token)
        { 
            return _context.Accounts.SingleOrDefault(x =>
                x.ResetToken == token &&
                x.ResetTokenExpires > DateTime.UtcNow);
        }

        public Account GetUserByVerificationToken(string token)
        {
            return _context.Accounts.SingleOrDefault(x => x.VerificationToken == token);
        }

        public int GetUsersCount()
        {
            return _context.Accounts.Count();
        }

        public bool CheckUserEmail(string emailId) 
        {
            return _context.Accounts.Any(x => x.Email == emailId);
        }

        public Account GetUser(string emailId)
        { 
            return _context.Accounts.SingleOrDefault(x => x.Email == emailId);
        }

        public Account GetUserByRefreshToken(string refreshToken) 
        {
            return _context.Accounts.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == refreshToken));
        }

        public void UpdateUser(Account account)
        {
            _context.Update(account);
            _context.SaveChanges();
        }
    }
}
