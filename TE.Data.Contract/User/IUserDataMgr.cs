using System;
using System.Collections.Generic;
using System.Text;
using TE.Entities;

namespace TE.Data.Contract
{
    public interface IUserDataMgr
    {
        Account GetUser(string emailId);
        void UpdateUser(Account account);
        void DeleteUser(Account account);
        Account GetUserByRefreshToken(string refreshToken);
        Account GetUserByVerificationToken(string token);
        Account GetUserByResetToken(string token);
        Account GetUserById(int id);
        bool CheckUserEmail(string emailId);
        int GetUsersCount();
        IEnumerable<Account> GetAllUsers();
    }
}
