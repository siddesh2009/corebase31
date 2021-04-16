using System;
using System.Collections.Generic;
using System.Text;
using TE.ViewModel;

namespace TE.Business.Contract
{
    public interface IUserBusinessMgr
    {
        AuthenticateResponseViewModel Authenticate(AuthenticateRequestViewModel model, string ipAddress);
        AuthenticateResponseViewModel RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);
        void Register(RegisterRequestViewModel model, string origin);
        void VerifyEmail(string token);
        void ForgotPassword(ForgotPasswordRequestViewModel model, string origin);
        void ValidateResetToken(ValidateResetTokenRequestViewModel model);
        void ResetPassword(ResetPasswordRequestViewModel model);
        IEnumerable<AccountResponseViewModel> GetAllUsers();
        AccountResponseViewModel GetUserById(int id);
        AccountResponseViewModel CreateUser(CreateRequestViewModel model);
        AccountResponseViewModel UpdateUser(int id, UpdateRequestViewModel model);
        void DeleteUser(int id);
    }
}
