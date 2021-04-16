using System;
using BC = BCrypt.Net.BCrypt;
using System.Collections.Generic;
using System.Text;
using TE.Business.Contract;
using TE.Data.Contract;
using TE.ViewModel;
using TE.Helpers;
using TE.Entities;
using System.IdentityModel.Tokens.Jwt;
using AutoMapper;
using Microsoft.Extensions.Options;
using NETCore.MailKit.Core;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Linq;

namespace TE.Business.Logic
{
    public class UserBusinessMgr: IUserBusinessMgr
    {
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        //private readonly IEmailService _emailService;
        private readonly IUserDataMgr _userDataMgr;
        public UserBusinessMgr(
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            //IEmailService emailService,
            IUserDataMgr userDataMgr)
        {
            _mapper = mapper;
            _appSettings = appSettings.Value;
            //_emailService = emailService;
            _userDataMgr = userDataMgr;
        }

        public void DeleteUser(int id)
        {
            var account = _userDataMgr.GetUserById(id);
            _userDataMgr.DeleteUser(account);
        }

        public AccountResponseViewModel CreateUser(CreateRequestViewModel model)
        {
            // validate
            if (_userDataMgr.CheckUserEmail(model.Email))
                throw new AppException($"Email '{model.Email}' is already registered");

            // map model to new account object
            var account = _mapper.Map<Account>(model);
            account.Created = DateTime.UtcNow;
            account.Verified = DateTime.UtcNow;

            // hash password
            account.PasswordHash = BC.HashPassword(model.Password);

            // save account
            _userDataMgr.UpdateUser(account);

            return _mapper.Map<AccountResponseViewModel>(account);
        }

        public AccountResponseViewModel UpdateUser(int id, UpdateRequestViewModel model)
        {
            var account = _userDataMgr.GetUserById(id);

            // validate
            if (account.Email != model.Email && _userDataMgr.CheckUserEmail(model.Email))
                throw new AppException($"Email '{model.Email}' is already taken");

            // hash password if it was entered
            if (!string.IsNullOrEmpty(model.Password))
                account.PasswordHash = BC.HashPassword(model.Password);

            // copy model to account and save
            _mapper.Map(model, account);
            account.Updated = DateTime.UtcNow;

            _userDataMgr.UpdateUser(account);

            return _mapper.Map<AccountResponseViewModel>(account);
        }

        public AccountResponseViewModel GetUserById(int id)
        {
            var account = _userDataMgr.GetUserById(id);
            return _mapper.Map<AccountResponseViewModel>(account);
        }

        public IEnumerable<AccountResponseViewModel> GetAllUsers()
        {
            var accounts = _userDataMgr.GetAllUsers();
            return _mapper.Map<IList<AccountResponseViewModel>>(accounts);
        }

        public void ResetPassword(ResetPasswordRequestViewModel model)
        {
            var account = _userDataMgr.GetUserByResetToken(model.Token);

            if (account == null)
                throw new AppException("Invalid token");

            // update password and remove reset token
            account.PasswordHash = BC.HashPassword(model.Password);
            account.PasswordReset = DateTime.UtcNow;
            account.ResetToken = null;
            account.ResetTokenExpires = null;

            _userDataMgr.UpdateUser(account);
        }

        public void ValidateResetToken(ValidateResetTokenRequestViewModel model)
        {
            var account = _userDataMgr.GetUserByResetToken(model.Token);

            if (account == null)
                throw new AppException("Invalid token");
        }

        public void Register(RegisterRequestViewModel model, string origin)
        {
            // validate
            if (_userDataMgr.CheckUserEmail(model.Email))
            {
                // send already registered error in email to prevent account enumeration
                sendAlreadyRegisteredEmail(model.Email, origin);
                return;
            }

            // map model to new account object
            var account = _mapper.Map<Account>(model);

            // first registered account is an admin
            var isFirstAccount = _userDataMgr.GetUsersCount() == 0;
            account.Role = isFirstAccount ? Role.Admin : Role.User;
            account.Created = DateTime.UtcNow;
            account.VerificationToken = randomTokenString();

            // hash password
            account.PasswordHash = BC.HashPassword(model.Password);

            // save account
            _userDataMgr.UpdateUser(account);

            // send email
            sendVerificationEmail(account, origin);
        }

        private void sendVerificationEmail(Account account, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/account/verify-email?token={account.VerificationToken}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                             <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                             <p><code>{account.VerificationToken}</code></p>";
            }

            //_emailService.Send(
            //    to: account.Email,
            //    subject: "Sign-up Verification API - Verify Email",
            //    html: $@"<h4>Verify Email</h4>
            //             <p>Thanks for registering!</p>
            //             {message}"
            //);
        }

        public void VerifyEmail(string token)
        {
            var account = _userDataMgr.GetUserByVerificationToken(token);

            if (account == null) throw new AppException("Verification failed");

            account.Verified = DateTime.UtcNow;
            account.VerificationToken = null;

            _userDataMgr.UpdateUser(account);
        }

        private void sendAlreadyRegisteredEmail(string email, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
                message = $@"<p>If you don't know your password please visit the <a href=""{origin}/account/forgot-password"">forgot password</a> page.</p>";
            else
                message = "<p>If you don't know your password you can reset it via the <code>/accounts/forgot-password</code> api route.</p>";

            //_emailService.Send(
            //    to: email,
            //    subject: "Sign-up Verification API - Email Already Registered",
            //    html: $@"<h4>Email Already Registered</h4>
            //             <p>Your email <strong>{email}</strong> is already registered.</p>
            //             {message}"
            //);
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var (refreshToken, account) = getRefreshToken(token);

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;

            _userDataMgr.UpdateUser(account);
        }

        public AuthenticateResponseViewModel RefreshToken(string token, string ipAddress)
        {
            var (refreshToken, account) = getRefreshToken(token);

            // replace old refresh token with a new one and save
            var newRefreshToken = generateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            account.RefreshTokens.Add(newRefreshToken);

            removeOldRefreshTokens(account);

            _userDataMgr.UpdateUser(account);

            // generate new jwt
            var jwtToken = generateJwtToken(account);

            var response = _mapper.Map<AuthenticateResponseViewModel>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        private (RefreshToken, Account) getRefreshToken(string token)
        {
            var account = _userDataMgr.GetUserByRefreshToken(token);
            if (account == null) throw new AppException("Invalid token");
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
            if (!refreshToken.IsActive) throw new AppException("Invalid token");
            return (refreshToken, account);
        }

        public void ForgotPassword(ForgotPasswordRequestViewModel model, string origin)
        {
            var account = _userDataMgr.GetUser(model.Email);

            // always return ok response to prevent email enumeration
            if (account == null) return;

            // create reset token that expires after 1 day
            account.ResetToken = randomTokenString();
            account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            _userDataMgr.UpdateUser(account);

            // send email
            sendPasswordResetEmail(account, origin);
        }

        private void sendPasswordResetEmail(Account account, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/account/reset-password?token={account.ResetToken}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                             <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                             <p><code>{account.ResetToken}</code></p>";
            }

            //_emailService.Send(
            //    to: account.Email,
            //    subject: "Sign-up Verification API - Reset Password",
            //    html: $@"<h4>Reset Password Email</h4>
            //             {message}"
            //);
        }


        public AuthenticateResponseViewModel Authenticate(AuthenticateRequestViewModel model, string ipAddress)
        {
            Account account = _userDataMgr.GetUser(model.Email);

            if (account == null || !account.IsVerified || !BC.Verify(model.Password, account.PasswordHash))
                throw new AppException("Email or password is incorrect");

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = generateJwtToken(account);
            var refreshToken = generateRefreshToken(ipAddress);
            account.RefreshTokens.Add(refreshToken);

            // remove old refresh tokens from account
            removeOldRefreshTokens(account);

            // save changes to db
            _userDataMgr.UpdateUser(account);

            var response = _mapper.Map<AuthenticateResponseViewModel>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = refreshToken.Token;
            return response;
        }

        private void removeOldRefreshTokens(Account account)
        {
            account.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        private string generateJwtToken(Account account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

        private string randomTokenString()
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[40];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            // convert random bytes to hex string
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }
    }
}
