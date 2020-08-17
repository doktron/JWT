using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Jwt;
using Owin;
using WebApplication2;

[assembly: OwinStartup(typeof(Startup))]

namespace WebApplication2
{
	public class Startup
	{
		public void Configuration(IAppBuilder app)
		{
			app.UseJwtBearerAuthentication(
				new JwtBearerAuthenticationOptions
				{
					TokenHandler = new DatschaJwtSecurityTokenHandler(),
					TokenValidationParameters = new TokenValidationParameters
					{
						ValidateIssuerSigningKey = true,
						IssuerSigningKey =
							new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ELh8O0ZYvoPVxymuLt6QmqBaAZomFHqB67oknRZjbK/RCHvh5JQ6lqOX0aic61t9nOtkTPkBifw9+1CMNCFtcVt53SVjr7UMIGr2jkPR5QBepgAr/yC1z35+o+lErWKBKl9NIg01Ge02VyuOC/u5axVPLo0gQnI7ww2n5QzLx3MIdGTkhMLyKIwT9aj0J8ODxDfU9H7UYeftEl7/jjThapC4hpaW1edSXQYBDE3JR5xKIyDU99L0NBN99nJk8plYMooXO6Et7O9QgZd401SZI8vBtWoTDHO9xFGDGd507mpsqNnDsgv7HDYxhHY7e2C+49OnojwuRCYWWnZPqdMQ2w==")),
						ValidateIssuer = false,
						ValidateAudience = false,
						ValidateLifetime = false
					}
				});
		}
	}

	public class DatschaJwtSecurityTokenHandler : JwtSecurityTokenHandler
	{
		public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters,
			out SecurityToken validatedToken)
		{
			if (string.IsNullOrWhiteSpace(token))
				throw LogHelper.LogArgumentNullException(nameof(token));

			if (validationParameters == null)
				throw LogHelper.LogArgumentNullException(nameof(validationParameters));

			if (token.Length > MaximumTokenSizeInBytes)
				throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(
					"IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.",
					token.Length, MaximumTokenSizeInBytes)));

			var tokenParts = token.Split(new[] {'.'}, 6);
			//if (tokenParts.Length != JwtConstants.JwsSegmentCount && tokenParts.Length != JwtConstants.JweSegmentCount)
			//	throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(System.IdentityModel.Tokens.Jwt.LogMessages.IDX12741, token)));

			if (tokenParts.Length == 5)
			{
				var jwtToken = ReadJwtToken(token);
				var decryptedJwt = DecryptToken(jwtToken, validationParameters);
				var innerToken = ValidateSignature(decryptedJwt, validationParameters);
				validatedToken = jwtToken;
				return ValidateTokenPayload(innerToken, validationParameters);
			}

			validatedToken = ValidateSignature(token, validationParameters);
			var claimsPrincipal = ValidateTokenPayload(validatedToken as JwtSecurityToken, validationParameters);
			return claimsPrincipal;
		}
	}
}