using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme) // передаем эти параметры что бы сказать что мы используем токен
    .AddJwtBearer/* <= в приложение добавляется конфигурация токена*/(options =>
    {
        options.TokenValidationParameters /*задает параметры валидации токена*/ = new TokenValidationParameters
        {
            // указывает, будет ли валидироваться издатель при валидации токена
            ValidateIssuer = true,
            // строка, представляющая издателя
            ValidIssuer = AuthOptions.ISSUER,
            // будет ли валидироваться потребитель токена
            ValidateAudience = true,
            // установка потребителя токена
            ValidAudience = AuthOptions.AUDIENCE,
            // будет ли валидироваться время существования
            ValidateLifetime = true,
            // установка ключа безопасности
            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),// он возвращает ключ безопасности который применяется для генерации токена 
            // валидация ключа безопасности
            ValidateIssuerSigningKey = true,
        };
    }
);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.Map("/login/{username}", (string username) =>
{
    var claims = new List<Claim> { new Claim(ClaimTypes.Name, username) };

    //делаем сам jwt токен 
    var jwt = new JwtSecurityToken
    (
        issuer: AuthOptions.ISSUER,
        audience: AuthOptions.AUDIENCE,
        claims: claims,
        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha512/*это алгоритм который определяет длину ключа в этом случае 32 байта*/));

    return new JwtSecurityTokenHandler().WriteToken(jwt);
});

app.Map("/data" , [Authorize] () => new { message = "какой то там текст"});

app.Run();

//Класс для настройки генерации токена 
public class AuthOptions 
{
    public const string ISSUER = "MyAuthServer"; // издатель токена jwt
    public const string AUDIENCE = "MyAuthClient";// сайт на котором применятся токен (потребитель токена)
    const string KEY = "MySecretKey";//ключ для шифрации,нужен для создания токена 
    public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));

}



