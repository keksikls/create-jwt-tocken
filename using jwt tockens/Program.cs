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
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme) // �������� ��� ��������� ��� �� ������� ��� �� ���������� �����
    .AddJwtBearer/* <= � ���������� ����������� ������������ ������*/(options =>
    {
        options.TokenValidationParameters /*������ ��������� ��������� ������*/ = new TokenValidationParameters
        {
            // ���������, ����� �� �������������� �������� ��� ��������� ������
            ValidateIssuer = true,
            // ������, �������������� ��������
            ValidIssuer = AuthOptions.ISSUER,
            // ����� �� �������������� ����������� ������
            ValidateAudience = true,
            // ��������� ����������� ������
            ValidAudience = AuthOptions.AUDIENCE,
            // ����� �� �������������� ����� �������������
            ValidateLifetime = true,
            // ��������� ����� ������������
            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),// �� ���������� ���� ������������ ������� ����������� ��� ��������� ������ 
            // ��������� ����� ������������
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

    //������ ��� jwt ����� 
    var jwt = new JwtSecurityToken
    (
        issuer: AuthOptions.ISSUER,
        audience: AuthOptions.AUDIENCE,
        claims: claims,
        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha512/*��� �������� ������� ���������� ����� ����� � ���� ������ 32 �����*/));

    return new JwtSecurityTokenHandler().WriteToken(jwt);
});

app.Map("/data" , [Authorize] () => new { message = "����� �� ��� �����"});

app.Run();

//����� ��� ��������� ��������� ������ 
public class AuthOptions 
{
    public const string ISSUER = "MyAuthServer"; // �������� ������ jwt
    public const string AUDIENCE = "MyAuthClient";// ���� �� ������� ���������� ����� (����������� ������)
    const string KEY = "MySecretKey";//���� ��� ��������,����� ��� �������� ������ 
    public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));

}



