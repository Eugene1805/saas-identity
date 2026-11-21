namespace Saas.Identity.Application.Ports;

public interface IPasswordHasherPort
{
    string Hash(string plainPassword);
    bool Verify(string passwordHash, string plainPassword);
}
