namespace Net7.AzureKeyVault.Options;

public class AzureKeyVaultOptions
{
    public string KeyVault { get; set; } = null!;
    public string Uri { get; set; } = null!;
    public string ClientId { get; set; } = null!;
    public string ClientSecret { get; set; } = null!;
    public string TenantId { get; set; } = null!;
}
