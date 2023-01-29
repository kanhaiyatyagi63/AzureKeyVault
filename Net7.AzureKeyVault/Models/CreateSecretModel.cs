namespace Net7.AzureKeyVault.Models
{
    public class CreateOrUpdateSecretModel
    {
        public string Key { get; set; } = null!;
        public string Value { get; set; } = null!;
        public Dictionary<string, string>? Tags { get; set; }
        public string? ContentType { get; set; }
        public DateTime? ExpiresOn { get; set; }
        public DateTime StartedFrom { get; set; }  = DateTime.Now;
        public bool IsEnabled { get; set; }
    }
}
