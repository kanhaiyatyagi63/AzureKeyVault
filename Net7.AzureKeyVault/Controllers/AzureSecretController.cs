using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Net7.AzureKeyVault.Models;
using Net7.AzureKeyVault.Options;
using System.Net;

namespace Net7.AzureKeyVault.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AzureSecretController : ControllerBase
{
    private readonly SecretClient _secretClient;
    public AzureSecretController(IOptions<AzureKeyVaultOptions> options)
    {
        var clientCredential = new ClientSecretCredential(options.Value.TenantId, options.Value.ClientId, options.Value.ClientSecret);
        _secretClient = new SecretClient(new Uri(options.Value.Uri), clientCredential);
    }

    /// <summary>
    /// Create a new secret or if secret exist with a key, 
    /// creates a new version for and set it to default
    /// </summary>
    /// <param name="model"></param>
    /// <returns>either secret is created or not</returns>
    [HttpPost("create-update-secret")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CreateOrUpdate([FromBody] CreateOrUpdateSecretModel model)
    {

        if (!ModelState.IsValid)
            return BadRequest("Invalid model state");
        try
        {

            var keyValueSecret = new KeyVaultSecret(model.Key, model.Value);

            keyValueSecret.Properties.NotBefore = model.StartedFrom; // started from
            keyValueSecret.Properties.ExpiresOn = model.ExpiresOn.HasValue ? model.ExpiresOn.Value : null; // valid to

            keyValueSecret.Properties.ContentType = model.ContentType ?? null; // optional
            keyValueSecret.Properties.Enabled = model.IsEnabled;

            if (model.Tags != null && model.Tags.Any())
            {
                foreach (KeyValuePair<string, string> tagItem in model.Tags)
                    keyValueSecret.Properties.Tags.Add(tagItem.Key, tagItem.Value);
            }

            var response = await _secretClient.SetSecretAsync(keyValueSecret);

            if (response.GetRawResponse().Status == (int)HttpStatusCode.OK)
                return Ok("Secret created");
            return BadRequest("Unable to create secret.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
    /// <summary>
    /// Update the properties of secret
    /// </summary>
    /// <param name="model"></param>
    /// <param name="version"></param>
    /// <returns>either secret is updated or not</returns>
    [HttpPut("update-secret-properties")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UpdateProperties([FromBody] UpdateSecretProperties model, [FromQuery] string? version)
    {
        if (!ModelState.IsValid)
            return BadRequest("Invalid model state");
        try
        {
            var secretResponse = await _secretClient.GetSecretAsync(model.Key, version);

            var properties = secretResponse.Value.Properties;

            if (model.ContentType != null)
                properties.ContentType = model.ContentType;

            properties.Enabled = model.IsEnabled;
            properties.NotBefore = model.StartedFrom;
            if (model.Tags != null && model.Tags.Any())
            {
                foreach (KeyValuePair<string, string> tagItem in model.Tags)
                {
                    if (model.Tags.ContainsKey(tagItem.Key))
                        properties.Tags[tagItem.Key] = tagItem.Value;
                    else
                        properties.Tags.Add(tagItem.Key, tagItem.Value);
                }
            }

            var response = await _secretClient.UpdateSecretPropertiesAsync(properties);
            if (response.GetRawResponse().Status == (int)HttpStatusCode.OK)
                return Ok("secret properties updated successfully.");

            return BadRequest("Unable to update secret properties.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }

    }
    /// <summary>
    /// Get the secret with the help of a key
    /// </summary>
    /// <param name="key"></param>
    /// <param name="version"></param>
    /// <returns>either secret with properties or not found</returns>
    [HttpGet("{key}")]
    [ProducesResponseType(typeof(Response<KeyVaultSecret>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Get([FromRoute] string key, [FromQuery] string? version = null)
    {
        if (string.IsNullOrEmpty(key))
            return BadRequest("key is required");

        try
        {
            var response = await _secretClient.GetSecretAsync(key, version);

            if (response.GetRawResponse().Status == (int)HttpStatusCode.OK)
                return Ok(response.Value);

            return BadRequest($"{key} with {version} not exist");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
    /// <summary>
    /// Soft delete the secret, takes atleast 5 minutes to reflect on azure
    /// </summary>
    /// <param name="key"></param>
    /// <returns>either secret is deleted or not</returns>
    [HttpDelete("soft-delete/{key}")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Delete(string key)
    {
        if (string.IsNullOrEmpty(key))
            return BadRequest("key is required");
        try
        {
            var response = await _secretClient.StartDeleteSecretAsync(key);
            if (response.GetRawResponse().Status == (int)HttpStatusCode.OK)
                return Ok($"secret {key} is soft-deleted successfully.");

            return BadRequest("something went wrong with soft-delete operation.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }

    }
    /// <summary>
    /// delete secret permanently but secret must be soft-deleted 
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    [HttpDelete("permanent-delete/{key}")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> PermanentDelete(string key)
    {
        if (string.IsNullOrEmpty(key))
            return BadRequest("key is required");
        try
        {
            var response = await _secretClient.PurgeDeletedSecretAsync(key);
            if (!response.IsError)
                return Ok($"secret {key} is deleted successfully!");

            return BadRequest(response.ToString());
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }

    }
    /// <summary>
    /// recover soft deleted secret, takes atleast 5 minutes to reflect on server
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    [HttpPost("recovery/{key}")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RecoverSecret(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return BadRequest("key is required");
        }
        try
        {
            var response = await _secretClient.StartRecoverDeletedSecretAsync(key);
            var result = response.WaitForCompletionResponse();
            return Ok("recovered successfully!");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    /// <summary>
    /// Get list of soft-deleted secrets
    /// </summary>
    /// <returns></returns>
    [HttpGet("get-deleted-secrets")]
    [ProducesResponseType(typeof(List<DeletedSecret>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(string), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> GetDeletedSecrets()
    {
        try
        {
            List<DeletedSecret> secrets = new List<DeletedSecret>();
            var response = _secretClient.GetDeletedSecretsAsync();

            await foreach (var page in response.AsPages())
            {
                // enumerate through page items
                foreach (var deletedSecret in page.Values)
                {
                    secrets.Add(deletedSecret);
                }
            }
            return Ok(secrets);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}
