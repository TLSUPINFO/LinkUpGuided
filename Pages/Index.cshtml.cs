﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace webapp_sam_lab13.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IConfiguration _configuration;

    public string StartError => ErrorLinkUp.Error?.Message;

    public string Message => ErrorLinkUp.Message;

    public bool IsAuthenticated { get; set; } = false;

    public IndexModel(ILogger<IndexModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        if (ErrorLinkUp.Error != null)
            _logger.LogError(ErrorLinkUp.Error.Message);

        _configuration = configuration;
    }

    public List<Publication> Publications { get; set; } = new List<Publication>();

    public async Task OnGet()
    {
        IsAuthenticated = User.Identity != null && User.Identity.IsAuthenticated;
        await FetchAnonymousContainersAsync();
    }

    public async Task<IActionResult> OnPostModifyPublicationAsync(int ID) => RedirectToPage("Creation", "Modify", new { publicationID = ID });

    public async Task<IActionResult> OnPostDeletePublicationAsync(int publicationID)
    {
        using (HttpClient httpClient = new HttpClient())
        {
            ClaimsIdentity identity = User.Identity as ClaimsIdentity;

            Claim claimToken = identity.Claims.FirstOrDefault(c => c.Type == "access_token");
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", claimToken?.Value);

            Claim claimIdentifier = identity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
            string hashID = "";
            if (claimIdentifier?.Value != null)
                hashID = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(claimIdentifier.Value))).Substring(0, Constant.SIZE_HASH);
            httpClient.DefaultRequestHeaders.Add("ID", hashID);
            httpClient.DefaultRequestHeaders.Add("PublicationID", publicationID.ToString());

            HttpResponseMessage response = await httpClient.DeleteAsync(/*"http://localhost:7071/api/DelPublication"*/_configuration["function-deletepublication-url"]);

            if (response.IsSuccessStatusCode)
                return RedirectToPage($"/Index");
            else
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, errorMessage);
            }
        }
    }

    async Task FetchAnonymousContainersAsync()
    {

        using (HttpClient httpClient = new HttpClient())
        {
            if(IsAuthenticated)
            {
                ClaimsIdentity identity = User.Identity as ClaimsIdentity;
                Claim claimToken = identity.Claims.FirstOrDefault(c => c.Type == "access_token");
                httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", claimToken?.Value);

                Claim claimIdentifier = identity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
                string hashID = "";
                if (claimIdentifier?.Value != null)
                    hashID = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(claimIdentifier.Value))).Substring(0, 32);

                httpClient.DefaultRequestHeaders.Add("ID", hashID);
            }

            httpClient.DefaultRequestHeaders.Add("PublicPost", "true");
            HttpResponseMessage response = await httpClient.GetAsync(/*"http://localhost:7071/api/GetPublications"*/_configuration["function-getpublications-url"]);

            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = await response.Content.ReadAsStringAsync();
                Publications = JsonSerializer.Deserialize<List<Publication>>(jsonResponse);

                if(Publications != null)
                    foreach (var publication in Publications)
                    {
                        System.Diagnostics.Debug.WriteLine($"Title: {publication.Title}, Description: {publication.Description}, MediaURL: {publication.MediaUrl}");
                    }
            }
            else
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                ErrorLinkUp.Message = errorMessage;
            }
        }
    }
}

public class Publication
{
    public int ID { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public string MediaUrl { get; set; }
    public string Author { get; set; }
    public DateTimeOffset ModifyDate { get; set; }
    public bool IsVideo { get; set; }
    public bool Owned { get; set; }
}

