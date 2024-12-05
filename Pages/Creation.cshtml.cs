using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using System.Text;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Principal;

namespace webapp_sam_lab13.Pages;

public class CreationModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    readonly IConfiguration _configuration;

    static int currentID = -1;

    [BindProperty]
    public string Title { get; set; } = string.Empty;

    [BindProperty]
    public string Description { get; set; } = string.Empty;

    [BindProperty]
    public IFormFile Media { get; set; } = null;

    [BindProperty]
    public bool Access { get; set; } = false;

    public CreationModel(ILogger<IndexModel> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public IActionResult OnGet()
    {
        //IIdentity identity = User?.Identity;
        //if (identity == null || !identity.IsAuthenticated)
        //    return RedirectToPage($"/Index");

        currentID = -1;
        return Page();
    }

    public void OnGetModify(int publicationID)
    {
        currentID = publicationID;

        // TODO => See if we can define title input field to publicationTitle's value here.
    }

    public async Task<IActionResult> OnPostSubmitPublicationAsync()
    {
        if (string.IsNullOrEmpty(Title) || string.IsNullOrEmpty(Description) || Media == null || Media.Length <= 0)
            return BadRequest(new BadRequestObjectResult("You need to complete all the fields."));

        byte[] mediaContent;
        string name = Media.FileName;
        using (Stream readStream = Media.OpenReadStream())
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                readStream.CopyTo(memoryStream);
                mediaContent = memoryStream.ToArray();
            }
        }

        ClaimsIdentity identity = User.Identity as ClaimsIdentity;

        var requestData = new
        {
            title = Title,
            description = Description,
            mediaBytes = Convert.ToBase64String(mediaContent),
            mediaFormat = Media.FileName.Split('.').Last(),
            access = Access ? "Public" : "Private",
            author = identity.Claims.FirstOrDefault(claim => claim.Type == "name")?.Value
        };

        string jsonString = JsonSerializer.Serialize(requestData);
        StringContent content = new StringContent(jsonString, Encoding.UTF8, "application/json");

        Claim claimIdentifier = identity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        string hashID = "";
        if (claimIdentifier?.Value != null)
            hashID = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(claimIdentifier.Value))).Substring(0, Constant.SIZE_HASH);

        Claim claimToken = identity.Claims.FirstOrDefault(c => c.Type == "access_token");
        return currentID == -1 ? await PostPublication(content, claimToken?.Value, hashID) : await ModifyPublication(content, claimToken?.Value, hashID);
    }

    async Task<IActionResult> PostPublication(StringContent content, string token, string hashID)
    {
        using (HttpClient httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            httpClient.DefaultRequestHeaders.Add("ID", hashID);

            HttpResponseMessage response = await httpClient.PostAsync("https://linkupfunctionappguided.azurewebsites.net/api/UploadPublication?code=2nhNca2ItVjBkhDpLitjYCX-NGfpfvSU8ZEL4baGpFaAAzFu9i2L0g%3D%3D"/*_configuration["function-uploadpublication-url"]*/, content);
            if (response.IsSuccessStatusCode)
                return RedirectToPage($"/Index");
            else
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, errorMessage);
            }
        }
    }

    async Task<IActionResult> ModifyPublication(StringContent content, string token, string hashID)
    {
        using (HttpClient httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            httpClient.DefaultRequestHeaders.Add("ID", hashID);
            httpClient.DefaultRequestHeaders.Add("PublicationID", currentID.ToString());

            HttpResponseMessage response = await httpClient.PutAsync("https://linkupfunctionappguided.azurewebsites.net/api/ModifyPublication?code=_2L3ZodGx6IDZ9DTSPmdYjFR6tNA355cdP2zK9-n-cC_AzFuMgfUlw%3D%3D"/*_configuration["function-modifypublication-url"]*/, content);
            if (response.IsSuccessStatusCode)
                return RedirectToPage($"/Index");
            else
            {
                string errorMessage = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, errorMessage);
            }
        }
    }
}
