using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace webapp_sam_lab13.Pages;

public class RedirectModel : PageModel
{
    ILogger<IndexModel> _logger;

    public RedirectModel(ILogger<IndexModel> logger, IConfiguration configuration)
    {
        _logger = logger;
    }

    public async Task<IActionResult> OnGet() =>  RedirectToPage("/Index");

}
