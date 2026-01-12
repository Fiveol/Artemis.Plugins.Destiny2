public class Destiny2DataModel
{
    public bool IsLoggedIn { get; set; }
    public string DisplayName { get; set; } = "Please Sign In";
    public string SubclassName { get; set; } = "Unknown Subclass";

    // RGB components to drive Artemis layers
    public int SubclassColorR { get; set; } = 255;
    public int SubclassColorG { get; set; } = 0;
    public int SubclassColorB { get; set; } = 255;

    public bool IsActiveMode { get; set; } = true;
    public bool IsPrismatic { get; set; }
}
