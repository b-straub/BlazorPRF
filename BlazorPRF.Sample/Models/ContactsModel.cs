using RxBlazorV2.Model;

namespace BlazorPRF.Sample.Models;

/// <summary>
/// Reactive model for contacts state management.
/// Triggers UI updates when contacts are modified.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class ContactsModel : ObservableModel
{
    /// <summary>
    /// Incremented each time contacts are modified.
    /// Components can react to this to refresh their contact lists.
    /// </summary>
    [ObservableComponentTrigger]
    public partial int ContactsVersion { get; set; }

    /// <summary>
    /// Signal that contacts have been modified and UI should refresh.
    /// </summary>
    public void NotifyContactsChanged()
    {
        ContactsVersion++;
    }
}
