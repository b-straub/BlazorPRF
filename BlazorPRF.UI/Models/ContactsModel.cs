using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.UI.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for contacts state management.
/// Handles contact operations via IContactsService and exposes reactive state for UI binding.
/// Also manages asymmetric encryption page state (contact selection).
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class ContactsModel : ObservableModel
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    // ReSharper disable UnusedParameter.Local
    public partial ContactsModel(PrfModel prfModel, InviteModel inviteModel, IContactsService contactsService);
    // ReSharper restore UnusedParameter.Local

    /// <summary>
    /// Loaded contacts with their decrypted user data.
    /// </summary>
    [ObservableComponentTrigger]
    public partial List<(TrustedContact Contact, ContactUserData UserData)> Contacts { get; set; } = [];

    /// <summary>
    /// Error message from the last operation.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Whether the current error is a decryption failure (wrong passkey).
    /// </summary>
    public partial bool IsDecryptionError { get; set; }

    /// <summary>
    /// Whether contacts are currently being loaded.
    /// </summary>
    public partial bool Loading { get; set; }

    /// <summary>
    /// Navigation request after sign-out or reset.
    /// Component should navigate and then clear this value.
    /// </summary>
    [ObservableComponentTrigger]
    public partial string? NavigateToRequest { get; set; }

    /// <summary>
    /// Status message for snackbar display.
    /// </summary>
    [ObservableComponentTrigger]
    public partial StatusMessage? Status { get; set; }

    // Asymmetric page state

    /// <summary>
    /// Selected contact ID for asymmetric encryption page.
    /// </summary>
    public partial Guid? SelectedContactId { get; set; }

    /// <summary>
    /// Selected public key (armored) for asymmetric encryption.
    /// </summary>
    [ObservableComponentTrigger]
    public partial string? SelectedPublicKey { get; set; }

    // Commands
    [ObservableCommand(nameof(LoadContactsAsync))]
    public partial IObservableCommandAsync LoadContacts { get; }

    [ObservableCommand(nameof(DeleteContactAsync))]
    public partial IObservableCommandAsync<Guid> DeleteContact { get; }

    [ObservableCommand(nameof(ResetDatabaseAsync))]
    public partial IObservableCommandAsync ResetDatabase { get; }

    [ObservableCommand(nameof(SignOutImpl))]
    public partial IObservableCommand SignOut { get; }

    /// <summary>
    /// Load all contacts with error handling.
    /// </summary>
    private async Task LoadContactsAsync()
    {
        Loading = true;
        ErrorMessage = null;
        IsDecryptionError = false;

        var result = await ContactsService.LoadContactsAsync(() => PrfModel.EnsureKeysAsync());

        Contacts = result.Contacts;
        ErrorMessage = result.ErrorMessage;
        IsDecryptionError = result.IsDecryptionError;

        Loading = false;
    }

    /// <summary>
    /// Delete a contact by ID.
    /// </summary>
    private async Task DeleteContactAsync(Guid id)
    {
        var deleted = await ContactsService.DeleteContactAsync(id);

        if (deleted)
        {
            Status = new StatusMessage("Contact deleted", StatusSeverity.SUCCESS);
            Contacts = Contacts.Where(c => c.Contact.Id != id).ToList();
        }
        else
        {
            Status = new StatusMessage("Failed to delete contact", StatusSeverity.ERROR);
        }
    }

    /// <summary>
    /// Reset the database and navigate to home.
    /// </summary>
    private async Task ResetDatabaseAsync()
    {
        try
        {
            await ContactsService.ResetDatabaseAsync();

            // Clear auth state
            PrfModel.ClearKeys.Execute();

            Status = new StatusMessage("Database reset successfully!", StatusSeverity.SUCCESS);
            NavigateToRequest = "./";
        }
        catch (Exception ex)
        {
            Status = new StatusMessage($"Database reset failed: {ex.Message}", StatusSeverity.ERROR);
        }
    }

    /// <summary>
    /// Sign out and navigate to home.
    /// </summary>
    private void SignOutImpl()
    {
        PrfModel.ClearKeys.Execute();
        NavigateToRequest = "./";
    }

    /// <summary>
    /// Cross-model observer: watches InviteModel.Status for successful contact saves.
    /// Naming convention: On{ParameterName}{PropertyName}Changed.
    /// </summary>
    private void OnInviteModelStatusChanged()
    {
        if (InviteModel.Status?.Severity == StatusSeverity.SUCCESS)
        {
            _ = LoadContacts.ExecuteAsync();
        }
    }

    /// <summary>
    /// Selects a contact and builds armored public key for asymmetric encryption.
    /// </summary>
    public void SelectContact(Guid? contactId)
    {
        SelectedContactId = contactId;

        if (contactId is null)
        {
            SelectedPublicKey = null;
            return;
        }

        var contact = Contacts.FirstOrDefault(c => c.Contact.Id == contactId.Value);
        if (contact.Contact is not null && contact.UserData is not null)
        {
            var metadata = new PublicKeyMetadata
            {
                Name = contact.UserData.Username,
                Email = contact.UserData.Email,
                Comment = contact.UserData.Comment
            };
            SelectedPublicKey = PrfArmor.ArmorPublicKey(contact.Contact.X25519PublicKey, metadata);
        }
    }
}
