// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Azure.EventHubs;
using Microsoft.Azure.EventHubs.Processor;
using Microsoft.Azure.Management.Media;
using Microsoft.Azure.Management.Media.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Rest;
using Microsoft.Rest.Azure.Authentication;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace AMSLiveEventDRMDVR
{
    class Program
    {
        private const string AdaptiveStreamingTransformName = "MyTransformWithAdaptiveStreamingPreset";
        private static readonly string Issuer = "myIssuer";
        private static readonly string Audience = "myAudience";
        private static byte[] TokenSigningKey = new byte[40];
        private static readonly string ContentKeyPolicyName = "DualPRWVContentPolicy";
        private static readonly string DefaultStreamingEndpointName = "default";  // Change this to your Endpoint name.

        public static async Task Main(string[] args)
        {
            // Please make sure you have set configuration in appsettings.json.
            ConfigWrapper config = new ConfigWrapper(new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build());

            try
            {
                await RunAsync(config);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"{exception.Message}");

                ApiErrorException apiException = exception.GetBaseException() as ApiErrorException;
                if (apiException != null)
                {
                    Console.Error.WriteLine(
                        $"ERROR: API call failed with error code '{apiException.Body.Error.Code}' and message '{apiException.Body.Error.Message}'.");
                }
            }

            Console.WriteLine("Press Enter to continue.");
            Console.ReadLine();
        }

        /// <summary>
        /// Run the sample async.
        /// </summary>
        /// <param name="config">The param is of type ConfigWrapper. This class reads values from local configuration file.</param>
        /// <returns></returns>
        private static async Task RunAsync(ConfigWrapper config)
        {
            IAzureMediaServicesClient client;
            try
            {
                client = await CreateMediaServicesClientAsync(config);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("TIP: Make sure that you have filled out the appsettings.json file before running this sample.");
                Console.Error.WriteLine($"{e.Message}");
                return;
            }

            // Set the polling interval for long running operations to 2 seconds.
            // The default value is 30 seconds for the .NET client SDK
            client.LongRunningOperationRetryTimeout = 2;

            // Creating a unique suffix so that we don't have name collisions if you run the sample
            // multiple times without cleaning up.
            string uniqueness = Guid.NewGuid().ToString().Substring(0, 13);
            string liveEventName = "liveevent-" + uniqueness;
            string assetName = "archiveAsset" + uniqueness;
            string liveOutputName = "liveOutput" + uniqueness;
            string drvStreamingLocatorName = "streamingLocator" + uniqueness;
            string archiveStreamingLocatorName = "fullLocator-" + uniqueness;
            string drvAssetFilterName = "filter-" + uniqueness;
            string streamingEndpointName = "default";  // Change this to your Endpoint name.
            EventProcessorHost eventProcessorHost = null;
            bool stopEndpoint = false;

            try
            {
                // Getting the mediaServices account so that we can use the location to create the
                // LiveEvent and StreamingEndpoint
                MediaService mediaService = await client.Mediaservices.GetAsync(config.ResourceGroup, config.AccountName);

                Console.WriteLine($"Creating a live event named {liveEventName}");
                Console.WriteLine();

                // Note: When creating a LiveEvent, you can specify allowed IP addresses in one of the following formats:                 
                //      IpV4 address with 4 numbers
                //      CIDR address range

                IPRange allAllowIPRange = new IPRange(
                    name: "AllowAll",
                    address: "0.0.0.0",
                    subnetPrefixLength: 0
                );

                // Create the LiveEvent input IP access control.
                LiveEventInputAccessControl liveEventInputAccess = new LiveEventInputAccessControl
                {
                    Ip = new IPAccessControl(
                            allow: new IPRange[]
                            {
                                allAllowIPRange
                            }
                        )
                };

                // Create the LiveEvent Preview IP access control
                LiveEventPreview liveEventPreview = new LiveEventPreview
                {
                    AccessControl = new LiveEventPreviewAccessControl(
                        ip: new IPAccessControl(
                            allow: new IPRange[]
                            {
                                allAllowIPRange
                            }
                        )
                    )
                };

                // To get the same ingest URL for the same LiveEvent name:
                // 1. Set vanityUrl to true so you have ingest like: 
                //        rtmps://liveevent-hevc12-eventgridmediaservice-usw22.channel.media.azure.net:2935/live/522f9b27dd2d4b26aeb9ef8ab96c5c77           
                // 2. Set accessToken to a desired GUID string (with or without hyphen)

                LiveEvent liveEvent = new LiveEvent(
                    location: mediaService.Location,
                    description: "Sample LiveEvent for testing",
                    vanityUrl: false,
                    encoding: new LiveEventEncoding(
                                // Set this to Standard to enable a trans-coding LiveEvent, and None to enable a pass-through LiveEvent
                                encodingType: LiveEventEncodingType.Premium1080p,
                                presetName: null
                            ),
                    input: new LiveEventInput(LiveEventInputProtocol.RTMP, liveEventInputAccess),
                    preview: liveEventPreview,
                    streamOptions: new List<StreamOptionsFlag?>()
                    {
                        // Set this to Default or Low Latency
                        // When using Low Latency mode, you must configure the Azure Media Player to use the 
                        // quick start heuristic profile or you won't notice the change. 
                        // In the AMP player client side JS options, set -  heuristicProfile: "Low Latency Heuristic Profile". 
                        // To use low latency optimally, you should tune your encoder settings down to 1 second GOP size instead of 2 seconds.
                        // StreamOptionsFlag.LowLatency
                    }
                );
                Console.WriteLine($"Creating the LiveEvent, be patient this can take time...");

                // When autostart is set to true, the Live Event will be started after creation. 
                // That means, the billing starts as soon as the Live Event starts running. 
                // You must explicitly call Stop on the Live Event resource to halt further billing.
                // The following operation can sometimes take awhile. Be patient.
                liveEvent = await client.LiveEvents.CreateAsync(config.ResourceGroup, config.AccountName, liveEventName, liveEvent, autoStart: true);

                // Start monitoring LiveEvent events.
                try
                {
                    // Please refer README for Event Hub and storage settings.
                    Console.WriteLine("Starting monitoring LiveEvent events...");
                    string StorageConnectionString = string.Format("DefaultEndpointsProtocol=https;AccountName={0};AccountKey={1}",
                        config.StorageAccountName, config.StorageAccountKey);

                    // Create a new host to process events from an Event Hub.
                    Console.WriteLine("Creating a new host to process events from an Event Hub...");
                    eventProcessorHost = new EventProcessorHost(config.EventHubName,
                        PartitionReceiver.DefaultConsumerGroupName, config.EventHubConnectionString,
                        StorageConnectionString, config.StorageContainerName);

                    // Registers the Event Processor Host and starts receiving messages.
                    await eventProcessorHost.RegisterEventProcessorFactoryAsync(new MediaServicesEventProcessorFactory(liveEventName),
                        EventProcessorOptions.DefaultOptions);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to connect to Event Hub, please refer README for Event Hub and storage settings. Skipping event monitoring...");
                    Console.WriteLine(e.Message);
                }



                // Get the input endpoint to configure the on premise encoder with
                string ingestUrl = liveEvent.Input.Endpoints.First().Url;
                Console.WriteLine($"The ingest url to configure the on premise encoder with is:");
                Console.WriteLine($"\t{ingestUrl}");
                Console.WriteLine();

                // Use the previewEndpoint to preview and verify
                // that the input from the encoder is actually being received
                string previewEndpoint = liveEvent.Preview.Endpoints.First().Url;
                Console.WriteLine($"The preview url is:");
                Console.WriteLine($"\t{previewEndpoint}");
                Console.WriteLine();

                Console.WriteLine($"Open the live preview in your browser and use the Azure Media Player to monitor the preview playback:");
                Console.WriteLine($"\thttps://ampdemo.azureedge.net/?url={previewEndpoint}"); // &heuristicprofile=lowlatency");
                Console.WriteLine();

                Console.WriteLine("Start the live stream now, sending the input to the ingest url and verify that it is arriving with the preview url.");
                Console.WriteLine("IMPORTANT TIP!: Make ABSOLUTLEY CERTAIN that the video is flowing to the Preview URL before continuing!");
                Console.WriteLine("******************************");
                Console.WriteLine("* Press ENTER to continue... *");
                Console.WriteLine("******************************");
                Console.WriteLine();
                Console.Out.Flush();

                var ignoredInput = Console.ReadLine();

                // Create an Asset for the LiveOutput to use
                Console.WriteLine($"Creating an asset named {assetName}");
                Console.WriteLine();
                Asset asset = await client.Assets.CreateOrUpdateAsync(config.ResourceGroup, config.AccountName, assetName, new Asset());

                //AssetFilter drvAssetFilter = new AssetFilter(
                //    presentationTimeRange: new PresentationTimeRange(
                //        forceEndTimestamp:false,
                //        // 300 seconds sliding window
                //        presentationWindowDuration: 3000000000L,
                //        // This value defines the latest live position that a client can seek back to 10 seconds, must be smaller than sliding window.
                //        liveBackoffDuration: 100000000L)
                //);

                //drvAssetFilter = await client.AssetFilters.CreateOrUpdateAsync(config.ResourceGroup, config.AccountName,
                //    assetName, drvAssetFilterName, drvAssetFilter);

                // Create the LiveOutput
                string manifestName = "output";
                Console.WriteLine($"Creating a live output named {liveOutputName}");
                Console.WriteLine();

                // withArchiveWindowLength: Can be set from 3 minutes to 25 hours. content that falls outside of ArchiveWindowLength
                // is continuously discarded from storage and is non-recoverable. For a full event archive, set to the maximum, 25 hours.
                LiveOutput liveOutput = new LiveOutput(assetName: asset.Name, manifestName: manifestName, archiveWindowLength: TimeSpan.FromHours(2));
                liveOutput = await client.LiveOutputs.CreateAsync(config.ResourceGroup, config.AccountName, liveEventName, liveOutputName, liveOutput);

                // Create the StreamingLocator
                Console.WriteLine($"Creating a streaming locator named {drvStreamingLocatorName}");
                Console.WriteLine();

                //IList<string> filters = new List<string>();
                ////filters.Add(drvAssetFilterName);
                //StreamingLocator locator = await client.StreamingLocators.CreateAsync(config.ResourceGroup,
                //    config.AccountName, 
                //    drvStreamingLocatorName, 
                //    new StreamingLocator
                //    {
                //        AssetName = assetName,
                //        StreamingPolicyName = PredefinedStreamingPolicy.ClearStreamingOnly,
                //        Filters = filters   // Associate filters with StreamingLocator.
                //    });

                // Set a token signing key that you want to use
                TokenSigningKey = Convert.FromBase64String(config.SymmetricKeyPR);

                // Create the content key policy that configures how the content key is delivered to end clients
                // via the Key Delivery component of Azure Media Services.
                // We are using the ContentKeyIdentifierClaim in the ContentKeyPolicy which means that the token presented
                // to the Key Delivery Component must have the identifier of the content key in it. 
                ContentKeyPolicy policy = await GetOrCreateContentKeyPolicyAsync(client, config.ResourceGroup, config.AccountName, ContentKeyPolicyName, TokenSigningKey);

                // Sets StreamingLocator.StreamingPolicyName to "Predefined_MultiDrmCencStreaming" policy. 
                StreamingLocator locator = await CreateStreamingLocatorAsync(client, config.ResourceGroup, config.AccountName, asset.Name, drvStreamingLocatorName, ContentKeyPolicyName);

                // In this example, we want to play the PlayReady (CENC) encrypted stream. 
                // We need to get the key identifier of the content key where its type is CommonEncryptionCenc.
                string keyIdentifier = locator.ContentKeys.Where(k => k.Type == StreamingLocatorContentKeyType.CommonEncryptionCenc).First().Id.ToString();

                Console.WriteLine($"KeyIdentifier = {keyIdentifier}");

                // In order to generate our test token we must get the ContentKeyId to put in the ContentKeyIdentifierClaim claim.
                string token = GetTokenAsync(Issuer, Audience, keyIdentifier, TokenSigningKey);

                StreamingEndpoint streamingEndpoint = await client.StreamingEndpoints.GetAsync(config.ResourceGroup,
                    config.AccountName, DefaultStreamingEndpointName);

                // If it's not running, Start it. 
                if (streamingEndpoint.ResourceState != StreamingEndpointResourceState.Running)
                {
                    Console.WriteLine("Streaming Endpoint was Stopped, restarting now..");
                    await client.StreamingEndpoints.StartAsync(config.ResourceGroup, config.AccountName, streamingEndpointName);

                    // Since we started the endpoint, we should stop it in cleanup.
                    stopEndpoint = true;
                }
                string dashPath = await GetDASHStreamingUrlAsync(client, config.ResourceGroup, config.AccountName, locator.Name, streamingEndpoint);

                if (dashPath.Length > 0)
                {
                    Console.WriteLine("---Encrypted URL for IE or Edge---");
                    Console.WriteLine($"\thttps://ampdemo.azureedge.net/?url={dashPath}&playready=true&token=Bearer%3D{token}");
                    Console.WriteLine("---Encrypted URL for Chrome or Firefox---");
                    Console.WriteLine($"\thttps://ampdemo.azureedge.net/?url={dashPath}&widevine=true&token=Bearer%3D{token}");
                    Console.WriteLine("-------------------");
                    Console.WriteLine("If you see an error in Azure Media Player, wait a few moments and try again.");
                    Console.WriteLine("Continue experimenting with the stream until you are ready to finish.");
                    Console.WriteLine();
                    Console.WriteLine("***********************************************");
                    Console.WriteLine("* Press ENTER anytime to stop the LiveEvent.  *");
                    Console.WriteLine("***********************************************");
                    Console.WriteLine();
                    Console.Out.Flush();
                    ignoredInput = Console.ReadLine();

                    Console.WriteLine("Cleaning up LiveEvent and output...");
                    await CleanupLiveEventAndOutputAsync(client, config.ResourceGroup, config.AccountName, liveEventName);
                    Console.WriteLine("The LiveOutput and LiveEvent are now deleted.  The event is available as an archive and can still be streamed.");

                    // If we started the endpoint, we'll stop it. Otherwise, we'll keep the endpoint running and print urls
                    // that can be played even after this sample ends.
                    if (!stopEndpoint)
                    {
                        StreamingLocator archiveLocator = await client.StreamingLocators.CreateAsync(config.ResourceGroup,
                            config.AccountName,
                            archiveStreamingLocatorName,
                            new StreamingLocator
                            {
                                AssetName = assetName,
                                StreamingPolicyName = PredefinedStreamingPolicy.ClearStreamingOnly
                            });
                        Console.WriteLine("To playback the archived files, Use the following urls:");
                        await PrintPaths(client, config.ResourceGroup, config.AccountName, archiveStreamingLocatorName, streamingEndpoint);
                    }
                }
            }
            catch (ApiErrorException e)
            {
                Console.WriteLine("Hit ApiErrorException");
                Console.WriteLine($"\tCode: {e.Body.Error.Code}");
                Console.WriteLine($"\tCode: {e.Body.Error.Message}");
                Console.WriteLine();
                Console.WriteLine("Exiting, cleanup may be necessary...");
                Console.ReadLine();
            }
            finally
            {
                await CleanupLiveEventAndOutputAsync(client, config.ResourceGroup, config.AccountName, liveEventName);

                await CleanupLocatorAsync(client, config.ResourceGroup, config.AccountName, drvStreamingLocatorName);

                // Stop event monitoring.
                if (eventProcessorHost != null)
                {
                    await eventProcessorHost.UnregisterEventProcessorAsync();
                }

                if (stopEndpoint)
                {
                    // Because we started the endpoint, we'll stop it.
                    await client.StreamingEndpoints.StopAsync(config.ResourceGroup, config.AccountName, streamingEndpointName);
                }
                else
                {
                    // We will keep the endpoint running because it was not started by us. There are costs to keep it running.
                    // Please refer https://azure.microsoft.com/en-us/pricing/details/media-services/ for pricing. 
                    Console.WriteLine($"The endpoint {streamingEndpointName} is running. To halt further billing on the endpoint, please stop it in azure portal or AMS Explorer.");
                }
            }
        }

        /// <summary>
        /// Create the ServiceClientCredentials object based on the credentials
        /// supplied in local configuration file.
        /// </summary>
        /// <param name="config">The param is of type ConfigWrapper. This class reads values from local configuration file.</param>
        /// <returns></returns>
        private static async Task<ServiceClientCredentials> GetCredentialsAsync(ConfigWrapper config)
        {
            // Use ApplicationTokenProvider.LoginSilentWithCertificateAsync or UserTokenProvider.LoginSilentAsync to get a token using service principal with certificate
            //// ClientAssertionCertificate
            //// ApplicationTokenProvider.LoginSilentWithCertificateAsync

            // Use ApplicationTokenProvider.LoginSilentAsync to get a token using a service principal with symmetric key
            ClientCredential clientCredential = new ClientCredential(config.AadClientId, config.AadSecret);
            return await ApplicationTokenProvider.LoginSilentAsync(config.AadTenantId, clientCredential, ActiveDirectoryServiceSettings.Azure);
        }

        /// <summary>
        /// Creates the AzureMediaServicesClient object based on the credentials
        /// supplied in local configuration file.
        /// </summary>
        /// <param name="config">The param is of type ConfigWrapper. This class reads values from local configuration file.</param>
        /// <returns></returns>
        private static async Task<IAzureMediaServicesClient> CreateMediaServicesClientAsync(ConfigWrapper config)
        {
            var credentials = await GetCredentialsAsync(config);

            return new AzureMediaServicesClient(config.ArmEndpoint, credentials)
            {
                SubscriptionId = config.SubscriptionId,
            };
        }

        /// <summary>
        /// Cleanup LiveEvent.
        /// </summary>
        /// <param name="client">The Media Services client.</param>
        /// <param name="resourceGroupName">The name of the resource group within the Azure subscription.</param>
        /// <param name="accountName"> The Media Services account name.</param>
        /// <param name="liveEventName">The LiveEvent name.</param>
        /// <returns></returns>
        private static async Task CleanupLiveEventAndOutputAsync(IAzureMediaServicesClient client, string resourceGroup, string accountName, string liveEventName)
        {
            try
            {
                LiveEvent liveEvent = await client.LiveEvents.GetAsync(resourceGroup, accountName, liveEventName);

                if (liveEvent != null)
                {
                    if (liveEvent.ResourceState == LiveEventResourceState.Running)
                    {
                        // If the LiveEvent is running, remove LiveOutpts and stop it.
                        var liveOutputs = await client.LiveOutputs.ListAsync(resourceGroup, accountName, liveEventName);
                        foreach (var liveOutput in liveOutputs)
                        {
                            // Delete a LiveOutput
                            await client.LiveOutputs.DeleteAsync(resourceGroup, accountName, liveEventName, liveOutput.Name);
                        }
                        await client.LiveEvents.StopAsync(resourceGroup, accountName, liveEventName);
                    }

                    // Delete the LiveEvent
                    await client.LiveEvents.DeleteAsync(resourceGroup, accountName, liveEventName);
                }
            }
            catch (ApiErrorException e)
            {
                Console.WriteLine("CleanupLiveEventAndOutputAsync -- Hit ApiErrorException");
                Console.WriteLine($"\tCode: {e.Body.Error.Code}");
                Console.WriteLine($"\tCode: {e.Body.Error.Message}");
                Console.WriteLine();
            }
        }

        private static async Task<ContentKeyPolicy> GetOrCreateContentKeyPolicyAsync(
            IAzureMediaServicesClient client,
            string resourceGroupName,
            string accountName,
            string contentKeyPolicyName,
            byte[] tokenSigningKey)
        {
            ContentKeyPolicy policy = await client.ContentKeyPolicies.GetAsync(resourceGroupName, accountName, contentKeyPolicyName);

            if (policy == null)
            {
                ContentKeyPolicySymmetricTokenKey primaryKey = new ContentKeyPolicySymmetricTokenKey(tokenSigningKey);
                List<ContentKeyPolicyTokenClaim> requiredClaims = new List<ContentKeyPolicyTokenClaim>()
        {
            ContentKeyPolicyTokenClaim.ContentKeyIdentifierClaim
        };
                List<ContentKeyPolicyRestrictionTokenKey> alternateKeys = null;
                ContentKeyPolicyTokenRestriction restriction
                    = new ContentKeyPolicyTokenRestriction(Issuer, Audience, primaryKey, ContentKeyPolicyRestrictionTokenType.Jwt, alternateKeys, requiredClaims);

                ContentKeyPolicyPlayReadyConfiguration playReadyConfig = ConfigurePlayReadyLicenseTemplate();
                ContentKeyPolicyWidevineConfiguration widevineConfig = ConfigureWidevineLicenseTempate();
                // ContentKeyPolicyFairPlayConfiguration fairplayConfig = ConfigureFairPlayPolicyOptions();

                List<ContentKeyPolicyOption> options = new List<ContentKeyPolicyOption>();

                options.Add(
                    new ContentKeyPolicyOption()
                    {
                        Configuration = playReadyConfig,
                        // If you want to set an open restriction, use
                        // Restriction = new ContentKeyPolicyOpenRestriction()
                        Restriction = restriction
                    });

                options.Add(
                    new ContentKeyPolicyOption()
                    {
                        Configuration = widevineConfig,
                        Restriction = restriction
                    });

                // add CBCS ContentKeyPolicyOption into the list
                //   options.Add(
                //       new ContentKeyPolicyOption()
                //       {
                //           Configuration = fairplayConfig,
                //           Restriction = restriction,
                //           Name = "ContentKeyPolicyOption_CBCS"
                //       });

                policy = await client.ContentKeyPolicies.CreateOrUpdateAsync(resourceGroupName, accountName, contentKeyPolicyName, options);
            }
            else
            {
                // Get the signing key from the existing policy.
                var policyProperties = await client.ContentKeyPolicies.GetPolicyPropertiesWithSecretsAsync(resourceGroupName, accountName, contentKeyPolicyName);
                var restriction = policyProperties.Options[0].Restriction as ContentKeyPolicyTokenRestriction;
                if (restriction != null)
                {
                    var signingKey = restriction.PrimaryVerificationKey as ContentKeyPolicySymmetricTokenKey;
                    if (signingKey != null)
                    {
                        TokenSigningKey = signingKey.KeyValue;
                    }
                }
            }
            return policy;
        }

        /// <summary>
        /// Configures PlayReady license template.
        /// </summary>
        /// <returns></returns>
        private static ContentKeyPolicyPlayReadyConfiguration ConfigurePlayReadyLicenseTemplate()
        {
            ContentKeyPolicyPlayReadyLicense objContentKeyPolicyPlayReadyLicense;

            objContentKeyPolicyPlayReadyLicense = new ContentKeyPolicyPlayReadyLicense
            {
                AllowTestDevices = true,
                ContentKeyLocation = new ContentKeyPolicyPlayReadyContentEncryptionKeyFromHeader(),
                ContentType = ContentKeyPolicyPlayReadyContentType.UltraVioletStreaming,
                LicenseType = ContentKeyPolicyPlayReadyLicenseType.NonPersistent,
                PlayRight = new ContentKeyPolicyPlayReadyPlayRight
                {
                    ImageConstraintForAnalogComponentVideoRestriction = true,
                    ExplicitAnalogTelevisionOutputRestriction = new ContentKeyPolicyPlayReadyExplicitAnalogTelevisionRestriction(true, 2),
                    AllowPassingVideoContentToUnknownOutput = ContentKeyPolicyPlayReadyUnknownOutputPassingOption.Allowed
                }
            };

            ContentKeyPolicyPlayReadyConfiguration objContentKeyPolicyPlayReadyConfiguration = new ContentKeyPolicyPlayReadyConfiguration
            {
                Licenses = new List<ContentKeyPolicyPlayReadyLicense> { objContentKeyPolicyPlayReadyLicense }
            };

            return objContentKeyPolicyPlayReadyConfiguration;
        }


        /// <summary>
        /// Configures Widevine license template.
        /// </summary>
        /// <returns></returns>
        private static ContentKeyPolicyWidevineConfiguration ConfigureWidevineLicenseTempate()
        {
            WidevineTemplate template = new WidevineTemplate()
            {
                AllowedTrackTypes = "SD_HD",
                ContentKeySpecs = new ContentKeySpec[]
                {
                    new ContentKeySpec()
                    {
                        TrackType = "SD",
                        SecurityLevel = 1,
                        RequiredOutputProtection = new OutputProtection()
                        {
                            HDCP = "HDCP_NONE"
                        }
                    }
                },
                PolicyOverrides = new PolicyOverrides()
                {
                    CanPlay = true,
                    CanPersist = false,
                    CanRenew = false,
                    RentalDurationSeconds = 2592000,
                    PlaybackDurationSeconds = 10800,
                    LicenseDurationSeconds = 604800,
                }
            };

            ContentKeyPolicyWidevineConfiguration objContentKeyPolicyWidevineConfiguration = new ContentKeyPolicyWidevineConfiguration
            {
                WidevineTemplate = Newtonsoft.Json.JsonConvert.SerializeObject(template)
            };
            return objContentKeyPolicyWidevineConfiguration;
        }

        private static async Task<StreamingLocator> CreateStreamingLocatorAsync(
            IAzureMediaServicesClient client,
            string resourceGroup,
            string accountName,
            string assetName,
            string locatorName,
            string contentPolicyName)
        {
            StreamingLocator locator = await client.StreamingLocators.GetAsync(resourceGroup, accountName, locatorName);

            if (locator != null)
            {
                // Name collision! This should not happen in this sample. If it does happen, in order to get the sample to work,
                // let's just go ahead and create a unique name.
                // Note that the returned locatorName can have a different name than the one specified as an input parameter.
                // You may want to update this part to throw an Exception instead, and handle name collisions differently.
                Console.WriteLine("Warning – found an existing Streaming Locator with name = " + locatorName);

                string uniqueness = $"-{Guid.NewGuid().ToString("N")}";
                locatorName += uniqueness;

                Console.WriteLine("Creating a Streaming Locator with this name instead: " + locatorName);
            }

            locator = await client.StreamingLocators.CreateAsync(
                resourceGroup,
                accountName,
                locatorName,
                new StreamingLocator
                {
                    AssetName = assetName,
                    // "Predefined_MultiDrmCencStreaming" policy supports envelope and cenc encryption
                    StreamingPolicyName = "Predefined_MultiDrmCencStreaming",
                    DefaultContentKeyPolicyName = contentPolicyName
                });

            return locator;
        }


        /// <summary>
        /// Create a token that will be used to protect your stream.
        /// Only authorized clients would be able to play the video.  
        /// </summary>
        /// <param name="issuer">The issuer is the secure token service that issues the token. </param>
        /// <param name="audience">The audience, sometimes called scope, describes the intent of the token or the resource the token authorizes access to. </param>
        /// <param name="keyIdentifier">The content key ID.</param>
        /// <param name="tokenVerificationKey">Contains the key that the token was signed with. </param>
        /// <returns></returns>
        private static string GetTokenAsync(string issuer, string audience, string keyIdentifier, byte[] tokenVerificationKey)
        {
            var tokenSigningKey = new SymmetricSecurityKey(tokenVerificationKey);

            SigningCredentials cred = new SigningCredentials(
                tokenSigningKey,
                // Use the  HmacSha256 and not the HmacSha256Signature option, or the token will not work!
                SecurityAlgorithms.HmacSha256,
                SecurityAlgorithms.Sha256Digest);

            Claim[] claims = new Claim[]
            {
                new Claim(ContentKeyPolicyTokenClaim.ContentKeyIdentifierClaim.ClaimType, keyIdentifier)
            };

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.Now.AddMinutes(-5),
                expires: DateTime.Now.AddMinutes(60),
                signingCredentials: cred);

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            return handler.WriteToken(token);
        }


        /// <summary>
        /// Checks if the "default" streaming endpoint is in the running state,
        /// if not, starts it.
        /// Then, builds the streaming URLs.
        /// </summary>
        /// <param name="client">The Media Services client.</param>
        /// <param name="resourceGroupName">The name of the resource group within the Azure subscription.</param>
        /// <param name="accountName"> The Media Services account name.</param>
        /// <param name="locatorName">The name of the StreamingLocator that was created.</param>
        /// <returns></returns>
        private static async Task<string> GetDASHStreamingUrlAsync(IAzureMediaServicesClient client, string resourceGroupName,
            string accountName, string locatorName, StreamingEndpoint streamingEndpoint)
        {
            string dashPath = "";

            ListPathsResponse paths = await client.StreamingLocators.ListPathsAsync(resourceGroupName, accountName, locatorName);

            foreach (StreamingPath path in paths.StreamingPaths)
            {
                UriBuilder uriBuilder = new UriBuilder
                {
                    Scheme = "https",
                    Host = streamingEndpoint.HostName
                };

                // Look for just the DASH path and generate a URL for the Azure Media Player to playback the encrypted DASH content. 
                // Note that the JWT token is set to expire in 1 hour. 
                if (path.StreamingProtocol == StreamingPolicyStreamingProtocol.Dash)
                {
                    uriBuilder.Path = path.Paths[0];

                    dashPath = uriBuilder.ToString();

                }
            }

            return dashPath;
        }

        /// <summary>
        /// Clean up streaming locator and asset.
        /// </summary>
        /// <param name="client">The Media Services client.</param>
        /// <param name="resourceGroupName">The name of the resource group within the Azure subscription.</param>
        /// <param name="accountName"> The Media Services account name.</param>
        /// <param name="streamingLocatorName">The streaming locator name.</param>
        /// <param name="assetName">The asset name.</param>
        /// <returns></returns>
        private static async Task CleanupLocatorAsync(IAzureMediaServicesClient client, string resourceGroup, string accountName, string streamingLocatorName)
        {
            try
            {
                // Delete the Streaming Locator
                await client.StreamingLocators.DeleteAsync(resourceGroup, accountName, streamingLocatorName);
            }
            catch (ApiErrorException e)
            {
                Console.WriteLine("CleanupLocatorandAssetAsync -- Hit ApiErrorException");
                Console.WriteLine($"\tCode: {e.Body.Error.Code}");
                Console.WriteLine($"\tMessage: {e.Body.Error.Message}");
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Build and print streaming URLs.
        /// </summary>
        /// <param name="client">The Media Services client.</param>
        /// <param name="resourceGroupName">The name of the resource group within the Azure subscription.</param>
        /// <param name="accountName"> The Media Services account name.</param>
        /// <param name="streamingLocatorName">The streaming locator name.</param>
        /// <param name="streamingEndpoint">The streaming endpoint.</param>
        /// <returns></returns>
        private static async Task<bool> PrintPaths(IAzureMediaServicesClient client, string resourceGroup, string accountName, string streamingLocatorName,
            StreamingEndpoint streamingEndpoint)
        {
            // Get the url to stream the output
            var paths = await client.StreamingLocators.ListPathsAsync(resourceGroup, accountName, streamingLocatorName);

            Console.WriteLine("The urls to stream the output from the client:");
            Console.WriteLine();
            StringBuilder stringBuilder = new StringBuilder();
            string playerPath = string.Empty;

            for (int i = 0; i < paths.StreamingPaths.Count; i++)
            {
                UriBuilder uriBuilder = new UriBuilder();
                uriBuilder.Scheme = "https";
                uriBuilder.Host = streamingEndpoint.HostName;

                if (paths.StreamingPaths[i].Paths.Count > 0)
                {
                    uriBuilder.Path = paths.StreamingPaths[i].Paths[0];
                    stringBuilder.AppendLine($"\t{paths.StreamingPaths[i].StreamingProtocol}-{paths.StreamingPaths[i].EncryptionScheme}");
                    stringBuilder.AppendLine($"\t\t{uriBuilder.ToString()}");
                    stringBuilder.AppendLine();

                    if (paths.StreamingPaths[i].StreamingProtocol == StreamingPolicyStreamingProtocol.Dash)
                    {
                        playerPath = uriBuilder.ToString();
                    }
                }
            }

            if (stringBuilder.Length > 0)
            {
                Console.WriteLine(stringBuilder.ToString());
                Console.WriteLine("Open the following URL to play it in the Azure Media Player");
                Console.WriteLine($"\t https://ampdemo.azureedge.net/?url={playerPath}&heuristicprofile=lowlatency");
                Console.WriteLine();
                return true;
            }
            else
            {
                Console.WriteLine("No Streaming Paths were detected. Has the Stream been started?");
                return false;
            }
        }
    }
}
