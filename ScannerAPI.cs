using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using Amazon.S3;
using Amazon.S3.Model;

namespace ScannerAPI
{

    public class AVScan
    {

        ILogger log;
        public static string ICAPServer { get; set; } = "54.89.242.83";
        public static string ICAPClient { get; set; } = "192.168.0.1";
        public static string sICAPPort { get; set; } = "1344";
        public static string ICAPServiceName = "avscan";
        public static int ICAPPort = int.Parse(sICAPPort);


        AVScan()
        {
            // EDIT ICAPServer, ICAPClient, and sICAPPort below if you will run the code directly on Azure (or pass them as environment variables)
            string ICAPServer = Environment.GetEnvironmentVariable("ICAPSERVER");
            if (string.IsNullOrEmpty(ICAPServer))
            {
                ICAPServer = "54.89.242.83";
                log.LogInformation("No ICAP server specified, defaulting to " + ICAPServer);
            }
            string ICAPClient = Environment.GetEnvironmentVariable("ICAPCLIENT");
            if (string.IsNullOrEmpty(ICAPClient))
            {
                ICAPClient = "192.168.0.1";
                log.LogInformation("No default ICAP client specified, defaulting to " + ICAPClient);
            }
            string sICAPPort = Environment.GetEnvironmentVariable("ICAPPORT");
            if (string.IsNullOrEmpty(sICAPPort))
            {
                sICAPPort = "1344";
                log.LogInformation("No default ICAP port specified, defaulting to " + sICAPPort);
            }
        }

        [FunctionName("AVScan")]
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req, ILogger log)
        {

            //Parse the request header for parameters
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            string urlToScan = req.Query["url"];
            string s3uriString = req.Query["s3uri"];
            string useFileCache = req.Query["usefilecache"];

            //To add/replace support for accepting a file directly, instead of pulling a blob pass the
            //file into a memory or file stream here

            

            log.LogInformation("C# HTTP triggered for AV Scan function");
            log.LogInformation("  Scanning: " + urlToScan + s3uriString);

            
            jsonScanResult ScanResult;

            ICAPClient icapper = new ICAPClient(ICAPServer, ICAPPort, ICAPServiceName, ICAPClient);

            try
            {

                if (urlToScan != null)
                {
                    //if a URL is provided, use that first

                    string fileName = Path.GetFileName(urlToScan);
                    Scanner scan = new Scanner();

                    if (useFileCache == bool.TrueString)  //Determine if we need to use a memory (default) or file stream to cache the file
                    {
                        ScanResult = scan.scanCachedFile(urlToScan, log);
                    }
                    else
                    {
                        log.LogInformation("  Using Memory Cache");
                        ScanResult = scan.scanStoredFile(urlToScan, log);

                    }

                    log.LogInformation(ScanResult.ToString());

                    icapper.Dispose();

                    return new OkObjectResult(JsonConvert.SerializeObject(ScanResult));
                }
                else if (s3uriString != null)
                {

                    //Got an S3 URI
                    Scanner scanner = new Scanner();
                    return (IActionResult)await scanner.scanUri(Path.GetFileName(s3uriString), useFileCache, log);
                    
                }
                
                else
                {
                    return new OkObjectResult("Error: Did not receive any object to scan");
                }

            }
            catch (Exception ex)
            {
                log.LogInformation("Scan failure, unknown Error: " + ex);
                return new OkObjectResult("Could not complete scan.  Exception:" + ex);

            }
            //return new OkObjectResult(responseMessage);
        }


        

        
    }
}
