using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Amazon.S3;
using Amazon.S3.Model;
using System.Threading.Tasks;

namespace ScannerAPI
{
    public class Scanner
    {
        public jsonScanResult scanCachedFile(string urlToScan, ILogger log)
        {
            string fileName = Path.GetFileName(urlToScan);

            ICAPClient icapper = new ICAPClient(AVScan.ICAPServer, AVScan.ICAPPort, AVScan.ICAPServiceName, AVScan.ICAPClient);

            //First download the file to temporary 
            string tempFileName = Path.GetTempFileName();
            log.LogInformation("  Using File Cache " + tempFileName);
            WebClient client = new WebClient();
            client.DownloadFile(urlToScan, tempFileName);
            client.Dispose();

            //Open temporary file to stream
            FileStream responseFileStream = new FileStream(tempFileName, FileMode.Open);
            jsonScanResult scanResult = icapper.scanStream(responseFileStream, fileName);

            responseFileStream.Close();
            responseFileStream.Dispose();
            File.Delete(tempFileName);


            log.LogInformation(JsonConvert.SerializeObject(scanResult));

            icapper.Dispose();
            return scanResult;
        }

        public jsonScanResult scanStoredFile(string urlToScan, ILogger log)
        {
            ICAPClient icapper = new ICAPClient(AVScan.ICAPServer, AVScan.ICAPPort, AVScan.ICAPServiceName, AVScan.ICAPClient);
            string fileName = Path.GetFileName(urlToScan);

            log.LogInformation("  Using Memory Cache");
            MemoryStream responseMemoryStream = new MemoryStream(new WebClient().DownloadData(urlToScan));
            jsonScanResult scanResult = icapper.scanStream(responseMemoryStream, fileName);

            responseMemoryStream.Dispose();

            return scanResult;
        }

        public async Task<jsonScanResult> scanUri(string s3uriString, string cached, ILogger log)
        {
            string jsonScanResultString;
            jsonScanResult ScanResult; 
            ICAPClient icapper = new ICAPClient(AVScan.ICAPServer, AVScan.ICAPPort, AVScan.ICAPServiceName, AVScan.ICAPClient);
            AmazonS3Client s3Client = new AmazonS3Client();
            GetObjectRequest s3GetRequest = new GetObjectRequest();

            Uri s3uri = new Uri(s3uriString);

            s3GetRequest.BucketName = s3uri.Host;

            char[] trimChars = { '/' };
            s3GetRequest.Key = System.Net.WebUtility.UrlDecode(s3uri.AbsolutePath.Trim(trimChars)); //need to remove leading or trailing slashes

            log.LogInformation("Got URI: " + s3uriString + ", bucket=" + s3uri.Host + ", key=" + s3uri.AbsolutePath.Trim(trimChars));

            if (cached == bool.TrueString)  //Scan S3 URI using File Cache
            {

                //First download the file to temporary
                string tempFileName = Path.GetTempFileName();
                log.LogInformation("  Using File Cache " + tempFileName);

                FileStream fs = File.Create(tempFileName);
                fs.Close();

                Amazon.S3.Transfer.TransferUtility ftu = new Amazon.S3.Transfer.TransferUtility(s3Client);
                ftu.Download(tempFileName, s3uri.Host, s3uri.AbsolutePath.Trim(trimChars));

                var responseFileStream = new FileStream(tempFileName, FileMode.Open);
                ScanResult = icapper.scanStream(responseFileStream, s3GetRequest.Key);
                jsonScanResultString = JsonConvert.SerializeObject(ScanResult);

                responseFileStream.Close();
                responseFileStream.Dispose();
                File.Delete(tempFileName);

            }
            else //Scan S3 URI using Memory Cache
            {
                log.LogInformation("  Using Memory Cache");

                GetObjectResponse response = await s3Client.GetObjectAsync(s3GetRequest);
                MemoryStream responseStream = new MemoryStream();
                response.ResponseStream.CopyTo(responseStream); //TODO: DELETE THIS COPY IF IT WORKS WITHOUT
                //response.Dispose();
                ScanResult = icapper.scanStream(responseStream, s3GetRequest.Key);
                jsonScanResultString = JsonConvert.SerializeObject(ScanResult);

                responseStream.Dispose();
            }

            log.LogInformation(jsonScanResultString);

            icapper.Dispose();

            return ScanResult;
        }
              
    }


}



