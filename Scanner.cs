using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace ScannerAPI
{
    internal class Scanner
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


    }


    
}
