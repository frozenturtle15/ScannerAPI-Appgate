﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;

namespace ScannerAPI
{
    class ICAPClient
    {

        private String serverIP;
        private String clientIP;
        private int port;

        private Socket sender;

        private String icapService;
        private const String VERSION = "1.0";
        private const String USERAGENT = "Rest2ICAP";
        private const String ICAPTERMINATOR = "\r\n\r\n";
        private const String HTTPTERMINATOR = "0\r\n\r\n";

        private int stdPreviewSize;
        private const int stdRecieveLength = 4194304;
        private const int stdSendLength = 4096;

        private byte[] buffer = new byte[4096];
        private String tempString;

        public ICAPClient(String serverHost, int port, String icapService, String clientIP, int previewSize = -1)
        {
            this.icapService = icapService;
            this.port = port;
            this.clientIP = clientIP;
            //Initialize connection

            var iplist = System.Net.Dns.GetHostAddresses(serverHost);

            if (iplist.Length == 0)
            {
                throw new ArgumentException("Unable to ICAP server address from specified host name.");
            }
            else
            {

                IPAddress ipAddress = iplist[0];
                this.serverIP = ipAddress.ToString();
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

                // Create a TCP/IP  socket.
                sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                sender.Connect(remoteEP);

                if (previewSize != -1)
                {
                    stdPreviewSize = previewSize;
                }
                else
                {
                    String parseMe = getOptions();
                    Dictionary<string, string> responseMap = parseHeader(parseMe);

                    responseMap.TryGetValue("StatusCode", out tempString);
                    if (tempString != null)
                    {
                        int status = Convert.ToInt16(tempString);

                        switch (status)
                        {
                            case 200:
                                responseMap.TryGetValue("Preview", out tempString);
                                if (tempString != null)
                                {
                                    stdPreviewSize = Convert.ToInt16(tempString);
                                }; break;
                            default: throw new ICAPException("Could not get preview size from server");
                        }
                    }
                    else
                    {
                        throw new ICAPException("Could not get options from server");
                    }
                }
            }

        }

        public jsonScanResult scanStream(Stream byteStream, string Filename)
        {
            int fileSize = (int)byteStream.Length;

            byte[] requestHeader = Encoding.ASCII.GetBytes("GET http://" + clientIP + "/" + Filename + " HTTP/1.1" + "\r\n" + "Host: " + clientIP + "\r\n\r\n");
            byte[] responseHeader = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n" + "Transfer-Encoding: chunked\r\n\r\n");
            int res_header = requestHeader.Length;
            int res_body = res_header + responseHeader.Length;
            int req_header = 0;
            jsonScanResult result = new jsonScanResult();


            //If the file is small, set the preview length to the size of the file
            int previewSize = stdPreviewSize;
            if (fileSize < stdPreviewSize)
            {
                previewSize = fileSize;
            }

            //Build the main ICAPrequest
            byte[] ICAPrequest = Encoding.ASCII.GetBytes(
                "RESPMOD icap://" + serverIP + ":" + port + "/" + "respmod?profile=" + icapService + " ICAP/" + VERSION + "\r\n"
                + "Connection: close\r\n"
                + "Encapsulated: req-hdr=" + req_header + " res-hdr=" + res_header + " res-body=" + res_body + "\r\n"
                + "Host: " + serverIP + "\r\n"
                + "User-Agent: " + USERAGENT + "\r\n"
                + "X-Client-IP: " + clientIP + "\r\n"
                + "Allow: 204\r\n"
                + "Preview: " + previewSize + "\r\n"
                + "\r\n"
            );

            byte[] previewSizeHex = Encoding.ASCII.GetBytes(previewSize.ToString("X") + "\r\n");
            sender.ReceiveTimeout = 600000;
            sender.SendTimeout = 600000;
            sender.Send(ICAPrequest);  //Send the initial ICAP request
            sender.Send(requestHeader); //Send the forged client Request Header - MWG requires this
            sender.Send(responseHeader); //Send the server response header (also forged)
            sender.Send(previewSizeHex); //Send the hex value for the number of bytes to follow in the preview

            byte[] chunk = new byte[previewSize]; //Send the preview chunk

            byteStream.Seek(0, SeekOrigin.Begin);  //Reset the stream position to the beginning

            byteStream.Read(chunk, 0, previewSize);
            sender.Send(chunk);
            sender.Send(Encoding.ASCII.GetBytes("\r\n"));

            if (fileSize <= previewSize)  //If the file fits in the preview size send the terminator
            {
                sender.Send(Encoding.ASCII.GetBytes("0; ieof\r\n\r\n"));
            }
            else if (previewSize != 0)
            {
                sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
            }

            // Parse the response to see if MWG bypasses based on preview or asks for the file
            Dictionary<String, String> responseMap = new Dictionary<string, string>();
            int status;

            if (fileSize > previewSize)
            {
                String parseMe = getNextHeader(ICAPTERMINATOR);
                responseMap = parseHeader(parseMe);

                responseMap.TryGetValue("StatusCode", out tempString);
                if (tempString != null)
                {
                    status = Convert.ToInt16(tempString);

                    result.Filename = Filename;
                    result.HasError = false;

                    switch (status)  //Switching the status of the preview only, most of the time we'll get continue here
                    {
                        case 100:
                            break;

                        case 200:
                            result.Infected = false;
                            result.HasError = true;
                            return result;

                        case 204:
                            result.Infected = false;
                            return result;

                        case 304:
                            result.Infected = true;
                            string infectionName;
                            responseMap.TryGetValue("X-Virus-Name", out infectionName);
                            result.InfectionName = infectionName = "viaPreview";
                            return result;

                        default:
                            result.Infected = false; // error
                            result.HasError = true;
                            string error = "Error: Unknown status code " + status;
                            result.ErrorMessage = error;
                            Console.WriteLine(DateTime.Now + ": " + error);
                            return result;

                    }

                }
            }

            //Sending remaining part of file
            if (fileSize > previewSize)
            {
                int offset = previewSize;
                byte[] buffer = new byte[stdSendLength];
                int n;

                while ((n = byteStream.Read(buffer, 0, stdSendLength)) > 0)
                {
                    offset += n;  // offset for next reading
                    if (n > stdSendLength)
                    {
                        sender.Send(Encoding.ASCII.GetBytes(buffer.Length.ToString("X") + "\r\n"));
                        sender.Send(buffer);
                    }
                    else
                    {
                        byte[] lastBuffer = new byte[n];
                        Buffer.BlockCopy(buffer, 0, lastBuffer, 0, n);
                        sender.Send(Encoding.ASCII.GetBytes(lastBuffer.Length.ToString("X") + "\r\n"));
                        sender.Send(lastBuffer);
                    }

                    sender.Send(Encoding.ASCII.GetBytes("\r\n"));
                }
                //Closing file transfer.
                sender.Send(Encoding.ASCII.GetBytes("0\r\n\r\n"));
            }

            responseMap.Clear();
            String response = getNextHeader(ICAPTERMINATOR);
            responseMap = parseHeader(response);
            responseMap.TryGetValue("StatusCode", out tempString);
            if (tempString != null)
            {
                status = Convert.ToInt16(tempString);


                if (status == 204)
                {
                    result.Infected = false;  //Unmodified
                    result.HasError = false;
                    return result;
                }

                if (status == 200) //OK - The 200 ICAP status is ok, but the encapsulated HTTP status will likely be different
                {

                    //Searching for: McAfee Virus Found Message
                    response = getNextHeader(HTTPTERMINATOR);

                    int titleStart = response.IndexOf("<title>", 0);
                    int titleEnd = response.IndexOf("</title>", titleStart);
                    String pageTitle = response.Substring(titleStart + 7, titleEnd - titleStart - 7);

                    if (pageTitle.Equals("McAfee Web Gateway - Notification"))
                    {
                        result.Infected = true;
                        String infectionName;
                        responseMap.TryGetValue("X-Virus-Name", out infectionName);

                        if (String.IsNullOrEmpty(infectionName))
                        {
                            //Grab virus name from the message since its not included in the HEADER, MWG version dependent
                            int x = response.IndexOf("Virus Name: </b>", 0);
                            int y = response.IndexOf("<br />", x);
                            infectionName = response.Substring(x + 16, y - x - 16);

                        }

                        result.InfectionName = infectionName;
                        return result;
                    }

                }
            }

            responseMap.TryGetValue("X-Virus-Name", out tempString);
            if (tempString != null)
            {
                result.InfectionName = tempString;
            }

            throw new ICAPException("Unrecognized or no status code in response header.");

        }

        /// <summary>
        /// Automatically asks for the servers available options and returns the raw response as a String.
        /// </summary>
        /// <returns>String of the raw response</returns>
        private string getOptions()
        {
            byte[] msg = Encoding.ASCII.GetBytes(
                "OPTIONS icap://" + serverIP + "/" + icapService + " ICAP/" + VERSION + "\r\n"
                + "Host: " + serverIP + "\r\n"
                + "User-Agent: " + USERAGENT + "\r\n"
                + "Encapsulated: null-body=0\r\n"
                + "\r\n");
            sender.Send(msg);

            return getNextHeader(ICAPTERMINATOR);
        }

        /// <summary>
        /// Receive an expected ICAP header as response of a request. The returned String should be parsed with parseHeader()
        /// </summary>
        /// <param name="terminator">Relative or absolute filepath to a file.</parm>
        /// <exception cref="ICAPException">Thrown when error occurs in communication with server</exception>
        /// <returns>String of the raw response</returns>
        private String getNextHeader(String terminator)
        {
            byte[] endofheader = System.Text.Encoding.UTF8.GetBytes(terminator);
            byte[] buffer = new byte[stdRecieveLength];

            int n;
            int offset = 0;
            //stdRecieveLength-offset is replaced by '1' to not receive the next (HTTP) header.
            while ((offset < stdRecieveLength) && ((n = sender.Receive(buffer, offset, 1, SocketFlags.None)) != 0)) // first part is to secure against DOS
            {
                offset += n;
                if (offset > endofheader.Length + 13) // 13 is the smallest possible message (ICAP/1.0 xxx\r\n) or (HTTP/1.0 xxx\r\n)
                {
                    byte[] lastBytes = new byte[endofheader.Length];
                    Array.Copy(buffer, offset - endofheader.Length, lastBytes, 0, endofheader.Length);
                    if (endofheader.SequenceEqual(lastBytes))
                    {
                        return Encoding.ASCII.GetString(buffer, 0, offset);
                    }
                }
            }

            throw new ICAPException("Error in getNextHeader() method");
        }

        /// <summary>
        /// Given a raw response header as a String, it will parse through it and return a Dictionary of the result
        /// </summary>
        /// <param name="response">A raw response header as a String.</parm>
        /// <returns>Dictionary of the key,value pairs of the response</returns>
        private Dictionary<String, String> parseHeader(String response)
        {
            Dictionary<String, String> headers = new Dictionary<String, String>();

            /****SAMPLE:****
             * ICAP/1.0 204 Unmodified
             * Server: C-ICAP/0.1.6
             * Connection: keep-alive
             * ISTag: CI0001-000-0978-6918203
             */
            // The status code is located between the first 2 whitespaces.
            // Read status code
            int x = response.IndexOf(" ", 0);
            int y = response.IndexOf(" ", x + 1);
            String statusCode = response.Substring(x + 1, y - x - 1);
            headers.Add("StatusCode", statusCode);

            // Each line in the sample is ended with "\r\n". 
            // When (i+2==response.length()) The end of the header have been reached.
            // The +=2 is added to skip the "\r\n".
            // Read headers
            int i = response.IndexOf("\r\n", y);
            i += 2;
            while (i + 2 != response.Length && response.Substring(i).Contains(':'))
            {
                int n = response.IndexOf(":", i);
                String key = response.Substring(i, n - i);

                n += 2;
                i = response.IndexOf("\r\n", n);
                String value = response.Substring(n, i - n);

                headers.TryAdd(key, value);
                i += 2;
            }
            return headers;
        }

        /// <summary>
        /// A basic excpetion to show ICAP-related errors
        /// </summary>
        public class ICAPException : Exception
        {
            public ICAPException(string message)
                : base(message)
            {
            }

        }

        public void Dispose()
        {
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
            sender.Dispose();
            //fileStream.Close();
            //throw new NotImplementedException();
        }
    }
}
